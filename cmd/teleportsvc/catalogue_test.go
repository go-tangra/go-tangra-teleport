package main

// T120: the catalogue descriptor and the join bundle.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra/v4/authz"
	"github.com/go-tangra/go-tangra/v4/catalogue"
	"github.com/go-tangra/go-tangra/v4/identity"

	"github.com/go-tangra/go-tangra-teleport/v4/pkg/teleportmanifest"
)

var placeholderRE = regexp.MustCompile(`\$\{([A-Z][A-Z0-9_]*)\}`)

// joinValues are values of the shape the gateway fills in: core values,
// generated secrets and the host inputs.
var joinValues = map[string]string{
	"TRUST_DOMAIN": "infra.example.org", "GATEWAY_ISSUER": "https://portal.example.org:8443",
	"LCM_ENROLL_URL": "https://portal.example.org:8443/api/lcm/v1/enroll", "LCM_GRPC": "portal.example.org:9945",
	"GATEWAY_GRPC": "portal.example.org:9643", "AUTH_GRPC": "portal.example.org:9543", "MESH_TENANT_ID": "00000000-0000-0000-0000-000000000001",
	"MODULE_IMAGE": "ghcr.io/go-tangra/go-tangra-teleport", "MODULE_VERSION": "1.0.0",
	"GEN_PASSWORD_1": strings.Repeat("a", 48), "GEN_PASSWORD_2": strings.Repeat("b", 48),
	"MODULE_ADVERTISE_HOST": "teleport.example.org", "MODULE_BIND_IP": "10.0.0.6",
	"VALKEY_ADDRESS": "valkey.example.org:6380", "VALKEY_PASSWORD": strings.Repeat("c", 32), "VALKEY_CA_FILE": "/etc/tangra/valkey-ca.pem",
	"WARDEN_GRPC": "portal.example.org:9843", "NOTIFICATION_GRPC": "portal.example.org:9943", "SCHEDULER_GRPC": "portal.example.org:9905",
}

func readRepoFile(t *testing.T, parts ...string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// tangra-module.yaml passes the catalogue's own checks, names this module
// and asks only for its own routes; compose.yaml (interpolated from the
// gateway's .env) uses only values the gateway writes there.
func TestCatalogueDescriptor(t *testing.T) {
	d, err := catalogue.ParseDescriptor(readRepoFile(t, "tangra-module.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if d.Module != teleportmanifest.Module || d.Bundle.Dir != "deploy/bundle" || !slices.Contains(d.Routes.Prefixes, teleportmanifest.APIPrefix) {
		t.Fatalf("%+v", d)
	}
	for _, p := range []string{"/api/teleport", "/m/teleport", "/teleport"} {
		if !slices.Contains(d.Routes.Prefixes, p) {
			t.Errorf("route %s missing", p)
		}
	}
	if d.MinCore["gateway"] == "" || d.MinCore["auth"] == "" {
		t.Fatalf("min_core %v", d.MinCore)
	}
	inputs := map[string]bool{}
	for _, in := range d.HostInputs {
		inputs[in.Key] = true
		if !regexp.MustCompile(in.Pattern).MatchString(joinValues[in.Key]) {
			t.Errorf("host input %s refuses %q", in.Key, joinValues[in.Key])
		}
	}
	for _, k := range []string{"MODULE_ADVERTISE_HOST", "MODULE_BIND_IP", "VALKEY_ADDRESS", "VALKEY_PASSWORD", "VALKEY_CA_FILE"} {
		if !inputs[k] {
			t.Errorf("host input %s missing", k)
		}
	}
	for _, m := range placeholderRE.FindAllStringSubmatch(string(readRepoFile(t, "deploy", "bundle", "compose.yaml")), -1) {
		if k := m[1]; !inputs[k] && !catalogue.Reserved(k) {
			t.Errorf("compose.yaml uses %s, which the gateway does not write to .env", k)
		}
	}
	bundle, err := catalogue.PackBundle(os.DirFS(filepath.Join("..", "..", d.Bundle.Dir)))
	if err != nil {
		t.Fatal(err)
	}
	e, err := catalogue.BuildEntry(d, "1.0.0", "go-tangra/go-tangra-teleport", teleportmanifest.PermissionRefs(), bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.CheckBundle(bundle); err != nil {
		t.Fatal(err)
	}
	files, err := catalogue.ReadBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range append([]string{"compose.yaml", "init-db.sh", "README.md"}, d.Bundle.Templates...) {
		if _, ok := files[name]; !ok {
			t.Errorf("%s missing from the bundle", name)
		}
	}
}

// The join bundle's templates, rendered with values of the shape the gateway
// fills in, are a valid configuration and policy with the production TLS
// guards met (env stays "dev" only for the file: credential references, until
// warden has a write RPC).
func TestJoinBundleRendersToValidConfig(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"config.yaml", "policy.yaml"} {
		raw := readRepoFile(t, "deploy", "bundle", name)
		var missing []string
		rendered := placeholderRE.ReplaceAllStringFunc(string(raw), func(m string) string {
			k := placeholderRE.FindStringSubmatch(m)[1]
			v, ok := joinValues[k]
			if !ok {
				missing = append(missing, k)
			}
			return v
		})
		if len(missing) > 0 {
			t.Fatalf("%s uses placeholders the gateway does not fill: %v", name, missing)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(rendered), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := loadConfig([]string{"-config", filepath.Join(dir, "config.yaml")})
	if err != nil {
		t.Fatalf("rendered config invalid: %v", err)
	}
	if cfg.Gateway.Issuer != "https://portal.example.org:8443" || !cfg.TaskScheduler.Enabled || cfg.ServiceName != "teleport" {
		t.Fatalf("%+v %+v", cfg.Gateway, cfg.TaskScheduler)
	}
	if !strings.Contains(cfg.DB.DSN, "sslmode=verify-full") || !strings.Contains(cfg.DB.MigrateDSN, "sslmode=verify-full") ||
		cfg.Valkey.AllowPlaintext || cfg.Valkey.CAFile != "/tls/valkey-ca.pem" || cfg.Valkey.Username != "teleport" ||
		cfg.Valkey.Addresses[0] != "valkey.example.org:6380" || cfg.MeshEnroll.Insecure || len(cfg.Teleport.AllowedPrivateNetworks) != 0 {
		t.Fatalf("production guards not met: %+v %+v %+v", cfg.DB, cfg.Valkey, cfg.MeshEnroll)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	pol, err := authz.Load(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	const td = "spiffe://infra.example.org/svc/"
	for _, c := range []struct {
		peer, op string
		want     bool
	}{
		{td + "gateway", "GET /api/teleport/v1/clusters", true},
		{td + "gateway", "/scheduler.v1.TaskExecutor/ExecuteTask", false},
		{td + "scheduler", "/scheduler.v1.TaskExecutor/ExecuteTask", true},
		{td + "inventory", "/scheduler.v1.TaskExecutor/ExecuteTask", false},
		{td + "inventory", "/teleport.v1.Access/LookupHost", true},
		{td + "scheduler", "/teleport.v1.Access/LookupHost", false},
		{"spiffe://example.org/svc/scheduler", "/scheduler.v1.TaskExecutor/ExecuteTask", false},
	} {
		id, err := identity.ParseSPIFFEID(c.peer)
		if err != nil {
			t.Fatal(err)
		}
		if got := pol.Authorize(context.Background(), id, "teleport", c.op).Allowed; got != c.want {
			t.Errorf("%s %s: allowed=%v", c.peer, c.op, got)
		}
	}
}
