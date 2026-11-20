package deploy_test

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/deploy"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

var update = flag.Bool("update", false, "rewrite the golden files under testdata/deploy")

var (
	acme = deploy.Input{Domain: "tp.example.test", CertMode: repo.CertACME, ACMEEmail: "ops@example.test",
		TeleportVersion: "19.1.2", AdminUsername: "admin", AdminLogins: []string{"root", "ubuntu"}}
	own = deploy.Input{Domain: "teleport.corp.example", CertMode: repo.CertOwn, TeleportVersion: "18.7.0",
		AdminUsername: "alice@corp.example", AdminLogins: []string{"ec2-user"}}
)

func golden(t *testing.T, variant, name string, got []byte) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "deploy", variant, name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil { //nolint:gosec // test fixtures
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) //nolint:gosec // fixed fixture path
	if err != nil {
		t.Fatalf("golden %s: %v (run go test -update)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s/%s differs from the golden file:\n%s", variant, name, got)
	}
}

func TestRenderGolden(t *testing.T) {
	for variant, in := range map[string]deploy.Input{"acme": acme, "own_cert": own} {
		for _, name := range deploy.Artifacts {
			out, err := deploy.Render(name, in)
			if err != nil {
				t.Fatalf("%s %s: %v", variant, name, err)
			}
			golden(t, variant, name, out)
		}
	}
}

func TestRenderedArtifacts(t *testing.T) {
	cfg, _ := deploy.Render("teleport.yaml", acme)
	var doc struct {
		Version string `yaml:"version"`
		Auth    struct {
			ClusterName string `yaml:"cluster_name"`
		} `yaml:"auth_service"`
		Proxy struct {
			PublicAddr string `yaml:"public_addr"`
			ACME       struct {
				Enabled string `yaml:"enabled"`
				Email   string `yaml:"email"`
			} `yaml:"acme"`
			Keypairs []map[string]string `yaml:"https_keypairs"`
		} `yaml:"proxy_service"`
	}
	if err := yaml.Unmarshal(cfg, &doc); err != nil {
		t.Fatalf("teleport.yaml does not parse: %v", err)
	}
	if doc.Version != "v3" || doc.Auth.ClusterName != acme.Domain || doc.Proxy.PublicAddr != acme.Domain+":443" ||
		doc.Proxy.ACME.Enabled != "yes" || doc.Proxy.ACME.Email != acme.ACMEEmail || len(doc.Proxy.Keypairs) != 0 {
		t.Fatalf("acme config %+v", doc)
	}
	cfg, _ = deploy.Render("teleport.yaml", own)
	doc.Proxy.ACME.Enabled = ""
	if err := yaml.Unmarshal(cfg, &doc); err != nil || doc.Proxy.ACME.Enabled != "" || len(doc.Proxy.Keypairs) != 1 {
		t.Fatalf("own_cert config %+v %v", doc, err)
	}
	sh, _ := deploy.Render("install.sh", acme)
	if !bytes.Contains(sh, []byte("bash -s 19.1.2")) || !bytes.HasPrefix(sh, []byte("#!/usr/bin/env bash\n")) || !bytes.Contains(sh, []byte("set -euo pipefail")) {
		t.Fatalf("install.sh is not pinned:\n%s", sh)
	}
	role, _ := deploy.Render("tangra-manager-role.yaml", acme)
	var r map[string]any
	if err := yaml.Unmarshal(role, &r); err != nil || r["kind"] != "role" {
		t.Fatalf("role %v %v", r, err)
	}
	cmds, _ := deploy.Render("setup-commands.txt", acme)
	for _, want := range []string{"tctl users add admin --roles=editor,access,auditor --logins=root,ubuntu",
		"tctl create -f tangra-manager-role.yaml", "tctl users add tangra-mgmt --roles=tangra-manager",
		"tctl auth sign --user=tangra-mgmt --format=file --ttl=720h --out=tangra-mgmt.identity", "tp.example.test:443"} {
		if !bytes.Contains(cmds, []byte(want)) {
			t.Errorf("setup-commands.txt lacks %q", want)
		}
	}
	list, _ := deploy.Render("checklist.md", own)
	for _, want := range []string{"teleport.corp.example", "*.teleport.corp.example", "443", "2 vCPU", "fullchain.pem"} {
		if !bytes.Contains(list, []byte(want)) {
			t.Errorf("checklist.md lacks %q", want)
		}
	}
	if _, err := deploy.Render("secrets.txt", acme); !errors.Is(err, deploy.ErrUnknownArtifact) {
		t.Fatalf("unknown artifact: %v", err)
	}
}

// The role artifact is the role the reference page documents.
func TestManagerRoleMatchesTheReference(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "help", "reference", "tangra-manager-role.md"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)```yaml\n(kind: role.*?)```").FindSubmatch(doc)
	role, _ := deploy.Render("tangra-manager-role.yaml", acme)
	if m == nil || !bytes.Equal(bytes.TrimSpace(m[1]), bytes.TrimSpace(role)) {
		t.Fatalf("tangra-manager-role.yaml differs from docs/help/reference/tangra-manager-role.md:\n%s", role)
	}
}

func fieldOf(err error) string {
	var fe *clusters.FieldError
	if errors.As(err, &fe) {
		return fe.Field
	}
	return ""
}

func TestValidate(t *testing.T) {
	norm, err := deploy.Validate(deploy.Input{Domain: " TP.Example.Test ", CertMode: "acme", ACMEEmail: "Ops@Example.test",
		TeleportVersion: "19.1.2", AdminUsername: "admin", AdminLogins: []string{"root", "root"}})
	if err != nil || norm.Domain != "tp.example.test" || len(norm.AdminLogins) != 1 {
		t.Fatalf("normalized %+v %v", norm, err)
	}
	if _, err := deploy.Validate(own); err != nil {
		t.Fatalf("own_cert: %v", err)
	}
	cases := map[string]struct {
		mut   func(*deploy.Input)
		field string
	}{
		"empty domain":      {func(i *deploy.Input) { i.Domain = "" }, "domain"},
		"single label":      {func(i *deploy.Input) { i.Domain = "localhost" }, "domain"},
		"ip":                {func(i *deploy.Input) { i.Domain = "10.0.0.1" }, "domain"},
		"underscore":        {func(i *deploy.Input) { i.Domain = "a_b.example.test" }, "domain"},
		"leading dash":      {func(i *deploy.Input) { i.Domain = "-a.example.test" }, "domain"},
		"long label":        {func(i *deploy.Input) { i.Domain = strings.Repeat("a", 64) + ".example.test" }, "domain"},
		"long name":         {func(i *deploy.Input) { i.Domain = strings.Repeat("abcdefghi.", 26) + "test" }, "domain"},
		"wildcard":          {func(i *deploy.Input) { i.Domain = "*.example.test" }, "domain"},
		"port":              {func(i *deploy.Input) { i.Domain = "tp.example.test:443" }, "domain"},
		"numeric tld":       {func(i *deploy.Input) { i.Domain = "example.123" }, "domain"},
		"cert mode":         {func(i *deploy.Input) { i.CertMode = "letsencrypt" }, "cert_mode"},
		"no email":          {func(i *deploy.Input) { i.ACMEEmail = "" }, "acme_email"},
		"bad email":         {func(i *deploy.Input) { i.ACMEEmail = "ops" }, "acme_email"},
		"email quote":       {func(i *deploy.Input) { i.ACMEEmail = "o'ps@example.test" }, "acme_email"},
		"email space":       {func(i *deploy.Input) { i.ACMEEmail = "o ps@example.test" }, "acme_email"},
		"email domain":      {func(i *deploy.Input) { i.ACMEEmail = "ops@localhost" }, "acme_email"},
		"version":           {func(i *deploy.Input) { i.TeleportVersion = "19.1" }, "teleport_version"},
		"version v":         {func(i *deploy.Input) { i.TeleportVersion = "v19.1.2" }, "teleport_version"},
		"version suffix":    {func(i *deploy.Input) { i.TeleportVersion = "19.1.2-rc.1" }, "teleport_version"},
		"version newline":   {func(i *deploy.Input) { i.TeleportVersion = "19.1.2\nrm -rf /" }, "teleport_version"},
		"version huge":      {func(i *deploy.Input) { i.TeleportVersion = "19.1.99999" }, "teleport_version"},
		"username":          {func(i *deploy.Input) { i.AdminUsername = "" }, "admin_username"},
		"username shell":    {func(i *deploy.Input) { i.AdminUsername = "a;rm" }, "admin_username"},
		"username subst":    {func(i *deploy.Input) { i.AdminUsername = "$(id)" }, "admin_username"},
		"username backtick": {func(i *deploy.Input) { i.AdminUsername = "a`id`" }, "admin_username"},
		"login":             {func(i *deploy.Input) { i.AdminLogins = []string{"root|id"} }, "admin_logins"},
		"login dash":        {func(i *deploy.Input) { i.AdminLogins = []string{"-oProxyCommand=x"} }, "admin_logins"},
		"no logins":         {func(i *deploy.Input) { i.AdminLogins = nil }, "admin_logins"},
		"too many logins":   {func(i *deploy.Input) { i.AdminLogins = strings.Split(strings.Repeat("a,", 33), ",")[:33] }, "admin_logins"},
	}
	for name, c := range cases {
		in := acme
		in.AdminLogins = append([]string(nil), acme.AdminLogins...)
		c.mut(&in)
		if _, err := deploy.Validate(in); fieldOf(err) != c.field {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := deploy.Render("install.sh", in); err == nil {
			t.Errorf("%s: rendered an invalid input", name)
		}
	}
	// own_cert takes no ACME e-mail.
	in := own
	in.ACMEEmail = "ops@example.test"
	if _, err := deploy.Validate(in); fieldOf(err) != "acme_email" {
		t.Errorf("own_cert with e-mail: %v", err)
	}
}

// Values with shell or YAML metacharacters never validate, so no artifact can
// carry them.
func TestShellMetacharactersRejected(t *testing.T) {
	for _, v := range []string{"$x", "`x`", "a;b", "a|b", "a&b", "a>b", "a<b", "a b", "a'b", `a"b`, "a\\b", "a\nb", "a\x00b", "a#b", "a{b", "a}b", "a(b"} {
		for field, mut := range map[string]func(*deploy.Input){
			"domain":           func(i *deploy.Input) { i.Domain = "x" + v + ".example.test" },
			"acme_email":       func(i *deploy.Input) { i.ACMEEmail = "o" + v + "@example.test" },
			"teleport_version": func(i *deploy.Input) { i.TeleportVersion = "19.1.2" + v },
			"admin_username":   func(i *deploy.Input) { i.AdminUsername = "a" + v },
			"admin_logins":     func(i *deploy.Input) { i.AdminLogins = []string{"a" + v} },
		} {
			in := acme
			mut(&in)
			if _, err := deploy.Validate(in); fieldOf(err) != field {
				t.Errorf("%s with %q: %v", field, v, err)
			}
		}
	}
}
