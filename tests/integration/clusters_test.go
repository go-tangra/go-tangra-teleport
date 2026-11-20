//go:build integration

package integration

// US1 against a real Teleport Community Edition (T047): a single-node
// cluster in a container, the tangra-manager role from the help docs and an
// identity issued with tctl inside the container. The cluster is registered
// through the real teleportapi.Dial and netguard, its counts are checked,
// then the container is stopped and three health checks on an injected
// clock (inside the 5-minute window) must mark it unreachable, publish the
// status change and notify.
//
// The proxy is reached on the container's bridge address: netguard refuses
// loopback outright, so the guard opens only 172.16.0.0/12 (the dev-only
// teleport.allowed_private_networks opt-out). Override the image with
// TELEPORT_IT_IMAGE (pin it by digest in CI). Run with:
//
//	go test -tags integration ./tests/integration/ -run TestClusterLifecycle

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

const (
	itTenant  = "11111111-1111-7111-8111-111111111111"
	itAdmin   = "55555555-5555-7555-8555-555555555555"
	itCluster = "it.example.com"
)

const teleportConfig = `version: v3
teleport:
  nodename: it
  data_dir: /var/lib/teleport
  log: { output: stderr, severity: INFO }
auth_service:
  enabled: true
  cluster_name: ` + itCluster + `
  listen_addr: 0.0.0.0:3025
  proxy_listener_mode: multiplex
proxy_service:
  enabled: true
  web_listen_addr: 0.0.0.0:3080
ssh_service:
  enabled: false
`

// roleYAML extracts the tangra-manager role from the help page, so the
// documented role is the one the test proves.
func roleYAML(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../docs/help/reference/tangra-manager-role.md"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)```yaml\n(.*?)```").FindSubmatch(raw)
	if m == nil {
		t.Fatal("role YAML block not found in the help page")
	}
	return string(m[1])
}

func tctl(t *testing.T, ctx context.Context, c testcontainers.Container, args ...string) {
	t.Helper()
	code, out, err := c.Exec(ctx, append([]string{"tctl", "-c", "/etc/teleport/teleport.yaml"}, args...))
	if err != nil || code != 0 {
		b, _ := io.ReadAll(out)
		t.Fatalf("tctl %v: %d %v\n%s", args, code, err, b)
	}
}

type recorder struct {
	mu   sync.Mutex
	rows []repo.AuditRow
}

func (r *recorder) Record(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows = append(r.rows, repo.AuditRow{Action: string(e.Action), Outcome: e.Outcome})
	return nil
}

func TestClusterLifecycle(t *testing.T) {
	ctx := context.Background()
	image := os.Getenv("TELEPORT_IT_IMAGE")
	if image == "" {
		image = "public.ecr.aws/gravitational/teleport-distroless:18"
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        image,
			Entrypoint:   []string{"teleport", "start", "-c", "/etc/teleport/teleport.yaml"},
			ExposedPorts: []string{"3080/tcp"},
			Files: []testcontainers.ContainerFile{
				{Reader: strings.NewReader(teleportConfig), ContainerFilePath: "/etc/teleport/teleport.yaml", FileMode: 0o644},
				{Reader: strings.NewReader(roleYAML(t)), ContainerFilePath: "/etc/teleport/tangra-manager-role.yaml", FileMode: 0o644},
			},
			WaitingFor: wait.ForLog("The new Teleport process has started").WithStartupTimeout(3 * time.Minute),
		}, Started: true,
	})
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	tctl(t, ctx, c, "create", "-f", "/etc/teleport/tangra-manager-role.yaml")
	tctl(t, ctx, c, "users", "add", "tangra-mgmt", "--roles=tangra-manager")
	tctl(t, ctx, c, "auth", "sign", "--user=tangra-mgmt", "--format=file", "--ttl=2h", "--out=/tmp/tangra-mgmt.identity", "--overwrite")
	rc, err := c.CopyFileFromContainer(ctx, "/tmp/tangra-mgmt.identity")
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := io.ReadAll(rc)
	_ = rc.Close()
	ip, err := c.ContainerIP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proxy := ip + ":3080"

	guard, err := netguard.New(netguard.Policy{AllowedPrivate: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")}})
	if err != nil {
		t.Fatal(err)
	}
	store, sec, rec, nt := memstore.New(), secrets.NewFake(), &events.Recorder{}, notify.NewFake()
	if err := store.CreateAlertRule(ctx, repo.AlertRule{ID: "018f3a2b-0000-7000-8000-0000000000c1", TenantID: itTenant, Name: "outage",
		ConditionKind: repo.ConditionClusterUnreachable, Recipients: repo.Recipients{UserIDs: []string{"ops"}}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	limits := teleportapi.Limits{CallTimeout: 5 * time.Second}
	pool := teleportapi.NewPool(func(ctx context.Context, k teleportapi.Key) (teleportapi.Client, error) {
		ref, err := secrets.ParseRef(k.CredentialRef)
		if err != nil {
			return nil, teleportapi.ErrCredentialInvalid
		}
		id, err := sec.Get(ctx, ref)
		if err != nil {
			return nil, teleportapi.ErrCredentialInvalid
		}
		return teleportapi.Dial(ctx, teleportapi.DialParams{ProxyAddr: k.ProxyAddr, Identity: id, Guard: guard, Limits: limits})
	})
	t.Cleanup(pool.Close)
	var mu sync.Mutex
	now := time.Now().UTC()
	svc := &clusters.Service{Repo: store, Secrets: sec, Pool: pool, Guard: guard, Limits: limits,
		Authz: &authz.Authorizer{Checker: authz.Static{itAdmin: authz.Permissions}, Clusters: store}, Audit: &recorder{},
		Events: rec, Notify: nt, Recipients: clusters.RuleRecipients(store), Log: slog.New(slog.DiscardHandler),
		Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }}
	as := authz.WithSubjects(ctx, authz.User(itTenant, itAdmin, nil))

	v, err := svc.Register(as, clusters.RegisterInput{DisplayName: "it", ProxyAddr: proxy, Credential: clusters.NewCredential(identity)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if v.Status != repo.StatusConnected || v.ClusterName != itCluster || v.Edition != repo.EditionCommunity || v.ServerVersion == "" ||
		v.CredentialIdentity != "tangra-mgmt" || len(v.MissingPermissions) != 0 {
		t.Fatalf("registered %+v", v)
	}
	if v.Counts.Users < 1 || v.Counts.Roles < 1 {
		t.Fatalf("counts %+v", v.Counts)
	}
	if got, err := svc.Check(as, v.ID); err != nil || got.Status != repo.StatusConnected {
		t.Fatalf("check: %v %+v", err, got)
	}

	// Stop Teleport: three failed checks inside 5 minutes mark it unreachable.
	stop := 10 * time.Second
	if err := c.Stop(ctx, &stop); err != nil {
		t.Fatal(err)
	}
	m := &clusters.Monitor{Service: svc}
	for range 3 {
		mu.Lock()
		now = now.Add(time.Minute)
		mu.Unlock()
		m.RunOnce(ctx)
	}
	got, err := svc.Get(as, v.ID)
	if err != nil || got.Status != repo.StatusUnreachable || got.LastContactAt == nil {
		t.Fatalf("after outage: %v %+v", err, got)
	}
	if len(rec.OfType(events.ClusterStatusChanged)) != 1 || len(nt.OfTemplate(notify.TemplateClusterUnreachable)) != 1 {
		t.Fatalf("status events %d, notifications %d", len(rec.OfType(events.ClusterStatusChanged)), len(nt.OfTemplate(notify.TemplateClusterUnreachable)))
	}

	// Removal deletes the registration and the secret; Teleport is untouched.
	if err := svc.Remove(as, v.ID); err != nil || sec.Len() != 0 {
		t.Fatalf("remove: %v (secrets %d)", err, sec.Len())
	}
}
