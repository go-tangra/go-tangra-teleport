//go:build integration

package integration

// US2 against a real Teleport Community Edition (T069, quickstart 2–2d):
// create alice with an invite, refuse a stale edit, lock alice and see
// Teleport refuse her own identity within 30 s (SC-004), unlock her, and
// refuse deleting the built-in `editor` role and locking the management
// identity. Same container and helpers as TestClusterLifecycle. Run with:
//
//	go test -tags integration ./tests/integration/ -run TestIdentityLifecycle

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/locks"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/roles"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/users"
)

func tctlOut(t *testing.T, ctx context.Context, c testcontainers.Container, args ...string) string {
	t.Helper()
	code, out, err := c.Exec(ctx, append([]string{"tctl", "-c", "/etc/teleport/teleport.yaml"}, args...))
	b, _ := io.ReadAll(out)
	if err != nil || code != 0 {
		t.Fatalf("tctl %v: %d %v\n%s", args, code, err, b)
	}
	return string(b)
}

func copyOut(t *testing.T, ctx context.Context, c testcontainers.Container, path string) []byte {
	t.Helper()
	rc, err := c.CopyFileFromContainer(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	return b
}

// eventually retries fn every second for up to d.
func eventually(d time.Duration, fn func() bool) bool {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(time.Second) {
		if fn() {
			return true
		}
	}
	return fn()
}

func guardOf(err error) string {
	var g *clusters.GuardError
	if errors.As(err, &g) {
		return g.Guard
	}
	return ""
}

func TestIdentityLifecycle(t *testing.T) {
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
			WaitingFor: wait.ForLog(teleportReady).WithStartupTimeout(3 * time.Minute),
		}, Started: true,
	})
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	tctl(t, ctx, c, "create", "-f", "/etc/teleport/tangra-manager-role.yaml")
	addManager(t, ctx, c)
	tctl(t, ctx, c, "auth", "sign", "--user=tangra-mgmt", "--format=file", "--ttl=2h", "--out=/tmp/tangra-mgmt.identity", "--overwrite")
	identity := copyOut(t, ctx, c, "/tmp/tangra-mgmt.identity")
	ip, err := c.ContainerIP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proxy := ip + ":3080"

	guard, err := netguard.New(netguard.Policy{AllowedPrivate: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")}})
	if err != nil {
		t.Fatal(err)
	}
	store, sec, rec := memstore.New(), secrets.NewFake(), &events.Recorder{}
	limits := teleportapi.Limits{CallTimeout: 5 * time.Second}
	dial := func(ctx context.Context, id secrets.Secret) (teleportapi.Client, error) {
		return teleportapi.Dial(ctx, teleportapi.DialParams{ProxyAddr: proxy, Identity: id, Guard: guard, Limits: limits})
	}
	pool := teleportapi.NewPool(func(ctx context.Context, k teleportapi.Key) (teleportapi.Client, error) {
		ref, err := secrets.ParseRef(k.CredentialRef)
		if err != nil {
			return nil, teleportapi.ErrCredentialInvalid
		}
		id, err := sec.Get(ctx, ref)
		if err != nil {
			return nil, teleportapi.ErrCredentialInvalid
		}
		return dial(ctx, id)
	})
	t.Cleanup(pool.Close)
	aud := &recorder{}
	cs := &clusters.Service{Repo: store, Secrets: sec, Pool: pool, Guard: guard, Limits: limits,
		Authz: &authz.Authorizer{Checker: authz.Static{itAdmin: authz.Permissions}, Clusters: store}, Audit: aud,
		Events: rec, Notify: notify.NewFake(), Log: slog.New(slog.DiscardHandler)}
	us := &users.Service{Clusters: cs, Audit: aud, Events: rec}
	rs := &roles.Service{Clusters: cs, Audit: aud, Events: rec}
	ls := &locks.Service{Clusters: cs, Audit: aud, Events: rec}
	as := authz.WithSubjects(ctx, authz.User(itTenant, itAdmin, nil))

	cl, err := cs.Register(as, clusters.RegisterInput{DisplayName: "it", ProxyAddr: proxy, Credential: clusters.NewCredential(identity)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// 2: create alice; the invite is returned once and Teleport has her roles.
	created, err := us.Create(as, cl.ID, users.CreateInput{Name: "alice", Roles: []string{"access"}, Logins: []string{"ubuntu"}})
	if err != nil || created.InviteURL.IsZero() || created.InviteExpiresAt.IsZero() {
		t.Fatalf("create alice: %v %+v", err, created)
	}
	if out := tctlOut(t, ctx, c, "get", "users/alice", "--format=json"); !strings.Contains(out, `"access"`) || !strings.Contains(out, `"ubuntu"`) {
		t.Fatalf("tctl get users/alice:\n%s", out)
	}
	if _, err := us.Update(as, cl.ID, "alice", users.UpdateInput{Roles: []string{"access", "editor"}, Revision: "stale"}); !errors.Is(err, teleportapi.ErrConflict) {
		t.Fatalf("stale user update: %v", err)
	}

	// 2b: a stale role edit is a conflict.
	def, err := rs.Get(as, cl.ID, "access")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rs.Put(as, cl.ID, "access", roles.PutInput{YAML: def.YAML, Revision: "stale"}); !errors.Is(err, teleportapi.ErrConflict) {
		t.Fatalf("stale role edit: %v", err)
	}

	// 2c: alice's own identity is refused while she is locked (SC-004: 30 s).
	tctl(t, ctx, c, "auth", "sign", "--user=alice", "--format=file", "--ttl=1h", "--out=/tmp/alice.identity", "--overwrite")
	alice, err := dial(ctx, secrets.NewSecret(copyOut(t, ctx, c, "/tmp/alice.identity")))
	if err != nil {
		t.Fatalf("dial as alice: %v", err)
	}
	defer alice.Close()
	if _, err := alice.Ping(ctx); err != nil {
		t.Fatalf("alice before the lock: %v", err)
	}
	lk, err := ls.Create(as, cl.ID, locks.CreateInput{TargetKind: "user", Target: "alice", Reason: "integration incident"})
	if err != nil {
		t.Fatalf("lock alice: %v", err)
	}
	if !eventually(30*time.Second, func() bool { _, err := alice.Ping(ctx); return err != nil }) {
		t.Fatal("alice still works 30 s after the lock")
	}
	active, err := ls.List(as, cl.ID)
	if err != nil || len(active.Items) != 1 || active.Items[0].Message != "integration incident" || active.Items[0].CreatedBy != itAdmin {
		t.Fatalf("active locks: %v %+v", err, active)
	}
	if err := ls.Remove(as, cl.ID, lk.Name); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if !eventually(30*time.Second, func() bool { _, err := alice.Ping(ctx); return err == nil }) {
		t.Fatal("alice is still refused 30 s after the unlock")
	}

	// 2d: the built-in editor role and the management identity are guarded.
	if err := rs.Delete(as, cl.ID, "editor"); guardOf(err) != clusters.GuardPresetRole {
		t.Fatalf("delete editor: %v", err)
	}
	if _, err := ls.Create(as, cl.ID, locks.CreateInput{TargetKind: "user", Target: "tangra-mgmt", Reason: "x"}); guardOf(err) != clusters.GuardSelfIdentity {
		t.Fatalf("lock tangra-mgmt: %v", err)
	}
	if _, err := ls.Create(as, cl.ID, locks.CreateInput{TargetKind: "role", Target: "tangra-manager", Reason: "x"}); guardOf(err) != clusters.GuardManagementRole {
		t.Fatalf("lock tangra-manager: %v", err)
	}
	if err := us.Delete(as, cl.ID, "alice"); err != nil {
		t.Fatalf("delete alice: %v", err)
	}
	if len(rec.OfType(events.LockCreated)) != 1 || len(rec.OfType(events.UserDeleted)) != 1 {
		t.Fatalf("events %+v", rec.All())
	}
}
