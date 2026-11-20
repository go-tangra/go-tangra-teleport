//go:build integration

package integration

// Degraded mode against a real Teleport Community Edition (T119, quickstart
// scenario 8): notification, scheduler and inventory are stopped. The
// notification client dials a peer that does not answer, no scheduler ever
// calls the task executor, and the inventory/asset host lookup and the auth
// membership source are the production "unavailable" adapters. Cluster
// management (register, users, mappings) keeps working; provisioning and
// automatic linking report dependency_unavailable; the leased health
// monitor and the resource watcher keep updating status on their own. A
// unit-level twin with fakes runs in the normal gate
// (internal/app TestDegradedModeWithFakes). Run with:
//
//	go test -tags integration ./tests/integration/ -run TestDegradedMode

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/locks"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/provisioning"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/resources"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/users"
)

func TestDegradedMode(t *testing.T) {
	ctx := context.Background()
	image := os.Getenv("TELEPORT_IT_IMAGE")
	if image == "" {
		image = "public.ecr.aws/gravitational/teleport-distroless:18"
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:      image,
			Entrypoint: []string{"teleport", "start", "-c", "/etc/teleport/teleport.yaml"},
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
	st, sec, rec := memstore.New(), secrets.NewFake(), &events.Recorder{}
	if err := st.CreateAlertRule(ctx, repo.AlertRule{ID: "018f3a2b-0000-7000-8000-0000000000c2", TenantID: itTenant, Name: "outage",
		ConditionKind: repo.ConditionClusterUnreachable, Recipients: repo.Recipients{UserIDs: []string{"ops"}}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	// notification is stopped: every dial fails.
	var notifyDials sync.Map
	nt := notify.NewClient(func(context.Context) (grpc.ClientConnInterface, error) {
		notifyDials.Store(time.Now(), true)
		return nil, errors.New("notification: connection refused")
	}, slog.New(slog.DiscardHandler))
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
	svc := &clusters.Service{Repo: st, Secrets: sec, Pool: pool, Guard: guard, Limits: limits,
		Authz: &authz.Authorizer{Checker: authz.Static{itAdmin: authz.Permissions}, Clusters: st}, Audit: &recorder{},
		Events: rec, Notify: nt, Recipients: clusters.RuleRecipients(st), Log: slog.New(slog.DiscardHandler),
		Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }}
	as := authz.WithSubjects(ctx, authz.User(itTenant, itAdmin, nil))
	cache := &teleportapi.Cache{KV: teleportapi.NewMemoryKV()}
	us := &users.Service{Clusters: svc, Audit: &recorder{}, Events: rec, Cache: cache}
	prov := &provisioning.Service{Clusters: svc, Repo: st, Users: us,
		Locks:      &locks.Service{Clusters: svc, Audit: &recorder{}, Events: rec, Cache: cache},
		Membership: provisioning.Unavailable{}, Notify: nt, Audit: &recorder{}, Events: rec, Log: slog.New(slog.DiscardHandler)}
	linker := &resources.Linker{Repo: st, Directory: resources.UnavailableDirectory{}, Events: rec}
	res := &resources.Service{Clusters: svc, Repo: st, Linker: linker, Cache: cache, Audit: &recorder{}, Events: rec}
	watcher := &resources.Watcher{Clusters: svc, Repo: st, Linker: linker, Cache: cache, Events: rec, Log: slog.New(slog.DiscardHandler)}
	wctx, stopWatch := context.WithCancel(ctx)
	t.Cleanup(func() { stopWatch(); watcher.Stop() })

	// Cluster management works.
	v, err := svc.Register(as, clusters.RegisterInput{DisplayName: "it", ProxyAddr: proxy, Credential: clusters.NewCredential(identity)})
	if err != nil || v.Status != repo.StatusConnected {
		t.Fatalf("register: %v %+v", err, v)
	}
	page, err := us.List(as, v.ID, users.ListInput{})
	if err != nil || len(page.Items) == 0 {
		t.Fatalf("users: %v %+v", err, page)
	}
	if _, err := prov.CreateMapping(as, v.ID, provisioning.MappingInput{SubjectKind: repo.SubjectModuleRole, SubjectRef: "operator",
		TeleportRoles: []string{"access"}, Logins: []string{"ubuntu"}}); err != nil {
		t.Fatalf("mapping: %v", err)
	}
	if n := watcher.RunOnce(wctx); n != 1 {
		t.Fatalf("watching %d clusters", n)
	}

	// The affected features report dependency_unavailable.
	if _, err := prov.Sync(as, v.ID); provisioning.ReasonOf(err) != "dependency_unavailable" {
		t.Fatalf("sync: %v", err)
	}
	rp, err := res.List(as, v.ID, resources.ListInput{})
	if err != nil || rp.LinkStatus != resources.LinkStatusUnavailable {
		t.Fatalf("resources: %v %+v", err, rp)
	}

	// The leased monitor keeps updating status with no scheduler and
	// notification down.
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
	if err != nil || got.Status != repo.StatusUnreachable {
		t.Fatalf("after outage: %v %+v", err, got)
	}
	if len(rec.OfType(events.ClusterStatusChanged)) != 1 {
		t.Fatalf("status events %d", len(rec.OfType(events.ClusterStatusChanged)))
	}
	dialled := 0
	notifyDials.Range(func(any, any) bool { dialled++; return true })
	if dialled == 0 {
		t.Fatal("the outage notification was never attempted")
	}
	if watcher.Watching() != 1 {
		t.Fatal("the watcher stopped watching")
	}
}
