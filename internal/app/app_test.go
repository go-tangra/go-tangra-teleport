package app

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra/v4"
	"github.com/go-tangra/go-tangra/v4/authn"
	"github.com/go-tangra/go-tangra/v4/identity"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/config"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/lease"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/resources"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/stream"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi/identitytest"
)

const (
	appTenant = "11111111-1111-7111-8111-111111111111"
	marker    = "TELEPORT-IDENTITY-MARKER"
)

type fakeVerifier struct{}

func (fakeVerifier) Verify(_ context.Context, token string) (authclient.Identity, error) {
	switch token {
	case "viewer":
		return authclient.Identity{UserID: "u1", TenantID: appTenant}, nil
	case "nobody":
		return authclient.Identity{UserID: "u9", TenantID: appTenant}, nil
	}
	return authclient.Identity{}, errors.New("unauthenticated")
}

func testConfig() config.Config {
	c := config.Default()
	c.ServiceName, c.TrustDomain, c.Env = "teleport", "example.org", "dev"
	c.DB.DSN = "postgres://unused"
	c.Valkey.Addresses, c.Valkey.AllowPlaintext = []string{"127.0.0.1:1"}, true
	c.Server.GRPCAddr, c.Server.HTTPAddr, c.Admin.Addr = "127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:0"
	c.Discovery.Static = map[string][]string{"lcm": {"127.0.0.1:1"}, "auth": {"127.0.0.1:1"}, "gateway": {"127.0.0.1:1"}, "warden": {"127.0.0.1:1"}}
	c.Gateway.Service, c.Gateway.Issuer = "gateway", "https://localhost:8443"
	return c
}

func options(sec secrets.Store, dial teleportapi.DialFunc) Options {
	return Options{
		Verifier: fakeVerifier{}, Checker: authz.Static{"u1": {authz.ClustersRead}},
		Repo: memstore.New(), Secrets: sec, Stream: stream.NewMemory(), Cache: teleportapi.NewMemoryKV(), Lease: lease.NewMemory(),
		Dial:  dial,
		Freya: []freya.Option{freya.WithInsecureLocalDev(), freya.WithAllowAllPolicy()},
	}
}

func TestBuildWiresTheService(t *testing.T) {
	a, err := Build(context.Background(), testConfig(), options(secrets.NewFake(), nil))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer a.Close()
	if a.Freya == nil || a.Repo == nil || a.HTTP == nil || a.Hub == nil || a.Audit == nil || a.Metrics == nil || a.Secrets == nil ||
		a.Events == nil || a.Checker == nil || a.Authz == nil || a.Pool == nil || a.Cache == nil || a.Lease == nil || a.Guard == nil || a.Docs == nil {
		t.Fatalf("app not fully wired: %+v", a)
	}
	do := func(path, tok string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://localhost"+path, nil)
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		w := httptest.NewRecorder()
		a.HTTP.Handler().ServeHTTP(w, r)
		return w
	}
	if w := do("/api/teleport/v1/health", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"ok"`) {
		t.Fatalf("health: %d %s", w.Code, w.Body)
	}
	if w := do("/api/teleport/v1/stream", ""); w.Code != 401 {
		t.Fatalf("anonymous stream: %d", w.Code)
	}
	if w := do("/api/teleport/v1/stream", "nobody"); w.Code != 403 {
		t.Fatalf("stream without permission: %d", w.Code)
	}
	a.Close()
	a.Close() // idempotent
}

// The pool's dial resolves the credential reference through the secret
// store at use time and hands the identity to the dialer; it is never kept
// on the app or logged.
func TestPoolDialResolvesCredential(t *testing.T) {
	sec := secrets.NewFake()
	ref, err := sec.Put(context.Background(), "c1", secrets.NewSecret([]byte(marker)))
	if err != nil {
		t.Fatal(err)
	}
	var got teleportapi.DialParams
	fake := teleportapi.NewFake()
	var logs strings.Builder
	o := options(sec, nil)
	o.Logger = slog.NewTextHandler(&logs, nil)
	o.dialer = func(_ context.Context, p teleportapi.DialParams) (teleportapi.Client, error) {
		got = p
		return fake, nil
	}
	a, err := Build(context.Background(), testConfig(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	c := repo.Cluster{ID: "c1", TenantID: appTenant, ProxyAddr: "teleport.example.com:443", CredentialRef: ref.String()}
	cl, err := a.Pool.Get(context.Background(), KeyFor(c))
	if err != nil || cl != fake {
		t.Fatalf("pool get: %v", err)
	}
	if string(got.Identity.Reveal()) != marker || got.ProxyAddr != c.ProxyAddr || got.Guard != a.Guard || got.Limits.CallTimeout != 10*time.Second {
		t.Fatalf("dial params: proxy %q guard %v limits %+v", got.ProxyAddr, got.Guard == a.Guard, got.Limits)
	}
	// Bad and unknown references fail without dialling.
	if _, err := a.Pool.Get(context.Background(), teleportapi.Key{ClusterID: "c2", CredentialRef: "nope"}); !errors.Is(err, teleportapi.ErrCredentialInvalid) {
		t.Fatalf("bad ref: %v", err)
	}
	if _, err := a.Pool.Get(context.Background(), teleportapi.Key{ClusterID: "c3", CredentialRef: "warden:fake/missing"}); !errors.Is(err, teleportapi.ErrCredentialInvalid) {
		t.Fatalf("missing ref: %v", err)
	}
	if strings.Contains(logs.String(), marker) {
		t.Fatal("identity logged")
	}
}

// Without a Dial override the default dialer is the real teleportapi.Dial,
// which refuses a blocked (loopback) target before any network I/O.
func TestDefaultDialRefusesBlockedTarget(t *testing.T) {
	sec := secrets.NewFake()
	ref, _ := sec.Put(context.Background(), "c1", secrets.NewSecret([]byte("not an identity")))
	a, err := Build(context.Background(), testConfig(), options(sec, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	_, err = a.Pool.Get(context.Background(), teleportapi.Key{ClusterID: "c1", CredentialRef: ref.String(), ProxyAddr: "127.0.0.1:443"})
	if err == nil {
		t.Fatal("dial accepted")
	}
}

func TestHealthReportsComponents(t *testing.T) {
	a, err := Build(context.Background(), testConfig(), options(secrets.NewFake(), nil))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	h := a.health()
	if h["store"] != "ok" || h["event_bus"] != "ok" {
		t.Fatalf("health %v", h)
	}
}

func TestWorkersAndLeases(t *testing.T) {
	a, err := Build(context.Background(), testConfig(), options(secrets.NewFake(), nil))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	var runs atomic.Int32
	base := len(a.Workers())
	a.AddLeasedWorker("probe", func(ctx context.Context) { runs.Add(1) })
	a.AddWorker("plain", func(ctx context.Context) {})
	if len(a.Workers()) != base+2 || a.Workers()[base].Name != "probe" {
		t.Fatalf("workers %+v", a.Workers())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Workers()[base].Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for runs.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if runs.Load() == 0 {
		t.Fatal("leased worker never ran")
	}
}

// US1 is wired: the cluster routes answer through the verification dialer
// and the secret store, and the health monitor is a leased worker.
func TestBuildWiresClusters(t *testing.T) {
	fake := teleportapi.NewFake()
	fake.Info = teleportapi.Info{ClusterName: "prod.example.com", ServerVersion: "19.0.0", Edition: teleportapi.EditionCommunity}
	sec := secrets.NewFake()
	o := options(sec, nil)
	o.Checker = authz.Static{"u1": authz.Permissions}
	o.Notify = notify.NewFake()
	var dials atomic.Int32
	o.dialer = func(_ context.Context, p teleportapi.DialParams) (teleportapi.Client, error) {
		dials.Add(1)
		return teleportapi.Limit(fake, p.Limits), nil
	}
	a, err := Build(context.Background(), testConfig(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.Clusters == nil || a.Notify == nil {
		t.Fatal("clusters not wired")
	}
	monitor := false
	for _, w := range a.Workers() {
		monitor = monitor || w.Name == "health-monitor"
	}
	if !monitor {
		t.Fatalf("no health monitor: %+v", a.Workers())
	}
	body, _ := json.Marshal(map[string]string{"display_name": "prod", "proxy_addr": "93.184.216.34",
		"credential": identitytest.New(t, identitytest.Options{Cluster: "prod.example.com"})})
	r := httptest.NewRequest("POST", "https://localhost/api/teleport/v1/clusters", strings.NewReader(string(body)))
	r.Header.Set("Authorization", "Bearer viewer")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", "csrf")
	w := httptest.NewRecorder()
	a.HTTP.Handler().ServeHTTP(w, r)
	if w.Code != 201 || sec.Len() != 1 || dials.Load() != 1 {
		t.Fatalf("register: %d %s (secrets %d, dials %d)", w.Code, w.Body, sec.Len(), dials.Load())
	}
}

func TestRegistrationLoop(t *testing.T) {
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		registrationLoop(ctx, slog.New(slog.DiscardHandler), func(context.Context) error {
			if calls.Add(1) == 1 {
				return errors.New("auth down")
			}
			return nil
		}, time.Millisecond, 5*time.Millisecond)
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if calls.Load() < 3 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestBuildRefusesWithoutDocsOrBadConfig(t *testing.T) {
	c := testConfig()
	c.Teleport.AllowedPrivateNetworks = []string{"not-a-cidr"}
	if _, err := Build(context.Background(), c, options(secrets.NewFake(), nil)); err == nil {
		t.Fatal("bad private networks accepted")
	}
}

// US4 is wired: the alert-rule routes answer, the alert poller is a leased
// worker, and module-condition alerts reach the engine through the late
// alerter.
func TestBuildWiresAlerts(t *testing.T) {
	o := options(secrets.NewFake(), nil)
	o.Checker = authz.Static{"u1": authz.Permissions}
	sent := notify.NewFake()
	o.Notify = sent
	a, err := Build(context.Background(), testConfig(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	poller := false
	for _, w := range a.Workers() {
		poller = poller || w.Name == "alert-poller"
	}
	if !poller || a.AuditLog == nil || a.AlertRules == nil || a.Alerter != resources.Alerter(a.AlertEngine) {
		t.Fatalf("alerts not wired: %+v", a.Workers())
	}
	r := httptest.NewRequest("GET", "https://localhost/api/teleport/v1/alert-rules", nil)
	r.Header.Set("Authorization", "Bearer viewer")
	w := httptest.NewRecorder()
	a.HTTP.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("alert rules: %d %s", w.Code, w.Body)
	}
	c := repo.Cluster{ID: store.NewID(), TenantID: "11111111-1111-7111-8111-111111111111", DisplayName: "c", ProxyAddr: "93.184.216.34:443",
		CredentialRef: "warden:x", CredentialKind: repo.CredentialIdentityFile, Status: repo.StatusConnected,
		Settings: repo.ClusterSettings{OfflineThresholdMinutes: 15, AlertsEnabled: true}}
	if err := a.Repo.CreateCluster(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if err := a.Repo.CreateAlertRule(context.Background(), repo.AlertRule{ID: store.NewID(), TenantID: c.TenantID, Name: "offline",
		ConditionKind: repo.ConditionResourceOffline, Recipients: repo.Recipients{UserIDs: []string{"u1"}}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	late := lateAlerter{a}
	late.Alert(context.Background(), c, repo.ConditionResourceOffline, "k", map[string]string{"resource": "n1"})
	late.Alert(context.Background(), c, repo.ConditionResourceOffline, "k", map[string]string{"resource": "n1"})
	if len(sent.Sent()) != 1 {
		t.Fatalf("sent %d", len(sent.Sent()))
	}
	a.Alerter = nil
	late.Alert(context.Background(), c, repo.ConditionResourceOffline, "k2", nil)
}

// T116: the task executor is always served and admits only the verified
// scheduler of the module's own trust domain; the registrar runs only when
// task_scheduler.enabled.
func TestSchedulerWiring(t *testing.T) {
	a, err := Build(context.Background(), testConfig(), options(secrets.NewFake(), nil))
	if err != nil {
		t.Fatal(err)
	}
	base := len(a.Workers())
	if a.Tasks == nil || a.Tasks.Clusters == nil || a.Tasks.Provisioning == nil || a.Backup == nil {
		t.Fatalf("tasks %+v", a.Tasks)
	}
	if _, ok := a.Freya.GRPC().Server.GetServiceInfo()["scheduler.v1.TaskExecutor"]; !ok {
		t.Fatal("TaskExecutor not served")
	}
	a.Close()
	cfg := testConfig()
	cfg.TaskScheduler.Enabled = true
	cfg.Events.TenantStream = "platform:events:system"
	b, err := Build(context.Background(), cfg, options(secrets.NewFake(), nil))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var names []string
	for _, w := range b.Workers() {
		names = append(names, w.Name)
	}
	if len(names) != base+2 || !strings.Contains(strings.Join(names, ","), "scheduler-registrar") || !strings.Contains(strings.Join(names, ","), "tenant-lifecycle") {
		t.Fatalf("workers %v", names)
	}
	caller := schedulerCaller("example.org")
	if _, ok := caller(context.Background()); ok {
		t.Fatal("a call without a verified peer has a caller")
	}
	for peer, want := range map[string]bool{"spiffe://example.org/svc/scheduler": true, "spiffe://other.org/svc/scheduler": false} {
		id, err := identity.ParseSPIFFEID(peer)
		if err != nil {
			t.Fatal(err)
		}
		svc, ok := caller(authn.WithPeer(context.Background(), authn.PeerIdentity{ID: id}))
		if ok != want || (want && svc != "scheduler") {
			t.Errorf("%s: %q %v", peer, svc, ok)
		}
	}
}

// Spec 003 is wired: the recording route is mounted (a permitted caller
// reaches the service: an unknown cluster is not_found, not 501) and the
// bounds come from config.
func TestBuildWiresRecording(t *testing.T) {
	o := options(secrets.NewFake(), nil)
	o.Checker = authz.Static{"u1": authz.Permissions}
	cfg := testConfig()
	cfg.Recording.MaxBytes = 2 << 20
	a, err := Build(context.Background(), cfg, o)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.Recording == nil || a.Recording.MaxBytes != 2<<20 || a.Recording.Signer == nil || a.Recording.Limiter == nil {
		t.Fatalf("recording %+v", a.Recording)
	}
	r := httptest.NewRequest("GET", "https://localhost/api/teleport/v1/clusters/018f3a2b-0000-7000-8000-0000000000ff/sessions/abc-1/recording", nil)
	r.Header.Set("Authorization", "Bearer viewer")
	w := httptest.NewRecorder()
	a.HTTP.Handler().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("recording route: %d %s", w.Code, w.Body)
	}
}
