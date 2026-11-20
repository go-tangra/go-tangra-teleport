//go:build integration

package integration

// US4 against a real Teleport Community Edition (T096, quickstart 4): five
// failed sign-ins for one user against the proxy's web login, with a burst
// rule of at least 3 in 5 minutes, give exactly one delivery on the
// notification fake within the 5-minute budget (SC-005); the event search
// filters them by user and type. Same container and helpers as
// TestClusterLifecycle. Run with:
//
//	go test -tags integration ./tests/integration/ -run TestFailedLoginBurstAlert

import (
	"bytes"
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/alerts"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/auditlog"
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

// failLogin attempts a web sign-in with a wrong password; Teleport records
// a user.login failure (T1000W) whatever the user.
func failLogin(t *testing.T, proxy, user string) {
	t.Helper()
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // the test container's self-signed proxy
	body := bytes.NewBufferString(`{"user":"` + user + `","pass":"wrong-password","second_factor_token":""}`)
	req, err := http.NewRequest(http.MethodPost, "https://"+proxy+"/v1/webapi/sessions/web", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		t.Fatalf("web login: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode < 400 {
		t.Fatalf("a wrong password was accepted: %d", res.StatusCode)
	}
}

func TestFailedLoginBurstAlert(t *testing.T) {
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
	store, sec, rec, sent := memstore.New(), secrets.NewFake(), &events.Recorder{}, notify.NewFake()
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
		return teleportapi.Dial(ctx, teleportapi.DialParams{ProxyAddr: proxy, Identity: id, Guard: guard, Limits: limits})
	})
	t.Cleanup(pool.Close)
	aud := &recorder{}
	az := &authz.Authorizer{Checker: authz.Static{itAdmin: authz.Permissions}, Clusters: store}
	cs := &clusters.Service{Repo: store, Secrets: sec, Pool: pool, Guard: guard, Limits: limits, Authz: az, Audit: aud,
		Events: rec, Notify: sent, Log: slog.New(slog.DiscardHandler)}
	as := authz.WithSubjects(ctx, authz.User(itTenant, itAdmin, nil))
	cl, err := cs.Register(as, clusters.RegisterInput{DisplayName: "it", ProxyAddr: proxy, Credential: clusters.NewCredential(identity)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	rules := &alerts.Rules{Repo: store, Authz: az, Audit: aud}
	if _, err := rules.Create(as, alerts.RuleInput{ClusterID: cl.ID, Name: "failed logins", ConditionKind: repo.ConditionTeleportEvent,
		EventTypes: []string{auditlog.TypeLoginFailure}, ThresholdCount: 3, WindowMinutes: 5,
		Recipients: alerts.Recipients{UserIDs: []string{itAdmin}}}); err != nil {
		t.Fatalf("rule: %v", err)
	}
	engine := &alerts.Engine{Clusters: cs, Repo: store, Notify: sent, Audit: aud, Lookback: 10 * time.Minute, Settle: time.Second}

	for range 5 {
		failLogin(t, proxy, "mallory")
	}
	if !eventually(5*time.Minute, func() bool {
		engine.RunOnce(ctx)
		return len(sent.Sent()) > 0
	}) {
		t.Fatal("no alert within 5 minutes (SC-005)")
	}
	for range 3 { // later polls deliver nothing more for the same burst
		time.Sleep(2 * time.Second)
		engine.RunOnce(ctx)
	}
	got := sent.Sent()
	if len(got) != 1 || got[0].Template != notify.TemplateAlert || got[0].Vars["user"] != "mallory" || got[0].Vars["cluster_id"] != cl.ID {
		t.Fatalf("deliveries %+v", got)
	}

	// The events view filters the failures by user and type (scenario 4).
	svc := &auditlog.Service{Clusters: cs}
	now := time.Now().UTC()
	p, err := svc.Events(as, cl.ID, auditlog.Query{From: now.Add(-time.Hour), To: now, Types: []string{auditlog.TypeLoginFailure}, User: "mallory"})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(p.Items) < 5 {
		t.Fatalf("%d failed logins found", len(p.Items))
	}
	for _, e := range p.Items {
		if e.Type != auditlog.TypeLoginFailure || e.Success || e.User != "mallory" {
			t.Fatalf("event %+v", e)
		}
	}
}
