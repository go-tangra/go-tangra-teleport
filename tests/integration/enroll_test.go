//go:build integration

package integration

// US3 against a real Teleport Community Edition (T085, quickstart 3–3b):
// issue a node join token through the module, join a second Teleport node
// container with the returned config snippet, see the watcher mark it
// online within the 10-minute budget (SC-003), stop the node and see it go
// offline, then revoke a fresh token and see Teleport no longer list it.
// Same container and helpers as TestClusterLifecycle. Run with:
//
//	go test -tags integration ./tests/integration/ -run TestEnrollLifecycle

import (
	"context"
	"encoding/json"
	"github.com/testcontainers/testcontainers-go/network"
	"gopkg.in/yaml.v3"
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
	"github.com/go-tangra/go-tangra-teleport/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/resources"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/tokens"
)

func TestEnrollLifecycle(t *testing.T) {
	ctx := context.Background()
	image := os.Getenv("TELEPORT_IT_IMAGE")
	if image == "" {
		image = "public.ecr.aws/gravitational/teleport-distroless:18"
	}
	// The node reconnects to the proxy's advertised address after joining, so
	// both containers share a network and the proxy advertises its alias
	// (production proxies set public_addr, as the deployment wizard does).
	nw, err := network.New(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = nw.Remove(ctx) })
	start := func(ready wait.Strategy, flags []string, cfg string, extra ...testcontainers.ContainerFile) (testcontainers.Container, error) {
		return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:          image,
				Networks:       []string{nw.Name},
				NetworkAliases: map[string][]string{nw.Name: {proxyAlias}},
				Entrypoint:     append([]string{"teleport", "start", "-c", "/etc/teleport/teleport.yaml"}, flags...),
				Files: append([]testcontainers.ContainerFile{{Reader: strings.NewReader(cfg), ContainerFilePath: "/etc/teleport/teleport.yaml", FileMode: 0o644}},
					extra...),
				WaitingFor: ready,
			}, Started: true,
		})
	}
	c, err := start(wait.ForLog(teleportReady).WithStartupTimeout(3*time.Minute), nil,
		strings.Replace(teleportConfig, "  web_listen_addr: 0.0.0.0:3080\n", "  web_listen_addr: 0.0.0.0:3080\n  public_addr: "+proxyAlias+":3080\n", 1), testcontainers.ContainerFile{Reader: strings.NewReader(roleYAML(t)),
			ContainerFilePath: "/etc/teleport/tangra-manager-role.yaml", FileMode: 0o644})
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
	cs := &clusters.Service{Repo: store, Secrets: sec, Pool: pool, Guard: guard, Limits: limits,
		Authz: &authz.Authorizer{Checker: authz.Static{itAdmin: authz.Permissions}, Clusters: store}, Audit: aud,
		Events: rec, Notify: notify.NewFake(), Log: slog.New(slog.DiscardHandler)}
	ts := &tokens.Service{Clusters: cs, Repo: store, Audit: aud, Events: rec}
	linker := &resources.Linker{Repo: store, Directory: resources.UnavailableDirectory{}, Events: rec}
	rs := &resources.Service{Clusters: cs, Repo: store, Linker: linker, Audit: aud, Events: rec}
	as := authz.WithSubjects(ctx, authz.User(itTenant, itAdmin, nil))
	cl, err := cs.Register(as, clusters.RegisterInput{DisplayName: "it", ProxyAddr: proxy, Credential: clusters.NewCredential(identity)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	w := &resources.Watcher{Clusters: cs, Repo: store, Linker: linker, Events: rec, Backoff: time.Second,
		Log: slog.New(slog.NewTextHandler(os.Stderr, nil))}
	wctx, stop := context.WithCancel(ctx)
	defer func() { stop(); w.Stop() }()
	w.RunOnce(wctx)

	// 3: a node token; the node joins with the returned config snippet.
	ttl := 15
	tok, err := ts.Create(as, cl.ID, tokens.CreateInput{ResourceType: repo.KindNode, TTLMinutes: &ttl})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	cfg := nodeConfig(t, oneTime(t, tok.ConfigSnippet))
	// The agent has no proxy line; the online poll below is its readiness check.
	// The test proxy's certificate is self-signed, so the agent skips its
	// verification here (production proxies carry a valid certificate).
	node, err := start(nil, []string{"--insecure"}, cfg)
	if err != nil {
		t.Fatalf("node container: %v", err)
	}
	if !eventually(10*time.Minute, func() bool {
		p, err := rs.List(as, cl.ID, resources.ListInput{Kind: repo.KindNode, Status: resources.StatusOnline})
		if err != nil {
			t.Logf("list: %v", err)
		}
		return err == nil && len(p.Items) == 1 && p.Items[0].Name != ""
	}) {
		if rc, err := node.Logs(ctx); err == nil {
			b, _ := io.ReadAll(rc)
			t.Logf("node logs (tail):\n%s", tail(string(b), 40))
		}
		t.Fatal("the joined node is not online within 10 minutes (SC-003)")
	}
	if len(rec.OfType(events.ResourceOnline)) == 0 {
		t.Fatal("no online event")
	}
	// 3a: the node stops; the watcher marks it offline once Teleport drops it.
	_ = node.Terminate(ctx)
	if !eventually(15*time.Minute, func() bool {
		p, err := rs.List(as, cl.ID, resources.ListInput{Status: resources.StatusOffline})
		return err == nil && len(p.Items) == 1
	}) {
		t.Fatal("the stopped node never went offline")
	}

	// 3b: a revoked token is gone from Teleport.
	tok2, err := ts.Create(as, cl.ID, tokens.CreateInput{ResourceType: repo.KindNode})
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.Revoke(as, cl.ID, tok2.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if out := tctlOut(t, ctx, c, "tokens", "ls"); strings.Contains(out, oneTime(t, tok2.Token)) {
		t.Fatal("Teleport still lists the revoked token")
	}
}

// oneTime reads a one-time value the way the browser does: from its JSON.
func oneTime(t *testing.T, o secrets.OneTime) string {
	t.Helper()
	b, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	var v string
	_ = json.Unmarshal(b, &v)
	return v
}

// tail returns the last n lines of s.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// proxyAlias is the auth+proxy container's name on the test network.
const proxyAlias = "teleport-it"

// nodeConfig edits the generated snippet as YAML (it is 4-space indented, so
// splicing lines would break it): a fixed node name and data dir, SSH on.
func nodeConfig(t *testing.T, snippet string) string {
	t.Helper()
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(snippet), &cfg); err != nil {
		t.Fatalf("config snippet: %v\n%s", err, snippet)
	}
	tp := cfg["teleport"].(map[string]any)
	tp["nodename"], tp["data_dir"] = "joined-1", "/var/lib/teleport"
	tp["proxy_server"] = proxyAlias + ":3080"
	cfg["ssh_service"] = map[string]any{"enabled": true}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
