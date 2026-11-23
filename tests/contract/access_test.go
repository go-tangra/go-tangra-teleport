package contract

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
	"github.com/gravitational/teleport/api/identityfile"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/access"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/terminal"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/users"
)

// accessRoutes are the spec 004 routes (plan.md Contract).
var accessRoutes = map[string]string{
	"GET /api/teleport/v1/clusters/{id}/access":                     authz.AccessTerminal,
	"GET /api/teleport/v1/clusters/{id}/access/nodes":               authz.AccessTerminal,
	"POST /api/teleport/v1/clusters/{id}/access/identity":           authz.AccessDownload,
	"PUT /api/teleport/v1/clusters/{id}/access/settings":            authz.ClustersManage,
	"POST /api/teleport/v1/clusters/{id}/terminals":                 authz.AccessTerminal,
	"DELETE /api/teleport/v1/clusters/{id}/terminals/{tid}":         authz.AccessTerminal,
	"GET /api/teleport/v1/clusters/{id}/terminals/{tid}/output":     authz.AccessTerminal,
	"POST /api/teleport/v1/clusters/{id}/terminals/{tid}/input":     authz.AccessTerminal,
	"POST /api/teleport/v1/clusters/{id}/terminals/{tid}/resize":    authz.AccessTerminal,
	"POST /api/teleport/v1/clusters/{id}/terminals/{tid}/keepalive": authz.AccessTerminal,
}

func accessRouteList() []string {
	out := make([]string, 0, len(accessRoutes))
	for r := range accessRoutes {
		out = append(out, r)
	}
	return out
}

const (
	accAlice = "aaaaaaaa-aaaa-7aaa-8aaa-aaaaaaaaaaaa" // provisioned, MFA session
	accCarol = "cccccccc-cccc-7ccc-8ccc-cccccccccccc" // not provisioned, MFA session
)

func accessServer(t *testing.T) (*httpapi.Server, *ct.Env, string) {
	s, e, id, _ := accessTerminalServer(t)
	return s, e, id
}

func accessTerminalServer(t *testing.T) (*httpapi.Server, *ct.Env, string, *terminal.Hub) {
	t.Helper()
	e := ct.New(t, nil)
	for _, u := range []string{accAlice, accCarol, otherTnt} {
		e.Perms[u] = []string{authz.AccessTerminal, authz.AccessDownload}
	}
	c := e.Register(t, ct.TenantA, "prod")
	if err := e.Repo.CreateManagedUser(context.Background(), repo.ManagedUser{ID: store.NewID(), TenantID: ct.TenantA, ClusterID: c.ID,
		TangraUserID: accAlice, TeleportUsername: "tangra-alice", State: repo.UserActive, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	e.Teleport.Users = append(e.Teleport.Users, teleportapi.User{Name: "tangra-alice", Roles: []string{"access"}, Logins: []string{"deploy"},
		Labels: map[string]string{users.LabelManaged: "true", users.LabelTenant: ct.TenantA, users.LabelUser: accAlice}})
	e.Teleport.Resources = append(e.Teleport.Resources, teleportapi.Resource{Kind: teleportapi.KindNode, Name: "node-1", Hostname: "web-1"})
	rt := testrt.New(t, testutil.MustCA("example.org"), "teleport")
	otp := []string{"pwd", "otp"}
	v := tokens{
		"admin":    {UserID: ct.Admin, TenantID: ct.TenantA, AMR: otp},
		"alice":    {UserID: accAlice, TenantID: ct.TenantA, AMR: otp},
		"alicepwd": {UserID: accAlice, TenantID: ct.TenantA, AMR: []string{"pwd"}},
		"carol":    {UserID: accCarol, TenantID: ct.TenantA, AMR: otp},
		"viewer":   {UserID: ct.Viewer, TenantID: ct.TenantA, AMR: otp},
		"outsider": {UserID: otherTnt, TenantID: ct.TenantB, AMR: otp},
	}
	s, err := httpapi.NewHandler(rt, httpapi.WithVerifier(v), httpapi.WithChecker(e.Perms))
	if err != nil {
		t.Fatal(err)
	}
	svc := &access.Service{Clusters: e.Service, Repo: e.Repo, Audit: e.Audit, Now: e.Now}
	hub := &terminal.Hub{Access: svc, Now: e.Now}
	t.Cleanup(hub.Shutdown)
	s.Register(httpapi.Deps{Clusters: e.Service, Access: svc, Terminals: hub})
	return s, e, c.ID, hub
}

// T013: every refusal of the access routes and the identity download.
func TestAccessRoutes(t *testing.T) {
	doc := load(t)
	s, e, id := accessServer(t)
	base := "/api/teleport/v1/clusters/" + id + "/access"
	do := func(method, path, token string, body any, status int, reason string) *httptest.ResponseRecorder {
		t.Helper()
		r, rec := call(s, method, path, token, body)
		if rec.Code != status {
			t.Fatalf("%s %s as %s: %d %s", method, path, token, rec.Code, rec.Body)
		}
		if reason != "" && reasonOf(t, rec.Body.Bytes()) != reason {
			t.Fatalf("%s %s as %s: %s, want %s", method, path, token, rec.Body, reason)
		}
		if rec.Header().Get("Content-Type") == "application/json" {
			ValidateResponse(t, doc, r, rec)
		}
		return rec
	}
	implemented := map[string]bool{}
	for _, r := range s.Implemented() {
		implemented[r.String()] = true
	}
	for route, perm := range accessRoutes {
		method, path, _ := strings.Cut(route, " ")
		if got := s.Permission(method, path); got != perm {
			t.Errorf("%s: permission %q, want %q", route, got, perm)
		}
		if !implemented[route] {
			t.Errorf("%s has no handler", route)
		}
	}

	rec := do("GET", base, "alicepwd", nil, 200, "")
	var my struct {
		TeleportUser string `json:"teleport_user"`
		MFA          bool   `json:"mfa"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &my)
	if my.TeleportUser != "tangra-alice" || my.MFA {
		t.Fatalf("my access %s", rec.Body)
	}
	do("GET", base, "viewer", nil, 403, "forbidden")
	do("GET", base, "carol", nil, 409, "not_provisioned")
	do("GET", base, "outsider", nil, 404, "not_found")
	do("GET", base+"/nodes", "alice", nil, 200, "")
	do("GET", base+"/nodes", "alicepwd", nil, 403, "mfa_required")

	do("POST", base+"/identity", "alicepwd", nil, 403, "mfa_required")
	do("POST", base+"/identity", "carol", nil, 409, "not_provisioned")
	do("POST", base+"/identity", "outsider", nil, 404, "not_found")
	do("POST", base+"/identity", "viewer", nil, 403, "forbidden")
	// FR-017: the permission refusal is audited as a failure.
	e.Audit.Flush(context.Background())
	refused := false
	for _, r := range e.Repo.Audit() {
		refused = refused || r.Action == "teleport.access.issued" && r.Outcome == "failure" && r.Reason == "forbidden" && r.ActorID == ct.Viewer
	}
	if !refused {
		t.Fatal("forbidden download not audited")
	}
	do("POST", base+"/identity", "alice", map[string]any{"ttl_minutes": 721}, 422, "validation_failed")
	do("POST", base+"/identity", "alice", map[string]any{"ttl_minutes": 5}, 422, "validation_failed")
	rec = do("POST", base+"/identity", "alice", map[string]any{"ttl_minutes": 60}, 200, "")
	h := rec.Header()
	if h.Get("Cache-Control") != "no-store" || !strings.HasPrefix(h.Get("Content-Disposition"), "attachment;") ||
		h.Get("X-Teleport-User") != "tangra-alice" || h.Get("X-Teleport-Expires") == "" || !strings.HasPrefix(h.Get("Content-Type"), "text/plain") {
		t.Fatalf("headers %v", h)
	}
	if exp, err := time.Parse(time.RFC3339, h.Get("X-Teleport-Expires")); err != nil || time.Until(exp) > 61*time.Minute {
		t.Fatalf("expiry %v %v", exp, err)
	}
	if _, err := identityfile.FromString(rec.Body.String()); err != nil {
		t.Fatal(err)
	}
	do("POST", base+"/identity", "alice", nil, 200, "")

	e.Teleport.ImpersonationDenied = true
	do("POST", base+"/identity", "alice", nil, 422, "access_identity_missing")
	e.Teleport.ImpersonationDenied = false
	e.Teleport.ClusterSessionMFA = true
	do("POST", base+"/identity", "alice", nil, 422, "session_mfa_required")
	e.Teleport.ClusterSessionMFA = false
	e.Teleport.Locks = []teleportapi.Lock{{Name: "l", TargetKind: "user", Target: "tangra-alice"}}
	do("POST", base+"/identity", "alice", nil, 409, "user_locked")
	e.Teleport.Locks = nil

	do("PUT", base+"/settings", "alice", map[string]any{"access_ttl_minutes": 60}, 403, "forbidden")
	do("PUT", base+"/settings", "admin", map[string]any{"access_ttl_minutes": 14}, 422, "validation_failed")
	do("PUT", base+"/settings", "outsider", map[string]any{"access_ttl_minutes": 60}, 403, "forbidden")
	do("PUT", base+"/settings", "admin", map[string]any{"access_ttl_minutes": 30}, 200, "")
	rec = do("GET", base, "alice", nil, 200, "")
	if !strings.Contains(rec.Body.String(), `"access_ttl_minutes":30`) {
		t.Fatalf("settings not applied: %s", rec.Body)
	}
}
