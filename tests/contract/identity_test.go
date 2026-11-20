package contract

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/locks"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/roles"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/users"
)

// identityRoutes are the US2 routes of contracts/http-api.md (Users, Roles,
// Locks) with their permissions.
var identityRoutes = map[string]string{
	"GET /api/teleport/v1/clusters/{id}/users":               authz.UsersRead,
	"POST /api/teleport/v1/clusters/{id}/users":              authz.UsersManage,
	"PUT /api/teleport/v1/clusters/{id}/users/{name}":        authz.UsersManage,
	"DELETE /api/teleport/v1/clusters/{id}/users/{name}":     authz.UsersManage,
	"POST /api/teleport/v1/clusters/{id}/users/{name}/reset": authz.UsersManage,
	"GET /api/teleport/v1/clusters/{id}/roles":               authz.RolesRead,
	"GET /api/teleport/v1/clusters/{id}/roles/{name}":        authz.RolesRead,
	"POST /api/teleport/v1/clusters/{id}/roles/preview":      authz.RolesManage,
	"PUT /api/teleport/v1/clusters/{id}/roles/{name}":        authz.RolesManage,
	"DELETE /api/teleport/v1/clusters/{id}/roles/{name}":     authz.RolesManage,
	"GET /api/teleport/v1/clusters/{id}/locks":               authz.LocksRead,
	"POST /api/teleport/v1/clusters/{id}/locks":              authz.LocksManage,
	"DELETE /api/teleport/v1/clusters/{id}/locks/{name}":     authz.LocksManage,
}

func identityRouteList() []string {
	out := make([]string, 0, len(identityRoutes))
	for r := range identityRoutes {
		out = append(out, r)
	}
	return out
}

// identityServer mounts the cluster, user, role and lock routes over the
// US1 harness with one registered cluster.
func identityServer(t *testing.T) (*httpapi.Server, *ct.Env, string) {
	t.Helper()
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	rt := testrt.New(t, testutil.MustCA("example.org"), "teleport")
	v := tokens{"admin": {UserID: ct.Admin, TenantID: ct.TenantA}, "viewer": {UserID: ct.Viewer, TenantID: ct.TenantA},
		"operator": {UserID: ct.Operator, TenantID: ct.TenantA}}
	s, err := httpapi.NewHandler(rt, httpapi.WithVerifier(v), httpapi.WithChecker(e.Perms))
	if err != nil {
		t.Fatal(err)
	}
	s.Register(httpapi.Deps{Clusters: e.Service,
		Users: &users.Service{Clusters: e.Service, Audit: e.Audit, Events: e.Events},
		Roles: &roles.Service{Clusters: e.Service, Audit: e.Audit, Events: e.Events},
		Locks: &locks.Service{Clusters: e.Service, Audit: e.Audit, Events: e.Events}})
	return s, e, c.ID
}

func TestIdentityRoutesDeclareTheirPermissions(t *testing.T) {
	s, _, _ := identityServer(t)
	implemented := map[string]bool{}
	for _, r := range s.Implemented() {
		implemented[r.String()] = true
	}
	for route, perm := range identityRoutes {
		method, path, _ := strings.Cut(route, " ")
		if got := s.Permission(method, path); got != perm {
			t.Errorf("%s: permission %q, want %q", route, got, perm)
		}
		if !implemented[route] {
			t.Errorf("%s has no handler", route)
		}
	}
}

const devRole = "kind: role\nversion: v7\nmetadata: {name: dev}\nspec: {allow: {logins: [dev]}}\n"

// Every US2 route answers in the declared shape, for success and for the
// refusals the contract names (quickstart scenarios 2–2e).
func TestIdentityResponsesMatchSchemas(t *testing.T) {
	doc := load(t)
	s, e, id := identityServer(t)
	base := "/api/teleport/v1/clusters/" + id
	e.Teleport.Locks = []teleportapi.Lock{{Name: "old", TargetKind: "server_id", Target: "n-1", Message: "x"}}
	type tc struct {
		method, path, token string
		body                any
		status              int
		reason, guard       string
	}
	for _, c := range []tc{
		// Users.
		{"GET", base + "/users", "viewer", nil, 200, "", ""},
		{"GET", base + "/users?q=ali&page_size=10", "viewer", nil, 200, "", ""},
		{"POST", base + "/users", "admin", map[string]any{"name": "carol", "roles": []string{"access"}, "logins": []string{"ubuntu"}}, 201, "", ""},
		{"POST", base + "/users", "admin", map[string]any{"name": "carol", "roles": []string{"access"}}, 409, "conflict", ""},
		{"POST", base + "/users", "admin", map[string]any{"name": "dave", "roles": []string{"nope"}}, 422, "validation_failed", ""},
		{"POST", base + "/users", "admin", map[string]any{"name": "dave", "roles": []string{}}, 422, "validation_failed", ""},
		{"POST", base + "/users", "admin", map[string]any{"name": "a b", "roles": []string{"access"}}, 422, "validation_failed", ""},
		{"POST", base + "/users", "viewer", map[string]any{"name": "dave", "roles": []string{"access"}}, 403, "forbidden", ""},
		{"PUT", base + "/users/alice", "admin", map[string]any{"roles": []string{"editor"}, "revision": "stale"}, 409, "conflict", ""},
		{"PUT", base + "/users/alice", "admin", map[string]any{"roles": []string{"editor"}, "logins": []string{"root"}, "revision": "u2"}, 200, "", ""},
		{"PUT", base + "/users/alice", "admin", map[string]any{"roles": []string{"editor"}}, 422, "validation_failed", ""},
		{"PUT", base + "/users/" + ct.Management, "admin", map[string]any{"roles": []string{"access"}, "revision": "u1"}, 403, "forbidden", "self_identity"},
		{"POST", base + "/users/alice/reset", "admin", nil, 200, "", ""},
		{"POST", base + "/users/nobody/reset", "admin", nil, 404, "not_found", ""},
		{"DELETE", base + "/users/" + ct.Management, "admin", nil, 403, "forbidden", "self_identity"},
		{"DELETE", base + "/users/carol", "operator", nil, 403, "forbidden", ""},
		{"DELETE", base + "/users/carol", "admin", nil, 204, "", ""},
		// Roles.
		{"GET", base + "/roles", "viewer", nil, 200, "", ""},
		{"GET", base + "/roles/editor", "viewer", nil, 200, "", ""},
		{"GET", base + "/roles/nope", "viewer", nil, 404, "not_found", ""},
		{"POST", base + "/roles/preview", "admin", map[string]any{"yaml": devRole}, 200, "", ""},
		{"POST", base + "/roles/preview", "admin", map[string]any{"yaml": "kind: user\n"}, 200, "", ""},
		{"POST", base + "/roles/preview", "admin", map[string]any{"yaml": strings.Repeat("#", 70000)}, 422, "validation_failed", ""},
		{"POST", base + "/roles/preview", "operator", map[string]any{"yaml": devRole}, 403, "forbidden", ""},
		{"PUT", base + "/roles/dev", "admin", map[string]any{"yaml": devRole}, 200, "", ""},
		{"PUT", base + "/roles/dev", "admin", map[string]any{"yaml": devRole}, 409, "conflict", ""},
		{"PUT", base + "/roles/access", "admin", map[string]any{"yaml": "kind: role\nversion: v7\nmetadata: {name: access}\n", "revision": "stale"}, 409, "conflict", ""},
		{"PUT", base + "/roles/other", "admin", map[string]any{"yaml": devRole}, 422, "validation_failed", ""},
		{"PUT", base + "/roles/dev", "admin", map[string]any{"yaml": "kind: role\nversion: v6\n"}, 422, "validation_failed", ""},
		{"PUT", base + "/roles/dev", "operator", map[string]any{"yaml": devRole}, 403, "forbidden", ""},
		{"DELETE", base + "/roles/editor", "admin", nil, 403, "forbidden", "preset_role"},
		{"DELETE", base + "/roles/" + ct.ManagerRole, "admin", nil, 403, "forbidden", "management_role"},
		{"DELETE", base + "/roles/dev", "admin", nil, 204, "", ""},
		// Locks.
		{"GET", base + "/locks", "viewer", nil, 200, "", ""},
		{"POST", base + "/locks", "operator", map[string]any{"target_kind": "user", "target": "alice", "reason": "incident", "expires_at": "2099-01-01T00:00:00Z"}, 201, "", ""},
		{"POST", base + "/locks", "admin", map[string]any{"target_kind": "user", "target": "alice"}, 422, "validation_failed", ""},
		{"POST", base + "/locks", "admin", map[string]any{"target_kind": "user", "target": "alice", "reason": "x", "expires_at": "2000-01-01T00:00:00Z"}, 422, "validation_failed", ""},
		{"POST", base + "/locks", "admin", map[string]any{"target_kind": "user", "target": ct.Management, "reason": "x"}, 403, "forbidden", "self_identity"},
		{"POST", base + "/locks", "admin", map[string]any{"target_kind": "role", "target": ct.ManagerRole, "reason": "x"}, 403, "forbidden", "management_role"},
		{"POST", base + "/locks", "viewer", map[string]any{"target_kind": "user", "target": "alice", "reason": "x"}, 403, "forbidden", ""},
		{"DELETE", base + "/locks/old", "viewer", nil, 403, "forbidden", ""},
		{"DELETE", base + "/locks/old", "operator", nil, 204, "", ""},
		{"DELETE", base + "/locks/old", "operator", nil, 404, "not_found", ""},
		// Another tenant's or an unknown cluster.
		{"GET", "/api/teleport/v1/clusters/018f3a2b-0000-7000-8000-0000000000ff/users", "viewer", nil, 404, "not_found", ""},
	} {
		r, w := call(s, c.method, c.path, c.token, c.body)
		if w.Code != c.status {
			t.Fatalf("%s %s: %d %s", c.method, c.path, w.Code, w.Body)
		}
		var m struct {
			Reason string         `json:"reason"`
			Detail map[string]any `json:"detail"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		if c.reason != "" && m.Reason != c.reason {
			t.Fatalf("%s %s: reason %q, want %s (%s)", c.method, c.path, m.Reason, c.reason, w.Body)
		}
		if c.guard != "" && m.Detail["guard"] != c.guard {
			t.Fatalf("%s %s: guard %v, want %s", c.method, c.path, m.Detail["guard"], c.guard)
		}
		if w.Code != http.StatusNoContent {
			ValidateResponse(t, doc, r, w)
		}
	}
}

// One-time links appear only in the responses that create them.
func TestOneTimeFieldsOnlyInCreatingResponses(t *testing.T) {
	doc := load(t)
	allowed := map[string]string{
		"invite_url": "POST /api/teleport/v1/clusters/{id}/users",
		"reset_url":  "POST /api/teleport/v1/clusters/{id}/users/{name}/reset",
		// US3: join tokens and what embeds them.
		"token":           "POST /api/teleport/v1/clusters/{id}/tokens",
		"install_command": "POST /api/teleport/v1/clusters/{id}/tokens",
		"config_snippet":  "POST /api/teleport/v1/clusters/{id}/tokens",
	}
	for p, item := range doc.Paths.Map() {
		for m, op := range item.Operations() {
			fields := map[string]bool{}
			for _, resp := range op.Responses.Map() {
				if resp.Value == nil {
					continue
				}
				for _, media := range resp.Value.Content {
					schemaFields(media.Schema, fields, map[*openapi3.Schema]bool{})
				}
			}
			for f, route := range allowed {
				if fields[f] && m+" "+p != route {
					t.Errorf("%s %s returns %s", m, p, f)
				}
			}
		}
	}
}
