package contract

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/locks"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/provisioning"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/users"
)

// provisioningRoutes are the US5 routes of contracts/http-api.md
// (Provisioning) with their permissions.
var provisioningRoutes = map[string]string{
	"GET /api/teleport/v1/clusters/{id}/mappings":           authz.UsersRead,
	"POST /api/teleport/v1/clusters/{id}/mappings":          authz.ProvisioningManage,
	"PUT /api/teleport/v1/clusters/{id}/mappings/{mid}":     authz.ProvisioningManage,
	"DELETE /api/teleport/v1/clusters/{id}/mappings/{mid}":  authz.ProvisioningManage,
	"GET /api/teleport/v1/clusters/{id}/managed-users":      authz.UsersRead,
	"POST /api/teleport/v1/clusters/{id}/managed-users":     authz.ProvisioningManage,
	"POST /api/teleport/v1/clusters/{id}/provisioning:sync": authz.ProvisioningManage,
}

func provisioningRouteList() []string {
	out := make([]string, 0, len(provisioningRoutes))
	for r := range provisioningRoutes {
		out = append(out, r)
	}
	return out
}

const (
	memberID   = "018f3a2b-0000-7000-8000-0000000000b1"
	outsiderID = "018f3a2b-0000-7000-8000-0000000000c1"
)

func provisioningServer(t *testing.T) (*httpapi.Server, *ct.Env, *provisioning.FakeMembership, string) {
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
	auth := provisioning.NewFakeMembership(provisioning.Member{UserID: memberID, Login: "bob", Roles: []string{"operator"}})
	s.Register(httpapi.Deps{Clusters: e.Service, Provisioning: &provisioning.Service{
		Clusters: e.Service, Repo: e.Repo, Membership: auth, Notify: e.Notify, Audit: e.Audit, Events: e.Events, Now: e.Now,
		Users: &users.Service{Clusters: e.Service, Audit: e.Audit, Events: e.Events},
		Locks: &locks.Service{Clusters: e.Service, Audit: e.Audit, Events: e.Events, Now: e.Now},
	}})
	return s, e, auth, c.ID
}

func TestProvisioningRoutesDeclareTheirPermissions(t *testing.T) {
	s, _, _, _ := provisioningServer(t)
	implemented := map[string]bool{}
	for _, r := range s.Implemented() {
		implemented[r.String()] = true
	}
	for route, perm := range provisioningRoutes {
		method, path, _ := strings.Cut(route, " ")
		if got := s.Permission(method, path); got != perm {
			t.Errorf("%s: permission %q, want %q", route, got, perm)
		}
		if !implemented[route] {
			t.Errorf("%s has no handler", route)
		}
	}
}

// Every US5 route answers in the declared shape (quickstart scenario 5).
func TestProvisioningResponsesMatchSchemas(t *testing.T) {
	doc := load(t)
	s, e, auth, id := provisioningServer(t)
	base := "/api/teleport/v1/clusters/" + id
	_, cr := call(s, "POST", base+"/mappings", "admin", map[string]any{"subject_kind": "module_role", "subject_ref": "operator",
		"teleport_roles": []string{"access"}, "logins": []string{"ubuntu"}})
	if cr.Code != 201 {
		t.Fatalf("create mapping: %d %s", cr.Code, cr.Body)
	}
	var m struct{ ID string }
	_ = json.Unmarshal(cr.Body.Bytes(), &m)
	type tc struct {
		method, path, token string
		body                any
		status              int
		reason, dependency  string
	}
	cases := []tc{
		{"GET", base + "/mappings", "viewer", nil, 200, "", ""},
		{"POST", base + "/mappings", "admin", map[string]any{"subject_kind": "group", "subject_ref": "devs", "teleport_roles": []string{"editor"}}, 201, "", ""},
		{"POST", base + "/mappings", "admin", map[string]any{"subject_kind": "group", "subject_ref": "devs", "teleport_roles": []string{"editor"}}, 409, "conflict", ""},
		{"POST", base + "/mappings", "admin", map[string]any{"subject_kind": "group", "subject_ref": "ops", "teleport_roles": []string{"nope"}}, 422, "validation_failed", ""},
		{"POST", base + "/mappings", "admin", map[string]any{"subject_kind": "team", "subject_ref": "ops", "teleport_roles": []string{"access"}}, 422, "validation_failed", ""},
		{"POST", base + "/mappings", "admin", map[string]any{"subject_kind": "group", "subject_ref": "ops", "teleport_roles": []string{"access"}, "logins": []string{"root;id"}}, 422, "validation_failed", ""},
		{"POST", base + "/mappings", "operator", map[string]any{"subject_kind": "group", "subject_ref": "ops", "teleport_roles": []string{"access"}}, 403, "forbidden", ""},
		{"PUT", base + "/mappings/" + m.ID, "admin", map[string]any{"teleport_roles": []string{"access", "editor"}, "logins": []string{"ubuntu"}}, 200, "", ""},
		{"PUT", base + "/mappings/" + m.ID, "operator", map[string]any{"teleport_roles": []string{"access"}}, 403, "forbidden", ""},
		{"PUT", base + "/mappings/018f3a2b-0000-7000-8000-0000000000ff", "admin", map[string]any{"teleport_roles": []string{"access"}}, 404, "not_found", ""},
		{"GET", base + "/managed-users", "viewer", nil, 200, "", ""},
		{"POST", base + "/managed-users", "operator", map[string]any{"tangra_user_id": memberID}, 403, "forbidden", ""},
		{"POST", base + "/managed-users", "admin", map[string]any{"tangra_user_id": outsiderID}, 422, "validation_failed", ""},
		{"POST", base + "/managed-users", "admin", map[string]any{"tangra_user_id": memberID}, 201, "", ""},
		{"POST", base + "/managed-users", "admin", map[string]any{"tangra_user_id": memberID}, 409, "conflict", ""},
		{"GET", base + "/managed-users", "viewer", nil, 200, "", ""},
		{"POST", base + "/provisioning:sync", "operator", nil, 403, "forbidden", ""},
		{"POST", base + "/provisioning:sync", "admin", nil, 200, "", ""},
		{"GET", "/api/teleport/v1/clusters/018f3a2b-0000-7000-8000-0000000000ff/mappings", "viewer", nil, 404, "not_found", ""},
	}
	run := func(c tc) {
		t.Helper()
		r, rec := call(s, c.method, c.path, c.token, c.body)
		if rec.Code != c.status {
			t.Fatalf("%s %s: %d %s", c.method, c.path, rec.Code, rec.Body)
		}
		var out struct {
			Reason string         `json:"reason"`
			Detail map[string]any `json:"detail"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if c.reason != "" && out.Reason != c.reason {
			t.Fatalf("%s %s: reason %q, want %s", c.method, c.path, out.Reason, c.reason)
		}
		if c.dependency != "" && out.Detail["dependency"] != c.dependency {
			t.Fatalf("%s %s: detail %v", c.method, c.path, out.Detail)
		}
		if rec.Code != 204 {
			ValidateResponse(t, doc, r, rec)
		}
		for _, u := range e.Teleport.IssuedURLs() {
			if strings.Contains(rec.Body.String(), u) {
				t.Fatalf("%s %s carries an invite link", c.method, c.path)
			}
		}
	}
	for _, c := range cases {
		run(c)
	}
	// Dependencies: notification down, then auth down.
	auth.Set(provisioning.Member{UserID: memberID, Login: "bob", Roles: []string{"operator"}},
		provisioning.Member{UserID: outsiderID, Login: "carol", Roles: []string{"operator"}})
	e.Notify.SetErr(notify.ErrUnavailable)
	run(tc{"POST", base + "/managed-users", "admin", map[string]any{"tangra_user_id": outsiderID}, 503, "dependency_unavailable", "notification"})
	e.Notify.SetErr(nil)
	auth.SetErr(notify.ErrUnavailable)
	run(tc{"POST", base + "/provisioning:sync", "admin", nil, 503, "dependency_unavailable", "auth"})
	run(tc{"DELETE", base + "/mappings/" + m.ID, "operator", nil, 403, "forbidden", ""})
	run(tc{"DELETE", base + "/mappings/" + m.ID, "admin", nil, 204, "", ""})
	run(tc{"DELETE", base + "/mappings/" + m.ID, "admin", nil, 404, "not_found", ""})
}
