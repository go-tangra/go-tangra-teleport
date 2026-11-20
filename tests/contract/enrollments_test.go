package contract

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"

	inventoryv1 "github.com/go-tangra/go-tangra-inventory/sdk/v4/api/proto/inventory/v1"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/enroll"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/enroll/enrolltest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/httpapi"
)

// enrollmentRoutes are the spec 002 routes with their permissions.
var enrollmentRoutes = map[string]string{
	"GET /api/teleport/v1/clusters/{id}/enrollment-targets":        authz.ResourcesEnroll,
	"GET /api/teleport/v1/clusters/{id}/enrollments":               authz.ResourcesRead,
	"POST /api/teleport/v1/clusters/{id}/enrollments":              authz.ResourcesEnroll,
	"POST /api/teleport/v1/clusters/{id}/enrollments/{eid}/cancel": authz.ResourcesEnroll,
	"POST /api/teleport/v1/clusters/{id}/enrollments/{eid}/retry":  authz.ResourcesEnroll,
}

func enrollmentRouteList() []string {
	out := make([]string, 0, len(enrollmentRoutes))
	for r := range enrollmentRoutes {
		out = append(out, r)
	}
	return out
}

const (
	enrollHost1 = "a1a1a1a1-1111-7111-8111-111111111111"
	enrollHost2 = "a2a2a2a2-2222-7222-8222-222222222222"
)

func enrollmentServer(t *testing.T) (*httpapi.Server, *enrolltest.Inventory, string) {
	t.Helper()
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	inv := enrolltest.New()
	inv.AddHost(ct.TenantA, &inventoryv1.TeleportJoinTarget{HostId: enrollHost1, Hostname: "web-1", OsName: "ubuntu", AgentOnline: true,
		Tags: map[string]string{"env": "prod"}})
	inv.AddHost(ct.TenantA, &inventoryv1.TeleportJoinTarget{HostId: enrollHost2, Hostname: "web-2"})
	inv.Refuse(enrollHost2, "upgrade_required")
	rt := testrt.New(t, testutil.MustCA("example.org"), "teleport")
	v := tokens{"admin": {UserID: ct.Admin, TenantID: ct.TenantA}, "viewer": {UserID: ct.Viewer, TenantID: ct.TenantA},
		"operator": {UserID: ct.Operator, TenantID: ct.TenantA}}
	s, err := httpapi.NewHandler(rt, httpapi.WithVerifier(v), httpapi.WithChecker(e.Perms))
	if err != nil {
		t.Fatal(err)
	}
	s.Register(httpapi.Deps{Clusters: e.Service,
		Enroll: &enroll.Service{Clusters: e.Service, Repo: e.Repo, Inventory: inv.Dial(), Audit: e.Audit, Events: e.Events, Now: e.Now}})
	return s, inv, c.ID
}

func TestEnrollmentRoutesDeclareTheirPermissions(t *testing.T) {
	s, _, _ := enrollmentServer(t)
	implemented := map[string]bool{}
	for _, r := range s.Implemented() {
		implemented[r.String()] = true
	}
	for route, perm := range enrollmentRoutes {
		method, path, _ := strings.Cut(route, " ")
		if got := s.Permission(method, path); got != perm {
			t.Errorf("%s: permission %q, want %q", route, got, perm)
		}
		if !implemented[route] {
			t.Errorf("%s has no handler", route)
		}
	}
}

// Every spec 002 route answers in the declared shape; no response carries
// a join token.
func TestEnrollmentResponsesMatchSchemas(t *testing.T) {
	doc := load(t)
	s, inv, id := enrollmentServer(t)
	base := "/api/teleport/v1/clusters/" + id

	_, w := call(s, "POST", base+"/enrollments", "operator", map[string]any{"host_ids": []string{enrollHost1, enrollHost2}, "ttl_hours": 12})
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var created struct {
		Items   []struct{ ID string } `json:"items"`
		Refused []struct{ Reason string }
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if len(created.Items) != 1 || len(created.Refused) != 1 || created.Refused[0].Reason != "upgrade_required" {
		t.Fatalf("created %s", w.Body)
	}
	eid := created.Items[0].ID
	inv.Set(eid, inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_FAILED, "install_failed", "")

	type tc struct {
		method, path, token string
		body                any
		status              int
		reason              string
	}
	for _, c := range []tc{
		{"GET", base + "/enrollment-targets", "operator", nil, 200, ""},
		{"GET", base + "/enrollment-targets?q=web&limit=1", "admin", nil, 200, ""},
		{"GET", base + "/enrollment-targets?limit=x", "operator", nil, 400, ""}, // refused by the request validator
		{"GET", base + "/enrollment-targets", "viewer", nil, 403, "forbidden"},
		{"GET", base + "/enrollments", "viewer", nil, 200, ""},
		{"POST", base + "/enrollments", "viewer", map[string]any{"host_ids": []string{enrollHost1}}, 403, "forbidden"},
		{"POST", base + "/enrollments", "operator", map[string]any{"host_ids": []string{}}, 422, "validation_failed"},
		{"POST", base + "/enrollments", "operator", map[string]any{"host_ids": []string{enrollHost1}, "ttl_hours": 100}, 422, "validation_failed"},
		{"POST", base + "/enrollments/" + eid + "/retry", "viewer", nil, 403, "forbidden"},
		{"POST", base + "/enrollments/" + eid + "/retry", "operator", nil, 201, ""},
		{"POST", base + "/enrollments/" + eid + "/cancel", "operator", nil, 200, ""},
		{"POST", base + "/enrollments/018f3a2b-0000-7000-8000-0000000000ff/cancel", "operator", nil, 404, "not_found"},
	} {
		r, w := call(s, c.method, c.path, c.token, c.body)
		if w.Code != c.status {
			t.Fatalf("%s %s: %d %s", c.method, c.path, w.Code, w.Body)
		}
		var m struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		if c.reason != "" && m.Reason != c.reason {
			t.Fatalf("%s %s: reason %q, want %s (%s)", c.method, c.path, m.Reason, c.reason, w.Body)
		}
		if strings.Contains(strings.ToLower(w.Body.String()), "token") {
			t.Fatalf("%s %s carries a token: %s", c.method, c.path, w.Body)
		}
		ValidateResponse(t, doc, r, w)
	}
	// A refused retry answers the refusal reason; an outage is a dependency.
	_, w = call(s, "POST", base+"/enrollments", "operator", map[string]any{"host_ids": []string{enrollHost1}})
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	_, w = call(s, "POST", base+"/enrollments/"+created.Items[0].ID+"/cancel", "operator", nil)
	inv.Refuse(enrollHost1, "retired")
	r, w := call(s, "POST", base+"/enrollments/"+created.Items[0].ID+"/retry", "operator", nil)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "retired") {
		t.Fatalf("refused retry: %d %s", w.Code, w.Body)
	}
	ValidateResponse(t, doc, r, w)
	inv.SetDown(true)
	r, w = call(s, "GET", base+"/enrollment-targets", "operator", nil)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "dependency_unavailable") {
		t.Fatalf("down: %d %s", w.Code, w.Body)
	}
	ValidateResponse(t, doc, r, w)
	r, w = call(s, "GET", base+"/enrollments", "viewer", nil)
	if w.Code != 200 {
		t.Fatalf("list down: %d %s", w.Code, w.Body)
	}
	ValidateResponse(t, doc, r, w)
}
