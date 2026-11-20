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
	"github.com/go-tangra/go-tangra-teleport/v4/internal/resources"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	tok "github.com/go-tangra/go-tangra-teleport/v4/internal/tokens"
)

// resourceRoutes are the US3 routes of contracts/http-api.md (Tokens,
// Resources) with their permissions.
var resourceRoutes = map[string]string{
	"GET /api/teleport/v1/clusters/{id}/tokens":                         authz.TokensManage,
	"POST /api/teleport/v1/clusters/{id}/tokens":                        authz.TokensManage,
	"DELETE /api/teleport/v1/clusters/{id}/tokens/{tid}":                authz.TokensManage,
	"GET /api/teleport/v1/clusters/{id}/resources":                      authz.ResourcesRead,
	"POST /api/teleport/v1/clusters/{id}/resources/{rid}/links":         authz.ResourcesLink,
	"DELETE /api/teleport/v1/clusters/{id}/resources/{rid}/links/{lid}": authz.ResourcesLink,
}

func resourceRouteList() []string {
	out := make([]string, 0, len(resourceRoutes))
	for r := range resourceRoutes {
		out = append(out, r)
	}
	return out
}

func resourceServer(t *testing.T) (*httpapi.Server, *ct.Env, string) {
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
	l := &resources.Linker{Repo: e.Repo, Directory: resources.UnavailableDirectory{}, Events: e.Events, Now: e.Now}
	s.Register(httpapi.Deps{Clusters: e.Service,
		Tokens:    &tok.Service{Clusters: e.Service, Repo: e.Repo, Audit: e.Audit, Events: e.Events, Now: e.Now},
		Resources: &resources.Service{Clusters: e.Service, Repo: e.Repo, Linker: l, Audit: e.Audit, Events: e.Events, Now: e.Now}})
	return s, e, c.ID
}

func TestResourceRoutesDeclareTheirPermissions(t *testing.T) {
	s, _, _ := resourceServer(t)
	implemented := map[string]bool{}
	for _, r := range s.Implemented() {
		implemented[r.String()] = true
	}
	for route, perm := range resourceRoutes {
		method, path, _ := strings.Cut(route, " ")
		if got := s.Permission(method, path); got != perm {
			t.Errorf("%s: permission %q, want %q", route, got, perm)
		}
		if !implemented[route] {
			t.Errorf("%s has no handler", route)
		}
	}
}

// Every US3 route answers in the declared shape (quickstart scenario 3).
func TestResourceResponsesMatchSchemas(t *testing.T) {
	doc := load(t)
	s, e, id := resourceServer(t)
	base := "/api/teleport/v1/clusters/" + id
	e.Teleport.Resources = []teleportapi.Resource{{Kind: teleportapi.KindNode, Name: "n1", Hostname: "web-1", Addr: "10.0.0.5:3022", Version: "19.0.1"}}

	_, w := call(s, "POST", base+"/tokens", "admin", map[string]any{"resource_type": "node", "ttl_minutes": 15})
	if w.Code != 201 {
		t.Fatalf("create token: %d %s", w.Code, w.Body)
	}
	var created struct{ ID, Token string }
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	_, w = call(s, "GET", base+"/resources", "viewer", nil)
	var page struct {
		Items []struct{ ID string } `json:"items"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Items) != 1 {
		t.Fatalf("resources %s", w.Body)
	}
	rid := page.Items[0].ID
	_, w = call(s, "POST", base+"/resources/"+rid+"/links", "operator", map[string]any{"target_module": "asset", "target_id": "a-1"})
	var link struct{ ID string }
	_ = json.Unmarshal(w.Body.Bytes(), &link)

	type tc struct {
		method, path, token string
		body                any
		status              int
		reason              string
	}
	for _, c := range []tc{
		{"POST", base + "/tokens", "admin", map[string]any{"resource_type": "db"}, 201, ""},
		{"POST", base + "/tokens", "admin", map[string]any{"resource_type": "node", "ttl_minutes": 2000}, 422, "validation_failed"},
		{"POST", base + "/tokens", "admin", map[string]any{"resource_type": "server"}, 422, "validation_failed"},
		{"POST", base + "/tokens", "viewer", map[string]any{"resource_type": "node"}, 403, "forbidden"},
		{"GET", base + "/tokens", "admin", nil, 200, ""},
		{"GET", base + "/tokens", "viewer", nil, 403, "forbidden"},
		{"DELETE", base + "/tokens/" + created.ID, "admin", nil, 204, ""},
		{"DELETE", base + "/tokens/018f3a2b-0000-7000-8000-0000000000ff", "admin", nil, 404, "not_found"},
		{"GET", base + "/resources", "viewer", nil, 200, ""},
		{"GET", base + "/resources?kind=node&status=online&page_size=10", "viewer", nil, 200, ""},
		{"GET", base + "/resources?label=novalue", "viewer", nil, 422, "validation_failed"},
		{"GET", base + "/resources?next=!!", "viewer", nil, 422, "validation_failed"},
		{"POST", base + "/resources/" + rid + "/links", "operator", map[string]any{"target_module": "inventory", "target_id": "i-1"}, 201, ""},
		{"POST", base + "/resources/" + rid + "/links", "viewer", map[string]any{"target_module": "inventory", "target_id": "i-1"}, 403, "forbidden"},
		{"POST", base + "/resources/018f3a2b-0000-7000-8000-0000000000ff/links", "operator", map[string]any{"target_module": "asset", "target_id": "x"}, 404, "not_found"},
		{"DELETE", base + "/resources/" + rid + "/links/" + link.ID, "operator", nil, 204, ""},
		{"DELETE", base + "/resources/" + rid + "/links/" + link.ID, "operator", nil, 404, "not_found"},
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
		if w.Code != 204 {
			ValidateResponse(t, doc, r, w)
		}
	}
	// The listed tokens never carry a value.
	_, w = call(s, "GET", base+"/tokens", "admin", nil)
	if strings.Contains(w.Body.String(), created.Token) || strings.Contains(w.Body.String(), "install_command") {
		t.Fatalf("token list leaks: %s", w.Body)
	}
}
