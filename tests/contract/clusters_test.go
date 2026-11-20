package contract

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
)

// clusterRoutes are the US1 routes of contracts/http-api.md (Clusters) with
// their permissions.
var clusterRoutes = map[string]string{
	"GET /api/teleport/v1/clusters":                  authz.ClustersRead,
	"POST /api/teleport/v1/clusters":                 authz.ClustersManage,
	"GET /api/teleport/v1/clusters/{id}":             authz.ClustersRead,
	"PATCH /api/teleport/v1/clusters/{id}":           authz.ClustersManage,
	"DELETE /api/teleport/v1/clusters/{id}":          authz.ClustersManage,
	"POST /api/teleport/v1/clusters/{id}/credential": authz.ClustersManage,
	"POST /api/teleport/v1/clusters/{id}/check":      authz.ClustersRead,
}

func clusterRouteList() []string {
	out := make([]string, 0, len(clusterRoutes))
	for r := range clusterRoutes {
		out = append(out, r)
	}
	return out
}

type tokens map[string]authclient.Identity

func (v tokens) Verify(_ context.Context, token string) (authclient.Identity, error) {
	if id, ok := v[token]; ok {
		return id, nil
	}
	return authclient.Identity{}, httpapi.ErrUnauthenticated
}

// clusterServer mounts the cluster routes over the US1 harness.
func clusterServer(t *testing.T) (*httpapi.Server, *ct.Env) {
	t.Helper()
	e := ct.New(t, nil)
	rt := testrt.New(t, testutil.MustCA("example.org"), "teleport")
	v := tokens{"admin": {UserID: ct.Admin, TenantID: ct.TenantA}, "viewer": {UserID: ct.Viewer, TenantID: ct.TenantA}}
	s, err := httpapi.NewHandler(rt, httpapi.WithVerifier(v), httpapi.WithChecker(e.Perms))
	if err != nil {
		t.Fatal(err)
	}
	s.Register(httpapi.Deps{Clusters: e.Service})
	return s, e
}

func call(s *httpapi.Server, method, path, token string, body any) (*http.Request, *httptest.ResponseRecorder) {
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, "https://localhost"+path, strings.NewReader(string(b)))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, "https://localhost"+path, nil)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	if method != http.MethodGet {
		r.Header.Set("X-CSRF-Token", "csrf")
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return r, w
}

func TestClusterRoutesDeclareTheirPermissions(t *testing.T) {
	s, _ := clusterServer(t)
	for route, perm := range clusterRoutes {
		method, path, _ := strings.Cut(route, " ")
		if got := s.Permission(method, path); got != perm {
			t.Errorf("%s: permission %q, want %q", route, got, perm)
		}
	}
	implemented := map[string]bool{}
	for _, r := range s.Implemented() {
		implemented[r.String()] = true
	}
	for route := range clusterRoutes {
		if !implemented[route] {
			t.Errorf("%s has no handler", route)
		}
	}
}

// Every cluster route answers in the shape the document declares, for
// success and for the refusals the contract names.
func TestClusterResponsesMatchSchemas(t *testing.T) {
	doc := load(t)
	s, e := clusterServer(t)
	cred := e.Identity(t, 30*24*time.Hour)
	reg := map[string]any{"display_name": "prod", "proxy_addr": ct.ProxyAddr, "credential_kind": "identity_file", "credential": cred}

	r, w := call(s, "POST", "/api/teleport/v1/clusters", "admin", reg)
	if w.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", w.Code, w.Body)
	}
	ValidateResponse(t, doc, r, w)
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	base := "/api/teleport/v1/clusters/" + created.ID

	for _, c := range []struct {
		method, path, token string
		body                any
		status              int
		reason              string
	}{
		{"GET", "/api/teleport/v1/clusters", "viewer", nil, 200, ""},
		{"GET", "/api/teleport/v1/clusters?page=1&page_size=10&sort=status&order=desc", "viewer", nil, 200, ""},
		{"GET", base, "viewer", nil, 200, ""},
		{"PATCH", base, "admin", map[string]any{"display_name": "production", "settings": map[string]any{"alerts_enabled": false}}, 200, ""},
		{"POST", base + "/check", "viewer", nil, 200, ""},
		{"POST", base + "/credential", "admin", map[string]any{"credential": e.Identity(t, 60*24*time.Hour)}, 200, ""},
		// Refusals.
		{"POST", "/api/teleport/v1/clusters", "admin", map[string]any{"display_name": "production", "proxy_addr": ct.ProxyAddr, "credential": cred}, 409, "conflict"},
		{"POST", "/api/teleport/v1/clusters", "admin", map[string]any{"display_name": "x", "proxy_addr": "169.254.169.254:443", "credential": cred}, 422, "blocked_target"},
		{"POST", "/api/teleport/v1/clusters", "admin", map[string]any{"display_name": "x", "proxy_addr": ct.ProxyAddr, "credential": "nope"}, 422, "credential_invalid"},
		{"POST", "/api/teleport/v1/clusters", "admin", map[string]any{"display_name": "x", "proxy_addr": "https://a/b", "credential": cred}, 422, "validation_failed"},
		{"POST", "/api/teleport/v1/clusters", "admin", map[string]any{"display_name": "x", "proxy_addr": ct.ProxyAddr, "credential_kind": "bot", "credential": cred}, 422, "validation_failed"},
		{"POST", "/api/teleport/v1/clusters", "admin", map[string]any{"display_name": "x", "proxy_addr": ct.ProxyAddr, "credential": cred, "extra": 1}, 422, "validation_failed"},
		{"POST", "/api/teleport/v1/clusters", "viewer", reg, 403, "forbidden"},
		{"PATCH", base, "admin", map[string]any{}, 422, "validation_failed"},
		{"GET", "/api/teleport/v1/clusters/018f3a2b-0000-7000-8000-0000000000ff", "viewer", nil, 404, "not_found"},
		{"GET", "/api/teleport/v1/clusters/not-a-uuid", "viewer", nil, 422, "validation_failed"},
		{"DELETE", base, "viewer", nil, 403, "forbidden"},
		{"DELETE", base, "admin", nil, 204, ""},
		{"POST", base + "/check", "viewer", nil, 404, "not_found"},
	} {
		r, w := call(s, c.method, c.path, c.token, c.body)
		if w.Code != c.status {
			t.Fatalf("%s %s: %d %s", c.method, c.path, w.Code, w.Body)
		}
		if c.reason != "" {
			var m map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &m)
			if m["reason"] != c.reason {
				t.Fatalf("%s %s: reason %v, want %s", c.method, c.path, m["reason"], c.reason)
			}
		}
		if w.Code != http.StatusNoContent {
			ValidateResponse(t, doc, r, w)
		}
	}
}

// In production the secret store is warden, which cannot write yet: the
// registration fails clearly and nothing is stored anywhere.
func TestRegistrationWithoutWritableSecretStore(t *testing.T) {
	doc := load(t)
	s, e := clusterServer(t)
	e.Secrets.SetErr(secrets.ErrWriteUnsupported)
	r, w := call(s, "POST", "/api/teleport/v1/clusters", "admin",
		map[string]any{"display_name": "prod", "proxy_addr": ct.ProxyAddr, "credential": e.Identity(t, 30*24*time.Hour)})
	var m struct {
		Reason string         `json:"reason"`
		Detail map[string]any `json:"detail"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	if w.Code != http.StatusServiceUnavailable || m.Reason != "dependency_unavailable" || m.Detail["dependency"] != "secret_store" {
		t.Fatalf("register: %d %s", w.Code, w.Body)
	}
	ValidateResponse(t, doc, r, w)
	e.Secrets.SetErr(nil)
	if e.Secrets.Len() != 0 || len(e.Repo.Audit()) > 1 {
		t.Fatalf("stored something: secrets %d", e.Secrets.Len())
	}
	if _, w := call(s, "GET", "/api/teleport/v1/clusters", "admin", nil); strings.Contains(w.Body.String(), `"id"`) {
		t.Fatalf("a cluster was stored: %s", w.Body)
	}
}
