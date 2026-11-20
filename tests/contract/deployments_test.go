package contract

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/deploy"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/httpapi"
)

// deploymentRoutes are the US6 routes of contracts/http-api.md (Deployment
// wizard) with their permissions.
var deploymentRoutes = map[string]string{
	"GET /api/teleport/v1/deployments":                       authz.DeploymentsManage,
	"POST /api/teleport/v1/deployments":                      authz.DeploymentsManage,
	"GET /api/teleport/v1/deployments/{id}":                  authz.DeploymentsManage,
	"PUT /api/teleport/v1/deployments/{id}":                  authz.DeploymentsManage,
	"DELETE /api/teleport/v1/deployments/{id}":               authz.DeploymentsManage,
	"GET /api/teleport/v1/deployments/{id}/artifacts/{name}": authz.DeploymentsManage,
	"POST /api/teleport/v1/deployments/{id}/checks":          authz.DeploymentsManage,
}

func deploymentRouteList() []string {
	out := make([]string, 0, len(deploymentRoutes))
	for r := range deploymentRoutes {
		out = append(out, r)
	}
	return out
}

func deploymentServer(t *testing.T) (*httpapi.Server, *ct.Env) {
	t.Helper()
	e := ct.New(t, nil)
	rt := testrt.New(t, testutil.MustCA("example.org"), "teleport")
	v := tokens{"admin": {UserID: ct.Admin, TenantID: ct.TenantA}, "operator": {UserID: ct.Operator, TenantID: ct.TenantA},
		"admin-b": {UserID: ct.Admin, TenantID: ct.TenantB}}
	s, err := httpapi.NewHandler(rt, httpapi.WithVerifier(v), httpapi.WithChecker(e.Perms))
	if err != nil {
		t.Fatal(err)
	}
	s.Register(httpapi.Deps{Clusters: e.Service, Deployments: &deploy.Service{Repo: e.Repo, Authz: e.Service.Authz,
		Prober: &deploy.Prober{Guard: e.Service.Guard, Now: e.Now}, Audit: e.Audit, Now: e.Now}})
	return s, e
}

func TestDeploymentRoutesDeclareTheirPermissions(t *testing.T) {
	s, _ := deploymentServer(t)
	implemented := map[string]bool{}
	for _, r := range s.Implemented() {
		implemented[r.String()] = true
	}
	for route, perm := range deploymentRoutes {
		method, path, _ := strings.Cut(route, " ")
		if got := s.Permission(method, path); got != perm {
			t.Errorf("%s: permission %q, want %q", route, got, perm)
		}
		if !implemented[route] {
			t.Errorf("%s has no handler", route)
		}
	}
}

// Every US6 route answers in the declared shape (quickstart scenario 6).
func TestDeploymentResponsesMatchSchemas(t *testing.T) {
	doc := load(t)
	s, e := deploymentServer(t)
	body := map[string]any{"domain": "tp.example.test", "cert_mode": "acme", "acme_email": "ops@example.test",
		"teleport_version": "19.1.2", "admin_username": "admin", "admin_logins": []string{"root"}}
	_, cr := call(s, "POST", "/api/teleport/v1/deployments", "admin", body)
	if cr.Code != 201 {
		t.Fatalf("create: %d %s", cr.Code, cr.Body)
	}
	var d struct {
		ID        string `json:"id"`
		ProxyAddr string `json:"proxy_addr"`
	}
	_ = json.Unmarshal(cr.Body.Bytes(), &d)
	if d.ProxyAddr != "tp.example.test:443" {
		t.Fatalf("proxy_addr %q", d.ProxyAddr)
	}
	base := "/api/teleport/v1/deployments/" + d.ID
	c := e.Register(t, ct.TenantA, "new")
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range body {
			m[kk] = vv
		}
		m[k] = v
		return m
	}
	type tc struct {
		method, path, token string
		body                any
		status              int
		reason              string
	}
	for _, x := range []tc{
		{"GET", "/api/teleport/v1/deployments", "admin", nil, 200, ""},
		{"GET", "/api/teleport/v1/deployments", "operator", nil, 403, "forbidden"},
		{"GET", base, "admin", nil, 200, ""},
		{"GET", base, "admin-b", nil, 404, "not_found"},
		{"POST", "/api/teleport/v1/deployments", "admin", with("domain", "x$(id).example.test"), 422, "validation_failed"},
		{"POST", "/api/teleport/v1/deployments", "admin", with("teleport_version", "latest"), 422, "validation_failed"},
		{"POST", "/api/teleport/v1/deployments", "admin", with("admin_logins", []string{"root;id"}), 422, "validation_failed"},
		{"POST", "/api/teleport/v1/deployments", "operator", body, 403, "forbidden"},
		{"PUT", base, "admin", with("cert_mode", "own_cert"), 422, "validation_failed"}, // own_cert takes no e-mail
		{"PUT", base, "admin", with("registered_cluster_id", c.ID), 200, ""},
		{"PUT", base, "admin", with("registered_cluster_id", "018f3a2b-0000-7000-8000-0000000000ff"), 422, "validation_failed"},
		{"GET", base + "/artifacts/teleport.yaml", "admin", nil, 200, ""},
		{"GET", base + "/artifacts/install.sh", "admin", nil, 200, ""},
		{"GET", base + "/artifacts/passwd", "admin", nil, 422, "validation_failed"},
		{"GET", base + "/artifacts/install.sh", "operator", nil, 403, "forbidden"},
		{"POST", base + "/checks", "admin", nil, 200, ""},
		{"POST", base + "/checks", "admin", nil, 429, "rate_limited"},
		{"POST", base + "/checks", "operator", nil, 403, "forbidden"},
		{"DELETE", base, "operator", nil, 403, "forbidden"},
		{"DELETE", base, "admin", nil, 204, ""},
		{"DELETE", base, "admin", nil, 404, "not_found"},
	} {
		r, rec := call(s, x.method, x.path, x.token, x.body)
		if rec.Code != x.status {
			t.Fatalf("%s %s: %d %s", x.method, x.path, rec.Code, rec.Body)
		}
		var m struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		if x.reason != "" && m.Reason != x.reason {
			t.Fatalf("%s %s: reason %q, want %s (%s)", x.method, x.path, m.Reason, x.reason, rec.Body)
		}
		if rec.Code != 204 {
			ValidateResponse(t, doc, r, rec)
		}
		if strings.Contains(x.path, "/artifacts/") && rec.Code == 200 {
			name := x.path[strings.LastIndex(x.path, "/")+1:]
			if rec.Header().Get("Content-Disposition") != `attachment; filename="`+name+`"` ||
				!strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("artifact headers %v", rec.Header())
			}
		}
	}
}
