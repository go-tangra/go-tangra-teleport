package contract

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi/identitytest"
)

// accessIdentityRoutes are the spec 005 routes (plan.md Contract).
var accessIdentityRoutes = map[string]string{
	"GET /api/teleport/v1/clusters/{id}/access-identity":    authz.ClustersRead,
	"PUT /api/teleport/v1/clusters/{id}/access-identity":    authz.ClustersManage,
	"DELETE /api/teleport/v1/clusters/{id}/access-identity": authz.ClustersManage,
}

func accessIdentityRouteList() []string {
	out := make([]string, 0, len(accessIdentityRoutes))
	for r := range accessIdentityRoutes {
		out = append(out, r)
	}
	return out
}

// Spec 005: status, upload refusals, upload, brokered access through it,
// expiry and removal, every JSON answer validated against the document.
func TestAccessIdentityRoutes(t *testing.T) {
	doc := load(t)
	s, e, id := accessServer(t)
	base := "/api/teleport/v1/clusters/" + id + "/access-identity"
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
	for route, perm := range accessIdentityRoutes {
		method, path, _ := strings.Cut(route, " ")
		if got := s.Permission(method, path); got != perm {
			t.Errorf("%s: permission %q, want %q", route, got, perm)
		}
		if !implemented[route] {
			t.Errorf("%s has no handler", route)
		}
	}
	state := func() string {
		t.Helper()
		var v struct {
			State string `json:"state"`
		}
		_ = json.Unmarshal(do("GET", base, "viewer", nil, 200, "").Body.Bytes(), &v)
		return v.State
	}
	if state() != "missing" {
		t.Fatal("configured before upload")
	}
	do("GET", base, "outsider", nil, 403, "forbidden") // no clusters:read in tenant B
	body := func(raw string) map[string]any { return map[string]any{"credential": raw} }
	good := e.AccessIdentity(t, 30*24*time.Hour, "")
	do("PUT", base, "viewer", body(good), 403, "forbidden")
	do("PUT", base, "alice", body(good), 403, "forbidden")
	do("PUT", base, "admin", body(e.AccessIdentity(t, 30*24*time.Hour, "x.prod.example.com")), 422, "access_identity_not_sign_in")
	do("PUT", base, "admin", body(identitytest.New(t, identitytest.Options{Cluster: "other.example.com", User: "tangra-access"})), 422, "validation_failed")
	do("PUT", base, "admin", body("not an identity"), 422, "credential_invalid")
	do("PUT", base, "admin", map[string]any{"credential": good, "extra": 1}, 422, "validation_failed")
	e.Teleport.AccessImpersonationDenied = true
	do("PUT", base, "admin", body(good), 422, "access_identity_cannot_impersonate")
	e.Teleport.AccessImpersonationDenied = false
	rec := do("PUT", base, "admin", body(good), 200, "")
	if strings.Contains(rec.Body.String(), "teleport-access-") || strings.Contains(rec.Body.String(), "PRIVATE KEY") ||
		!strings.Contains(rec.Body.String(), `"impersonation_checked":true`) {
		t.Fatalf("upload answer %s", rec.Body)
	}
	if state() != "ok" {
		t.Fatal("not configured after upload")
	}

	// Brokered access issues with it; the management role cannot.
	e.Teleport.ImpersonationDenied = true
	acc := "/api/teleport/v1/clusters/" + id + "/access"
	do("POST", acc+"/identity", "alice", nil, 200, "")
	if !strings.Contains(do("GET", acc, "alice", nil, 200, "").Body.String(), `"access_identity":"ok"`) {
		t.Fatal("GET access does not show the access identity")
	}
	e.Teleport.AccessImpersonationDenied = true
	do("POST", acc+"/identity", "alice", nil, 422, "access_identity_invalid")
	e.Teleport.AccessImpersonationDenied = false

	// Expired.
	e.Advance(31 * 24 * time.Hour)
	do("POST", acc+"/identity", "alice", nil, 422, "access_identity_expired")
	if state() != "expired" {
		t.Fatal("not expired")
	}

	do("DELETE", base, "viewer", nil, 403, "forbidden")
	do("DELETE", base, "admin", nil, 204, "")
	do("DELETE", base, "admin", nil, 404, "not_found")
	do("POST", acc+"/identity", "alice", nil, 422, "access_identity_missing")
}
