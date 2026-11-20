package security

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/trace"

	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
)

const roleYAML = "kind: role\nversion: v7\nmetadata: {name: dev}\nspec: {allow: {logins: [dev]}}\n"

type route struct {
	method, path string
	body         any
}

// identityWrites are the US2 write routes on cluster base.
func identityWrites(base string) []route {
	return []route{
		{"POST", base + "/users", map[string]any{"name": "eve", "roles": []string{"access"}}},
		{"PUT", base + "/users/alice", map[string]any{"roles": []string{"editor"}, "revision": "u2"}},
		{"POST", base + "/users/alice/reset", nil},
		{"DELETE", base + "/users/alice", nil},
		{"POST", base + "/roles:preview", map[string]any{"yaml": roleYAML}},
		{"PUT", base + "/roles/dev", map[string]any{"yaml": roleYAML}},
		{"DELETE", base + "/roles/access", nil},
		{"POST", base + "/locks", map[string]any{"target_kind": "user", "target": "alice", "reason": "incident"}},
		{"DELETE", base + "/locks/l1", nil},
	}
}

func identityReads(base string) []route {
	return []route{{"GET", base + "/users", nil}, {"GET", base + "/roles", nil}, {"GET", base + "/roles/access", nil}, {"GET", base + "/locks", nil}}
}

func (f *fixture) cluster(t *testing.T, token string) string {
	t.Helper()
	code, c := f.register(t, token, "prod", ct.ProxyAddr, f.Identity(t, 30*24*time.Hour))
	if code != http.StatusCreated {
		t.Fatalf("register: %d %v", code, c)
	}
	return c["id"].(string)
}

// SR-005: an operator may lock and unlock but never change roles.
func TestOperatorCannotManageRoles(t *testing.T) {
	f := newFixture(t)
	base := "/clusters/" + f.cluster(t, "admin-a")
	for _, c := range []route{
		{"POST", base + "/roles:preview", map[string]any{"yaml": roleYAML}},
		{"PUT", base + "/roles/dev", map[string]any{"yaml": roleYAML}},
		{"PUT", base + "/roles/access", map[string]any{"yaml": roleYAML, "revision": "r1"}},
		{"DELETE", base + "/roles/access", nil},
		{"POST", base + "/users", map[string]any{"name": "eve", "roles": []string{"access"}}},
	} {
		if code, m := f.do(t, c.method, c.path, "operator-a", c.body); code != http.StatusForbidden || m["reason"] != "forbidden" {
			t.Errorf("operator %s %s: %d %v", c.method, c.path, code, m)
		}
	}
	code, l := f.do(t, "POST", base+"/locks", "operator-a", map[string]any{"target_kind": "user", "target": "alice", "reason": "incident"})
	if code != http.StatusCreated {
		t.Fatalf("operator lock: %d %v", code, l)
	}
	if code, _ := f.do(t, "DELETE", base+"/locks/"+l["name"].(string), "operator-a", nil); code != http.StatusNoContent {
		t.Fatalf("operator unlock: %d", code)
	}
	if f.Teleport.Calls("CreateRole")+f.Teleport.Calls("UpdateRole")+f.Teleport.Calls("DeleteRole") != 0 {
		t.Fatal("an operator reached a role write")
	}
}

// Quickstart 2e: a viewer reads users, roles and locks but every write is 403.
func TestViewerCannotChangeIdentity(t *testing.T) {
	f := newFixture(t)
	base := "/clusters/" + f.cluster(t, "admin-a")
	for _, c := range identityWrites(base) {
		if code, m := f.do(t, c.method, c.path, "viewer-a", c.body); code != http.StatusForbidden || m["reason"] != "forbidden" {
			t.Errorf("viewer %s %s: %d %v", c.method, c.path, code, m)
		}
	}
	for _, c := range identityReads(base) {
		if code, m := f.do(t, c.method, c.path, "viewer-a", nil); code != http.StatusOK {
			t.Errorf("viewer %s %s: %d %v", c.method, c.path, code, m)
		}
	}
	for _, m := range []string{"CreateUser", "UpdateUser", "DeleteUser", "CreateUserToken", "UpsertLock", "DeleteLock"} {
		if f.Teleport.Calls(m) != 0 {
			t.Errorf("a viewer reached %s", m)
		}
	}
}

// Quickstart 9: another tenant's cluster answers 404 on every US2 route.
func TestCrossTenantIdentityIsNotFound(t *testing.T) {
	f := newFixture(t)
	base := "/clusters/" + f.cluster(t, "admin-b")
	before := len(f.Teleport.Users)
	for _, c := range append(identityReads(base), identityWrites(base)...) {
		if code, m := f.do(t, c.method, c.path, "admin-a", c.body); code != http.StatusNotFound || m["reason"] != "not_found" {
			t.Errorf("tenant A %s %s: %d %v", c.method, c.path, code, m)
		}
	}
	if len(f.Teleport.Users) != before || len(f.Teleport.Locks) != 0 || len(f.Teleport.IssuedURLs()) != 0 {
		t.Fatalf("tenant B's cluster changed: users %d locks %d", len(f.Teleport.Users), len(f.Teleport.Locks))
	}
}

// SR-002: invite and reset URLs appear only in the one response that issued
// them — never in another response, a log line (including 5xx diagnostics),
// an event or an audit row — across successes and failures.
func TestNoInviteOrResetURLInAnyOutput(t *testing.T) {
	f := newFixture(t)
	base := "/clusters/" + f.cluster(t, "admin-a")
	var issuing []string // responses that carry a URL by contract
	keep := func() {
		issuing = append(issuing, f.responses[len(f.responses)-1])
		f.responses = f.responses[:len(f.responses)-1]
	}

	if code, _ := f.do(t, "POST", base+"/users", "admin-a", map[string]any{"name": "carol", "roles": []string{"access"}}); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	keep()
	if code, _ := f.do(t, "POST", base+"/users/carol/reset", "admin-a", nil); code != http.StatusOK {
		t.Fatalf("reset: %d", code)
	}
	keep()
	// Failures around the links: rollback, stale update, guards, an outage (5xx, logged).
	f.Teleport.FailNext("CreateUserToken", trace.AccessDenied("denied"))
	f.do(t, "POST", base+"/users", "admin-a", map[string]any{"name": "dave", "roles": []string{"access"}})
	f.do(t, "PUT", base+"/users/carol", "admin-a", map[string]any{"roles": []string{"editor"}, "revision": "stale"})
	f.do(t, "POST", base+"/users/"+ct.Management+"/reset", "admin-a", nil)
	f.do(t, "POST", base+"/locks", "admin-a", map[string]any{"target_kind": "user", "target": "carol", "reason": "incident"})
	f.Teleport.SetErr(trace.ConnectionProblem(errors.New("dial"), "connection refused"))
	f.do(t, "POST", base+"/users/carol/reset", "admin-a", nil)
	f.do(t, "GET", base+"/users", "viewer-a", nil)
	f.Teleport.SetErr(nil)
	f.do(t, "GET", base+"/users", "viewer-a", nil)
	f.do(t, "DELETE", base+"/users/carol", "admin-a", nil)

	urls := f.Teleport.IssuedURLs()
	if len(urls) != 2 {
		t.Fatalf("issued %d URLs", len(urls))
	}
	for i, u := range urls {
		if !strings.Contains(issuing[i], u) {
			t.Fatalf("issuing response %d lacks its URL", i)
		}
	}
	if !strings.Contains(f.logs.String(), "request failed") {
		t.Fatal("the 5xx path was not exercised")
	}
	f.Audit.Flush(context.Background())
	channels := map[string]string{"responses": strings.Join(f.responses, "\n"), "logs": f.logs.String()}
	b, _ := json.Marshal(f.Events.All())
	channels["events"] = string(b)
	b, _ = json.Marshal(f.Repo.Audit())
	channels["audit"] = string(b)
	b, _ = json.Marshal(f.Notify.Sent())
	channels["notifications"] = string(b)
	for name, out := range channels {
		for _, u := range urls {
			if strings.Contains(out, u) || strings.Contains(out, u[strings.LastIndex(u, "/")+1:]) {
				t.Errorf("%s carry a one-time URL", name)
			}
		}
	}
	if !strings.Contains(channels["audit"], "teleport.user.reset") || !strings.Contains(channels["audit"], "teleport.user.create") {
		t.Fatal("the link operations were not audited")
	}
}
