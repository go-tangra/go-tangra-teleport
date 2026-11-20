package security

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gravitational/trace"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// SR-001/SR-002 (US3): a join token, its install command and its config
// snippet appear only in the 201 response that issues them, never in a
// list, log, event, audit row or notification; only its hash is stored.
func TestNoJoinTokenInAnyOutput(t *testing.T) {
	f := newFixture(t)
	base := "/clusters/" + f.cluster(t, "admin-a")
	var issuing []string
	for _, kind := range []string{"node", "app", "db", "kube", "desktop"} {
		if code, _ := f.do(t, "POST", base+"/tokens", "admin-a", map[string]any{"resource_type": kind}); code != http.StatusCreated {
			t.Fatalf("create %s: %d", kind, code)
		}
		issuing = append(issuing, f.responses[len(f.responses)-1])
		f.responses = f.responses[:len(f.responses)-1]
	}
	// Failures: Teleport refuses, Teleport is down, a viewer, a revoke.
	f.Teleport.FailNext("CreateJoinToken", trace.AccessDenied("denied"))
	f.do(t, "POST", base+"/tokens", "admin-a", map[string]any{"resource_type": "node"})
	f.Teleport.SetErr(trace.ConnectionProblem(errors.New("dial"), "connection refused"))
	f.do(t, "POST", base+"/tokens", "admin-a", map[string]any{"resource_type": "node"})
	f.Teleport.SetErr(nil)
	f.do(t, "POST", base+"/tokens", "viewer-a", map[string]any{"resource_type": "node"})
	_, list := f.do(t, "GET", base+"/tokens", "admin-a", nil)
	items, _ := list["items"].([]any)
	if len(items) != 5 {
		t.Fatalf("%d tokens listed", len(items))
	}
	f.do(t, "DELETE", base+"/tokens/"+items[0].(map[string]any)["id"].(string), "admin-a", nil)
	f.do(t, "GET", base+"/tokens", "admin-a", nil)

	issued := f.Teleport.IssuedTokens()
	if len(issued) != 5 {
		t.Fatalf("issued %d tokens", len(issued))
	}
	for i, tok := range issued {
		if !strings.Contains(issuing[i], tok) {
			t.Fatalf("issuing response %d lacks its token", i)
		}
	}
	rows, _ := f.Repo.ListJoinTokens(context.Background(), "", "")
	f.Audit.Flush(context.Background())
	channels := map[string]string{"responses": strings.Join(f.responses, "\n"), "logs": f.logs.String()}
	for name, v := range map[string]any{"events": f.Events.All(), "audit": f.Repo.Audit(), "notifications": f.Notify.Sent(), "store": rows} {
		b, _ := json.Marshal(v)
		channels[name] = string(b)
	}
	for name, out := range channels {
		for _, tok := range issued {
			if strings.Contains(out, tok) {
				t.Errorf("%s carry a join token", name)
			}
		}
		if strings.Contains(out, "install-node.sh") || strings.Contains(out, "join_params") {
			t.Errorf("%s carry an install command or config snippet", name)
		}
	}
	if !strings.Contains(channels["audit"], "teleport.token.create") || !strings.Contains(channels["audit"], "teleport.token.revoke") {
		t.Fatal("token operations were not audited")
	}
}

// Tokens and links need their permissions; another tenant's cluster is 404.
func TestResourceRoutesRefuseWithoutPermission(t *testing.T) {
	f := newFixture(t)
	base := "/clusters/" + f.cluster(t, "admin-a")
	f.Teleport.Resources = []teleportapi.Resource{{Kind: teleportapi.KindNode, Name: "n1", Hostname: "web-1"}}
	_, page := f.do(t, "GET", base+"/resources", "viewer-a", nil)
	items, _ := page["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("resources %v", page)
	}
	rid := items[0].(map[string]any)["id"].(string)
	for _, r := range []route{
		{"GET", base + "/tokens", nil},
		{"POST", base + "/tokens", map[string]any{"resource_type": "node"}},
		{"POST", base + "/resources/" + rid + "/links", map[string]any{"target_module": "asset", "target_id": "a"}},
	} {
		if code, _ := f.do(t, r.method, r.path, "viewer-a", r.body); code != http.StatusForbidden {
			t.Errorf("viewer %s %s: %d", r.method, r.path, code)
		}
		if code, _ := f.do(t, r.method, r.path, "admin-b", r.body); code != http.StatusNotFound {
			t.Errorf("other tenant %s %s: %d", r.method, r.path, code)
		}
	}
	if code, _ := f.do(t, "GET", base+"/resources", "admin-b", nil); code != http.StatusNotFound {
		t.Errorf("other tenant lists resources: %d", code)
	}
	// An operator links and issues tokens (SR-005).
	if code, _ := f.do(t, "POST", base+"/resources/"+rid+"/links", "operator-a", map[string]any{"target_module": "asset", "target_id": "a"}); code != http.StatusCreated {
		t.Errorf("operator link: %d", code)
	}
	if code, _ := f.do(t, "POST", base+"/tokens", "operator-a", map[string]any{"resource_type": "node"}); code != http.StatusCreated {
		t.Errorf("operator token: %d", code)
	}
}
