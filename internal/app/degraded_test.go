package app

// T119 (unit level; tests/integration/degraded_test.go runs the same
// scenario against a real Teleport): quickstart scenario 8 with fakes. With
// notification failing, the scheduler unreachable (task registration on,
// nobody answering) and the production wiring of the membership source and
// the inventory/asset host lookup (both unavailable), cluster management
// keeps working, the affected features answer dependency_unavailable, and
// the leased health monitor keeps moving the cluster's status.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	sdktask "github.com/go-tangra/go-tangra-scheduler/sdk/v4/pkg/taskexec"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/resources"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi/identitytest"
)

func TestDegradedModeWithFakes(t *testing.T) {
	fake := teleportapi.NewFake()
	fake.Info = teleportapi.Info{ClusterName: "prod.example.com", ServerVersion: "19.0.0", Edition: teleportapi.EditionCommunity}
	fake.Users = []teleportapi.User{{Name: "alice", Roles: []string{"access"}, Revision: "u1"}}
	fake.Roles = []teleportapi.Role{{Name: "access", Preset: true, Revision: "r1"}}
	fake.Resources = []teleportapi.Resource{{Kind: teleportapi.KindNode, Name: "web1", Hostname: "web1.example"}}
	o := options(secrets.NewFake(), nil)
	o.Checker = authz.Static{"u1": authz.Permissions}
	down := notify.NewFake()
	down.SetErr(notify.ErrUnavailable) // notification stopped
	o.Notify = down
	o.dialer = func(_ context.Context, p teleportapi.DialParams) (teleportapi.Client, error) {
		return teleportapi.Limit(fake, p.Limits), nil
	}
	o.Dial = func(context.Context, teleportapi.Key) (teleportapi.Client, error) {
		return teleportapi.Limit(fake, teleportapi.Limits{}), nil
	}
	cfg := testConfig()
	cfg.TaskScheduler.Enabled = true // the scheduler is registered with, but stopped
	cfg.Discovery.Static["scheduler"] = []string{"127.0.0.1:1"}
	a, err := Build(context.Background(), cfg, o)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	do := func(method, path string, body any) *httptest.ResponseRecorder {
		var rd *strings.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rd = strings.NewReader(string(raw))
		} else {
			rd = strings.NewReader("")
		}
		r := httptest.NewRequest(method, "https://localhost/api/teleport/v1"+path, rd)
		r.Header.Set("Authorization", "Bearer viewer")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", "csrf")
		w := httptest.NewRecorder()
		a.HTTP.Handler().ServeHTTP(w, r)
		return w
	}
	reason := func(w *httptest.ResponseRecorder) string {
		var e struct {
			Reason string         `json:"reason"`
			Detail map[string]any `json:"detail"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &e)
		dep, _ := e.Detail["dependency"].(string)
		return e.Reason + "/" + dep
	}

	// Cluster management works.
	w := do("POST", "/clusters", map[string]string{"display_name": "prod", "proxy_addr": "93.184.216.34",
		"credential": identitytest.New(t, identitytest.Options{Cluster: "prod.example.com"})})
	if w.Code != 201 {
		t.Fatalf("register: %d %s", w.Code, w.Body)
	}
	var v clusters.View
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	if w := do("GET", "/clusters/"+v.ID+"/users", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "alice") {
		t.Fatalf("users: %d %s", w.Code, w.Body)
	}
	if w := do("POST", "/clusters/"+v.ID+"/mappings", map[string]any{"subject_kind": "module_role", "subject_ref": "operator",
		"teleport_roles": []string{"access"}, "logins": []string{"ubuntu"}}); w.Code != 201 {
		t.Fatalf("mapping: %d %s", w.Code, w.Body)
	}
	// The affected features report dependency_unavailable.
	if w := do("POST", "/clusters/"+v.ID+"/provisioning/sync", nil); w.Code != 503 || reason(w) != "dependency_unavailable/auth" {
		t.Fatalf("sync: %d %s", w.Code, w.Body)
	}
	if w := do("GET", "/clusters/"+v.ID+"/resources", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"link_status":"`+resources.LinkStatusUnavailable+`"`) {
		t.Fatalf("resources: %d %s", w.Code, w.Body)
	}
	if resources.LinkStatusUnavailable != "dependency_unavailable" {
		t.Fatalf("link status %q", resources.LinkStatusUnavailable)
	}
	// The sync task, run directly, fails retryably (membership unavailable).
	res := a.Tasks.SyncProvisioning(context.Background(), schedulerRequest("teleport:sync-provisioning"))
	if res.Success || res.Permanent {
		t.Fatalf("sync task: %+v", res)
	}

	// The leased monitor keeps updating status without the scheduler and
	// with notification down: three failed checks mark it unreachable.
	fake.SetErr(errors.New("dial tcp: connection refused"))
	m := &clusters.Monitor{Service: a.Clusters}
	for range 3 {
		m.RunOnce(context.Background())
	}
	c, err := a.Repo.GetCluster(context.Background(), appTenant, v.ID)
	if err != nil || c.Status != repo.StatusUnreachable {
		t.Fatalf("status %v %s", err, c.Status)
	}
	if len(down.Sent()) != 0 {
		t.Fatal("a notification was delivered while notification was down")
	}
	fake.SetErr(nil)
	m.RunOnce(context.Background())
	if c, _ := a.Repo.GetCluster(context.Background(), appTenant, v.ID); c.Status != repo.StatusConnected {
		t.Fatalf("recovery %s", c.Status)
	}
	// The registrar keeps retrying in the background and blocks nothing.
	names := map[string]bool{}
	for _, w := range a.Workers() {
		names[w.Name] = true
	}
	for _, n := range []string{"health-monitor", "resource-watcher", "offline-sweep", "alert-poller", "scheduler-registrar"} {
		if !names[n] {
			t.Errorf("worker %s missing", n)
		}
	}
}

func schedulerRequest(typ string) sdktask.Request {
	return sdktask.Request{ExecutionID: "x", Type: typ, TenantID: appTenant, Payload: []byte(`{}`)}
}
