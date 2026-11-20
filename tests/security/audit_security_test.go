package security

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

func window() string {
	now := time.Now().UTC()
	return "from=" + url.QueryEscape(now.Add(-24*time.Hour).Format(time.RFC3339)) + "&to=" + url.QueryEscape(now.Format(time.RFC3339))
}

// A viewer holds every read but audit:read: events, sessions and the module
// audit trail are 403; another tenant's cluster is 404 (SR-001).
func TestAuditRoutesRefuseWithoutAuditRead(t *testing.T) {
	f := newFixture(t)
	base := "/clusters/" + f.cluster(t, "admin-a")
	for _, path := range []string{base + "/events?" + window(), base + "/sessions?" + window(), "/audit"} {
		if code, m := f.do(t, "GET", path, "viewer-a", nil); code != http.StatusForbidden || m["reason"] != "forbidden" {
			t.Errorf("viewer %s: %d %v", path, code, m)
		}
		if code, _ := f.do(t, "GET", path, "auditor-a", nil); code != http.StatusOK {
			t.Errorf("auditor %s: %d", path, code)
		}
		if code, _ := f.do(t, "GET", path, "operator-a", nil); code != http.StatusOK {
			t.Errorf("operator %s: %d", path, code)
		}
	}
	for _, path := range []string{base + "/events?" + window(), base + "/sessions?" + window()} {
		if code, _ := f.do(t, "GET", path, "admin-b", nil); code != http.StatusNotFound {
			t.Errorf("other tenant %s: %d", path, code)
		}
	}
	// The module audit trail never shows another tenant's rows.
	_, page := f.do(t, "GET", "/audit", "admin-b", nil)
	if items, _ := page["items"].([]any); len(items) != 0 {
		t.Fatalf("tenant B sees %d audit rows of tenant A", len(items))
	}
}

// Alert rules: a viewer and an operator read but cannot change them; another
// tenant's rule is 404 and a rule cannot point at another tenant's cluster.
func TestAlertRulesAreTenantScoped(t *testing.T) {
	f := newFixture(t)
	mine := f.cluster(t, "admin-a")
	body := map[string]any{"name": "failed logins", "condition_kind": "teleport_event", "event_types": []string{"user.login.failure"},
		"recipients": map[string]any{"user_ids": []string{"u-sec"}}, "cluster_id": mine}
	code, rule := f.do(t, "POST", "/alert-rules", "admin-a", body)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, rule)
	}
	id := rule["id"].(string)
	for _, token := range []string{"viewer-a", "operator-a", "auditor-a"} {
		if code, _ := f.do(t, "GET", "/alert-rules", token, nil); code != http.StatusOK {
			t.Errorf("%s list: %d", token, code)
		}
		for _, r := range []route{{"POST", "/alert-rules", body}, {"PUT", "/alert-rules/" + id, body}, {"DELETE", "/alert-rules/" + id, nil}} {
			if code, _ := f.do(t, r.method, r.path, token, r.body); code != http.StatusForbidden {
				t.Errorf("%s %s %s: %d", token, r.method, r.path, code)
			}
		}
	}
	if _, list := f.do(t, "GET", "/alert-rules", "admin-b", nil); len(list["items"].([]any)) != 0 {
		t.Fatal("tenant B lists tenant A's rules")
	}
	if code, _ := f.do(t, "PUT", "/alert-rules/"+id, "admin-b", body); code != http.StatusNotFound {
		t.Errorf("tenant B update: %d", code)
	}
	if code, _ := f.do(t, "DELETE", "/alert-rules/"+id, "admin-b", nil); code != http.StatusNotFound {
		t.Errorf("tenant B delete: %d", code)
	}
	// Tenant B cannot scope a rule to tenant A's cluster.
	if code, m := f.do(t, "POST", "/alert-rules", "admin-b", body); code != http.StatusUnprocessableEntity || m["reason"] != "validation_failed" {
		t.Errorf("foreign cluster scope: %d %v", code, m)
	}
}

// SR-004: Teleport-supplied strings come back as JSON data: never as
// markup, with control characters stripped and lengths bounded.
func TestTeleportTextIsDataNotMarkup(t *testing.T) {
	f := newFixture(t)
	base := "/clusters/" + f.cluster(t, "admin-a")
	evil := `<img src=x onerror=alert(1)><script>alert("x")</script>`
	raw, _ := json.Marshal(map[string]any{"user": evil + "\x1b[31m\n", "server_hostname": evil, "sid": "<b>", "participants": []string{evil}})
	at := time.Now().UTC().Add(-time.Hour)
	f.Teleport.AuditEvents = []teleportapi.AuditEvent{{ID: "e1", Type: "session.start", Code: "T2000I", Time: at, Raw: raw}}
	f.Teleport.SessionEvents = []teleportapi.AuditEvent{{ID: "s1", Type: "session.end", Code: "T2004I", Time: at, Raw: raw}}
	for _, path := range []string{base + "/events?" + window(), base + "/sessions?" + window()} {
		code, m := f.do(t, "GET", path, "auditor-a", nil)
		body := f.responses[len(f.responses)-1]
		if code != http.StatusOK {
			t.Fatalf("%s: %d", path, code)
		}
		if strings.ContainsAny(body, "<>") || strings.Contains(body, "\x1b") {
			t.Fatalf("%s returns raw markup or control characters: %s", path, body)
		}
		items := m["items"].([]any)
		if len(items) != 1 {
			t.Fatalf("%s: %v", path, m)
		}
		it := items[0].(map[string]any)
		// The value survives as text: the UI shows it, it does not run it.
		if !strings.Contains(it["user"].(string), "<script>") {
			t.Fatalf("%s: user %q", path, it["user"])
		}
		if _, ok := it["playback_url"]; ok {
			t.Fatalf("%s: a playback link for an unsafe session id", path)
		}
	}
}
