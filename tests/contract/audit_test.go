package contract

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/alerts"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/auditlog"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// auditRoutes are the US4 routes of contracts/http-api.md (Audit and
// alerts) with their permissions.
var auditRoutes = map[string]string{
	"GET /api/teleport/v1/clusters/{id}/events":   authz.AuditRead,
	"GET /api/teleport/v1/clusters/{id}/sessions": authz.AuditRead,
	"GET /api/teleport/v1/audit":                  authz.AuditRead,
	"GET /api/teleport/v1/alert-rules":            authz.AlertsRead,
	"POST /api/teleport/v1/alert-rules":           authz.AlertsManage,
	"PUT /api/teleport/v1/alert-rules/{id}":       authz.AlertsManage,
	"DELETE /api/teleport/v1/alert-rules/{id}":    authz.AlertsManage,
}

func auditRouteList() []string {
	out := make([]string, 0, len(auditRoutes))
	for r := range auditRoutes {
		out = append(out, r)
	}
	return out
}

func auditServer(t *testing.T) (*httpapi.Server, *ct.Env, string) {
	t.Helper()
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	rt := testrt.New(t, testutil.MustCA("example.org"), "teleport")
	v := tokens{"admin": {UserID: ct.Admin, TenantID: ct.TenantA}, "viewer": {UserID: ct.Viewer, TenantID: ct.TenantA},
		"auditor": {UserID: ct.Auditor, TenantID: ct.TenantA}}
	s, err := httpapi.NewHandler(rt, httpapi.WithVerifier(v), httpapi.WithChecker(e.Perms))
	if err != nil {
		t.Fatal(err)
	}
	s.Register(httpapi.Deps{Clusters: e.Service, Audit: &auditlog.Service{Clusters: e.Service},
		Alerts: &alerts.Rules{Repo: e.Repo, Authz: e.Service.Authz, Audit: e.Audit, Now: e.Now}})
	return s, e, c.ID
}

func TestAuditRoutesDeclareTheirPermissions(t *testing.T) {
	s, _, _ := auditServer(t)
	implemented := map[string]bool{}
	for _, r := range s.Implemented() {
		implemented[r.String()] = true
	}
	for route, perm := range auditRoutes {
		method, path, _ := strings.Cut(route, " ")
		if got := s.Permission(method, path); got != perm {
			t.Errorf("%s: permission %q, want %q", route, got, perm)
		}
		if !implemented[route] {
			t.Errorf("%s has no handler", route)
		}
	}
}

// The document's EventType enum is the module's allow-list.
func TestEventTypeEnumIsTheAllowList(t *testing.T) {
	doc := load(t)
	var got []string
	for _, v := range doc.Components.Schemas["EventType"].Value.Enum {
		got = append(got, v.(string))
	}
	if !slices.Equal(got, auditlog.EventTypes) {
		t.Fatalf("EventType enum %v\nallow-list %v", got, auditlog.EventTypes)
	}
}

func raw(t *testing.T, m map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Every US4 route answers in the declared shape (quickstart scenarios 4 and 4b).
func TestAuditResponsesMatchSchemas(t *testing.T) {
	doc := load(t)
	s, e, id := auditServer(t)
	now := time.Now().UTC().Truncate(time.Second)
	e.Teleport.AuditEvents = []teleportapi.AuditEvent{
		{ID: "e1", Type: "user.login", Code: "T1000W", Time: now.Add(-time.Hour), Raw: raw(t, map[string]any{"user": "mallory", "success": false})},
		{ID: "e2", Type: "session.start", Code: "T2000I", Time: now.Add(-30 * time.Minute), Raw: raw(t, map[string]any{"user": "alice", "server_hostname": "web-1"})},
	}
	e.Teleport.SessionEvents = []teleportapi.AuditEvent{
		{ID: "s1", Type: "session.end", Code: "T2004I", Time: now.Add(-20 * time.Minute), Raw: raw(t, map[string]any{"user": "alice", "sid": "abc-1",
			"participants": []string{"alice"}, "server_hostname": "web-1", "session_start": now.Add(-25 * time.Minute).Format(time.RFC3339)})},
	}
	base := "/api/teleport/v1/clusters/" + id
	w := func(from, to time.Time) string {
		return "from=" + url.QueryEscape(from.Format(time.RFC3339)) + "&to=" + url.QueryEscape(to.Format(time.RFC3339))
	}
	day := w(now.Add(-24*time.Hour), now)
	_, cr := call(s, "POST", "/api/teleport/v1/alert-rules", "admin", map[string]any{"name": "failed logins", "condition_kind": "teleport_event",
		"event_types": []string{"user.login.failure"}, "threshold_count": 3, "window_minutes": 5, "cluster_id": id,
		"recipients": map[string]any{"user_ids": []string{ct.Admin}}})
	if cr.Code != 201 {
		t.Fatalf("create rule: %d %s", cr.Code, cr.Body)
	}
	var rule struct{ ID string }
	_ = json.Unmarshal(cr.Body.Bytes(), &rule)

	type tc struct {
		method, path, token string
		body                any
		status              int
		reason              string
	}
	for _, c := range []tc{
		{"GET", base + "/events?" + day, "auditor", nil, 200, ""},
		{"GET", base + "/events?" + day + "&types=user.login.failure&user=mallory&limit=10", "auditor", nil, 200, ""},
		{"GET", base + "/events?" + day + "&types=user.login&types=session.start&resource=web", "admin", nil, 200, ""},
		{"GET", base + "/events", "auditor", nil, 422, "validation_failed"},                                      // 4b: no window
		{"GET", base + "/events?" + w(now.Add(-60*24*time.Hour), now), "auditor", nil, 422, "validation_failed"}, // 4b: 60 days
		{"GET", base + "/events?" + day + "&limit=500", "auditor", nil, 422, "validation_failed"},
		{"GET", base + "/events?" + day + "&types=session.print", "auditor", nil, 422, "validation_failed"},
		{"GET", base + "/events?" + day, "viewer", nil, 403, "forbidden"},
		{"GET", "/api/teleport/v1/clusters/018f3a2b-0000-7000-8000-0000000000ff/events?" + day, "auditor", nil, 404, "not_found"},
		{"GET", base + "/sessions?" + day, "auditor", nil, 200, ""},
		{"GET", base + "/sessions?from=" + url.QueryEscape(now.Format(time.RFC3339)), "auditor", nil, 422, "validation_failed"},
		{"GET", base + "/sessions?" + day, "viewer", nil, 403, "forbidden"},
		{"GET", "/api/teleport/v1/audit", "auditor", nil, 200, ""},
		{"GET", "/api/teleport/v1/audit?page=1&page_size=5&order=asc&action=teleport.alert_rule.create&outcome=success&cluster_id=" + id, "auditor", nil, 200, ""},
		{"GET", "/api/teleport/v1/audit?action=teleport.nope", "auditor", nil, 422, "validation_failed"},
		{"GET", "/api/teleport/v1/audit?page_size=500", "auditor", nil, 422, "validation_failed"},
		{"GET", "/api/teleport/v1/audit", "viewer", nil, 403, "forbidden"},
		{"GET", "/api/teleport/v1/alert-rules", "viewer", nil, 200, ""},
		{"POST", "/api/teleport/v1/alert-rules", "viewer", map[string]any{"name": "x", "condition_kind": "resource_offline",
			"recipients": map[string]any{"user_ids": []string{"u"}}}, 403, "forbidden"},
		{"POST", "/api/teleport/v1/alert-rules", "admin", map[string]any{"name": "offline", "condition_kind": "resource_offline",
			"recipients": map[string]any{"user_ids": []string{"u"}}, "enabled": false}, 201, ""},
		{"POST", "/api/teleport/v1/alert-rules", "admin", map[string]any{"name": "x", "condition_kind": "teleport_event",
			"event_types": []string{"session.print"}, "recipients": map[string]any{"user_ids": []string{"u"}}}, 422, "validation_failed"},
		{"POST", "/api/teleport/v1/alert-rules", "admin", map[string]any{"name": "x", "condition_kind": "teleport_event",
			"recipients": map[string]any{"user_ids": []string{"u"}}}, 422, "validation_failed"},
		{"POST", "/api/teleport/v1/alert-rules", "admin", map[string]any{"name": "x", "condition_kind": "resource_offline",
			"recipients": map[string]any{"user_ids": []string{"u"}}, "extra": 1}, 422, "validation_failed"},
		{"PUT", "/api/teleport/v1/alert-rules/" + rule.ID, "admin", map[string]any{"name": "any failed login", "condition_kind": "teleport_event",
			"event_types": []string{"user.login.failure"}, "cluster_id": id, "recipients": map[string]any{"user_ids": []string{ct.Admin}}}, 200, ""},
		{"PUT", "/api/teleport/v1/alert-rules/018f3a2b-0000-7000-8000-0000000000ff", "admin", map[string]any{"name": "x",
			"condition_kind": "resource_offline", "recipients": map[string]any{"user_ids": []string{"u"}}}, 404, "not_found"},
		{"DELETE", "/api/teleport/v1/alert-rules/" + rule.ID, "viewer", nil, 403, "forbidden"},
		{"DELETE", "/api/teleport/v1/alert-rules/" + rule.ID, "admin", nil, 204, ""},
		{"DELETE", "/api/teleport/v1/alert-rules/" + rule.ID, "admin", nil, 404, "not_found"},
	} {
		r, rec := call(s, c.method, c.path, c.token, c.body)
		if rec.Code != c.status {
			t.Fatalf("%s %s: %d %s", c.method, c.path, rec.Code, rec.Body)
		}
		var m struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		if c.reason != "" && m.Reason != c.reason {
			t.Fatalf("%s %s: reason %q, want %s (%s)", c.method, c.path, m.Reason, c.reason, rec.Body)
		}
		if rec.Code != 204 {
			ValidateResponse(t, doc, r, rec)
		}
	}
	// The normalized fields and the playback link come back as declared.
	_, rec := call(s, "GET", base+"/events?"+day+"&types=user.login.failure", "auditor", nil)
	var page struct {
		Items []struct {
			Type    string `json:"type"`
			User    string `json:"user"`
			Success bool   `json:"success"`
		} `json:"items"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &page)
	if len(page.Items) != 1 || page.Items[0].Type != "user.login.failure" || page.Items[0].User != "mallory" || page.Items[0].Success {
		t.Fatalf("failed logins %s", rec.Body)
	}
	_, rec = call(s, "GET", base+"/sessions?"+day, "auditor", nil)
	if !strings.Contains(rec.Body.String(), `"playback_url":"https://teleport.example.com/web/cluster/prod.example.com/session/abc-1","playable":true`) {
		t.Fatalf("sessions %s", rec.Body)
	}
}
