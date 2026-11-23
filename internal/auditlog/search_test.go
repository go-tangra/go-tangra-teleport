package auditlog_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/auditlog"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// ev builds a Teleport audit event whose JSON carries fields.
func ev(id, typ, code string, at time.Time, fields map[string]any) teleportapi.AuditEvent {
	m := map[string]any{"uid": id, "event": typ, "code": code, "time": at.Format(time.RFC3339Nano)}
	for k, v := range fields {
		m[k] = v
	}
	raw, _ := json.Marshal(m)
	return teleportapi.AuditEvent{ID: id, Type: typ, Code: code, Time: at, Raw: raw}
}

func setup(t *testing.T) (*ct.Env, *auditlog.Service, string) {
	t.Helper()
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	return e, &auditlog.Service{Clusters: e.Service}, c.ID
}

func field(err error) string {
	var fe *clusters.FieldError
	if errors.As(err, &fe) {
		return fe.Field
	}
	return ""
}

// The window is required and at most 31 days; limit is at most 200; event
// types must be on the allow-list (quickstart scenario 4b).
func TestSearchValidatesTheQuery(t *testing.T) {
	_, s, id := setup(t)
	ctx := ct.As(ct.TenantA, ct.Admin)
	now := time.Now().UTC()
	for _, c := range []struct {
		q     auditlog.Query
		field string
	}{
		{auditlog.Query{To: now}, "from"},
		{auditlog.Query{From: now}, "to"},
		{auditlog.Query{From: now, To: now.Add(-time.Second)}, "to"},
		{auditlog.Query{From: now.Add(-60 * 24 * time.Hour), To: now}, "to"},
		{auditlog.Query{From: now.Add(-time.Hour), To: now, Limit: 201}, "limit"},
		{auditlog.Query{From: now.Add(-time.Hour), To: now, Limit: -1}, "limit"},
		{auditlog.Query{From: now.Add(-time.Hour), To: now, Types: []string{"session.print"}}, "types"},
		{auditlog.Query{From: now.Add(-time.Hour), To: now, User: strings.Repeat("u", 129)}, "user"},
		{auditlog.Query{From: now.Add(-time.Hour), To: now, Resource: strings.Repeat("r", 129)}, "resource"},
	} {
		if _, err := s.Events(ctx, id, c.q); !errors.Is(err, clusters.ErrInvalid) || field(err) != c.field {
			t.Errorf("%+v: %v (field %q, want %q)", c.q, err, field(err), c.field)
		}
	}
	for _, q := range []auditlog.SessionQuery{{To: now}, {From: now.Add(-32 * 24 * time.Hour), To: now}, {From: now.Add(-time.Hour), To: now, Limit: 500}} {
		if _, err := s.Sessions(ctx, id, q); !errors.Is(err, clusters.ErrInvalid) {
			t.Errorf("sessions %+v: %v", q, err)
		}
	}
	// Exactly 31 days and 200 events are allowed.
	if _, err := s.Events(ctx, id, auditlog.Query{From: now.Add(-auditlog.MaxWindow), To: now, Limit: auditlog.MaxLimit}); err != nil {
		t.Fatal(err)
	}
}

// Events need audit:read (a viewer lacks it); another tenant's cluster is not found.
func TestSearchNeedsAuditRead(t *testing.T) {
	_, s, id := setup(t)
	now := time.Now().UTC()
	q := auditlog.Query{From: now.Add(-time.Hour), To: now}
	if _, err := s.Events(ct.As(ct.TenantA, ct.Viewer), id, q); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer events: %v", err)
	}
	if _, err := s.Sessions(ct.As(ct.TenantA, ct.Viewer), id, auditlog.SessionQuery{From: q.From, To: q.To}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer sessions: %v", err)
	}
	if _, err := s.Events(ct.As(ct.TenantB, ct.Admin), id, q); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("other tenant: %v", err)
	}
	if _, err := s.Events(ct.As(ct.TenantA, ct.Auditor), id, q); err != nil {
		t.Fatalf("auditor: %v", err)
	}
}

// The main event types are normalized: user, resource, success and a
// module-written summary.
func TestNormalizeMainEvents(t *testing.T) {
	at := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		in                        teleportapi.AuditEvent
		typ, user, resource, summ string
		success                   bool
	}{
		{ev("1", "user.login", "T1000I", at, map[string]any{"user": "alice", "method": "local", "success": true}), "user.login", "alice", "", "alice signed in", true},
		{ev("2", "user.login", "T1000W", at, map[string]any{"user": "mallory", "success": false, "error": "bad password"}), "user.login.failure", "mallory", "", "mallory failed to sign in", false},
		{ev("3", "user.login", "T1001W", at, map[string]any{"user": "sso-user"}), "user.login.failure", "sso-user", "", "sso-user failed to sign in", false},
		{ev("4", "session.start", "T2000I", at, map[string]any{"user": "alice", "server_hostname": "web-1", "sid": "s1"}), "session.start", "alice", "web-1", "alice started a session on web-1", true},
		{ev("5", "session.end", "T2004I", at, map[string]any{"user": "alice", "server_hostname": "web-1"}), "session.end", "alice", "web-1", "alice ended a session on web-1", true},
		{ev("6", "role.created", "T9000I", at, map[string]any{"user": "admin", "name": "dev"}), "role.created", "admin", "dev", "admin created role dev", true},
		{ev("7", "role.updated", "T9002I", at, map[string]any{"user": "admin", "name": "dev"}), "role.updated", "admin", "dev", "admin updated role dev", true},
		{ev("8", "lock.created", "TLK00I", at, map[string]any{"user": "admin", "name": "tangra-1"}), "lock.created", "admin", "tangra-1", "admin created lock tangra-1", true},
		{ev("9", "", "T9006I", at, map[string]any{"user": "admin", "name": "l2"}), "lock.created", "admin", "l2", "admin created lock l2", true},
		{ev("10", "db.session.start", "TDB00I", at, map[string]any{"user": "bob", "db_service": "pg"}), "db.session.start", "bob", "pg", "bob started a database session on pg", true},
		{ev("11", "exec", "T3002E", at, map[string]any{"user": "bob", "server_hostname": "web-2"}), "exec", "bob", "web-2", "bob ran a command on web-2", false},
		{ev("12", "custom.thing", "X1", at, map[string]any{"user": "<b>x</b>"}), "custom.thing", "<b>x</b>", "", "custom.thing by <b>x</b>", true},
	} {
		got := auditlog.Normalize(c.in)
		if got.Type != c.typ || got.User != c.user || got.Resource != c.resource || got.Summary != c.summ || got.Success != c.success {
			t.Errorf("%s/%s: %+v", c.in.Type, c.in.Code, got)
		}
		if got.ID != c.in.ID || !got.Time.Equal(at) || got.Code != c.in.Code || !json.Valid(got.Raw) {
			t.Errorf("%s: identity %+v", c.in.ID, got)
		}
	}
	// Control characters are stripped and long names bounded.
	n := auditlog.Normalize(ev("x", "user.login", "T1000I", at, map[string]any{"user": "a\x00b\nc" + strings.Repeat("z", 400)}))
	if strings.ContainsAny(n.User, "\x00\n") || len(n.User) > 256 {
		t.Fatalf("user %q", n.User)
	}
}

// raw is bounded at 16 KiB and stays valid JSON.
func TestRawIsBounded(t *testing.T) {
	at := time.Now().UTC()
	small := auditlog.Normalize(ev("a", "exec", "T3002I", at, map[string]any{"command": "ls"}))
	if !strings.Contains(string(small.Raw), `"command":"ls"`) {
		t.Fatalf("raw %s", small.Raw)
	}
	big := auditlog.Normalize(ev("b", "exec", "T3002I", at, map[string]any{"user": "alice", "command": strings.Repeat("x", 40<<10),
		"nested": map[string]any{"a": strings.Repeat("y", 1000)}}))
	if len(big.Raw) > auditlog.MaxRaw || !json.Valid(big.Raw) {
		t.Fatalf("raw %d bytes valid=%v", len(big.Raw), json.Valid(big.Raw))
	}
	var m map[string]any
	_ = json.Unmarshal(big.Raw, &m)
	if m["truncated"] != true || m["user"] != "alice" || len(m["command"].(string)) > 256 || m["nested"] != nil {
		t.Fatalf("truncated raw %v", m)
	}
	if big.User != "alice" || big.Resource != "" {
		t.Fatalf("event %+v", big)
	}
	// Not an object, or not JSON at all.
	for _, raw := range []string{`[1,2]`, `"s"`, `{`, ``} {
		n := auditlog.Normalize(teleportapi.AuditEvent{ID: "z", Type: "exec", Raw: json.RawMessage(raw)})
		if !json.Valid(n.Raw) || len(n.Raw) > auditlog.MaxRaw {
			t.Fatalf("%q -> %s", raw, n.Raw)
		}
	}
}

// Events come back newest first; next passes through; types, user and
// resource filter; a filter that drops events reads further pages.
func TestSearchEvents(t *testing.T) {
	e, s, id := setup(t)
	ctx := ct.As(ct.TenantA, ct.Auditor)
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	var all []teleportapi.AuditEvent
	for i := range 10 {
		code, user := "T1000I", "alice"
		if i%2 == 1 {
			code, user = "T1000W", "mallory"
		}
		all = append(all, ev("l"+string(rune('0'+i)), "user.login", code, base.Add(time.Duration(i)*time.Minute), map[string]any{"user": user}))
	}
	all = append(all, ev("s1", "session.start", "T2000I", base.Add(30*time.Minute), map[string]any{"user": "alice", "server_hostname": "web-1"}))
	all = append(all, ev("x1", "app.session.chunk", "T2008I", base.Add(31*time.Minute), nil)) // not on the allow-list
	e.Teleport.AuditEvents = all
	from, to := base.Add(-time.Minute), base.Add(time.Hour)

	p, err := s.Events(ctx, id, auditlog.Query{From: from, To: to, Limit: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Items) != 4 || p.Items[0].ID != "s1" || p.Next == "" {
		t.Fatalf("first page %+v", p)
	}
	for i := 1; i < len(p.Items); i++ {
		if p.Items[i].Time.After(p.Items[i-1].Time) {
			t.Fatal("not newest first")
		}
	}
	p2, err := s.Events(ctx, id, auditlog.Query{From: from, To: to, Limit: 4, Next: p.Next})
	if err != nil || len(p2.Items) != 4 || p2.Items[0].ID == p.Items[0].ID {
		t.Fatalf("second page %+v %v", p2, err)
	}
	// Default limit; the event outside the allow-list is never returned.
	p, _ = s.Events(ctx, id, auditlog.Query{From: from, To: to})
	if len(p.Items) != 11 || p.Next != "" {
		t.Fatalf("all %d next %q", len(p.Items), p.Next)
	}
	// Failed logins only: half of every Teleport page is dropped, so further pages are read.
	p, _ = s.Events(ctx, id, auditlog.Query{From: from, To: to, Types: []string{auditlog.TypeLoginFailure}, Limit: 3})
	if len(p.Items) != 3 || p.Next == "" {
		t.Fatalf("failures %+v", p)
	}
	for _, it := range p.Items {
		if it.Type != auditlog.TypeLoginFailure || it.Success || it.User != "mallory" {
			t.Fatalf("failure item %+v", it)
		}
	}
	p, _ = s.Events(ctx, id, auditlog.Query{From: from, To: to, User: "ALICE"})
	if len(p.Items) != 6 {
		t.Fatalf("alice %d", len(p.Items))
	}
	p, _ = s.Events(ctx, id, auditlog.Query{From: from, To: to, Resource: "web"})
	if len(p.Items) != 1 || p.Items[0].ID != "s1" {
		t.Fatalf("resource %+v", p.Items)
	}
	// Teleport failures pass through mapped.
	e.Teleport.SetErr(errors.New("dial tcp: connection refused"))
	if _, err := s.Events(ctx, id, auditlog.Query{From: from, To: to}); err == nil {
		t.Fatal("outage not reported")
	}
}

// Sessions list participants, target, kind, start, duration and a playback link.
func TestSearchSessions(t *testing.T) {
	e, s, id := setup(t)
	ctx := ct.As(ct.TenantA, ct.Auditor)
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	stop := start.Add(90 * time.Second)
	e.Teleport.SessionEvents = []teleportapi.AuditEvent{
		ev("e1", "session.end", "T2004I", stop, map[string]any{"sid": "8f6e3a2b-1111-4222-8333-444455556666", "user": "alice",
			"participants": []string{"alice", "bob"}, "server_hostname": "web-1", "session_start": start.Format(time.RFC3339Nano),
			"session_stop": stop.Format(time.RFC3339Nano)}),
		ev("e2", "session.end", "T2004I", stop.Add(time.Minute), map[string]any{"sid": "k-1", "user": "carol", "kubernetes_cluster": "prod-k8s"}),
		ev("e3", "db.session.end", "TDB01I", stop.Add(2*time.Minute), map[string]any{"sid": "bad sid/..", "user": "dan", "db_service": "pg"}),
		ev("e4", "windows.desktop.session.end", "TDP01I", stop.Add(3*time.Minute), map[string]any{"sid": "d-1", "user": "erin", "desktop_name": "win-1"}),
	}
	p, err := s.Sessions(ctx, id, auditlog.SessionQuery{From: start.Add(-time.Hour), To: stop.Add(time.Hour)})
	if err != nil || len(p.Items) != 4 {
		t.Fatalf("sessions %+v %v", p, err)
	}
	by := map[string]auditlog.Session{}
	for _, it := range p.Items {
		by[it.Kind] = it
	}
	ssh := by["ssh"]
	if ssh.Target != "web-1" || ssh.DurationS != 90 || !ssh.StartedAt.Equal(start) || strings.Join(ssh.Participants, ",") != "alice,bob" ||
		ssh.PlaybackURL != "https://teleport.example.com/web/cluster/prod.example.com/session/8f6e3a2b-1111-4222-8333-444455556666" {
		t.Fatalf("ssh %+v", ssh)
	}
	if k := by["kube"]; k.Target != "prod-k8s" || strings.Join(k.Participants, ",") != "carol" || k.PlaybackURL == "" {
		t.Fatalf("kube %+v", k)
	}
	if d := by["db"]; d.Target != "pg" || d.PlaybackURL != "" {
		t.Fatalf("db %+v (an unsafe sid gets no link)", d)
	}
	if d := by["desktop"]; d.Target != "win-1" {
		t.Fatalf("desktop %+v", d)
	}
	// Spec 003 FR-007: only SSH sessions are playable in the portal; every
	// kind keeps its Teleport link.
	for kind, it := range by {
		if it.Playable != (kind == "ssh") {
			t.Errorf("%s playable = %v", kind, it.Playable)
		}
	}
	raw, _ := json.Marshal(by["kube"])
	if !strings.Contains(string(raw), `"playable":false`) {
		t.Fatalf("playable is always sent: %s", raw)
	}
	// An SSH session with an unusable id is not playable.
	e.Teleport.SessionEvents = []teleportapi.AuditEvent{ev("e5", "session.end", "T2004I", stop, map[string]any{"sid": "bad sid", "user": "x"})}
	p, err = s.Sessions(ctx, id, auditlog.SessionQuery{From: start.Add(-time.Hour), To: stop.Add(time.Hour)})
	if err != nil || len(p.Items) != 1 || p.Items[0].Kind != "ssh" || p.Items[0].Playable {
		t.Fatalf("unsafe ssh sid %+v %v", p, err)
	}
}

func TestPlaybackURL(t *testing.T) {
	for _, c := range []struct{ addr, cluster, sid, want string }{
		{"tp.example.com:443", "tp", "s-1", "https://tp.example.com/web/cluster/tp/session/s-1"},
		{"tp.example.com:3080", "a b", "s-1", "https://tp.example.com:3080/web/cluster/a%20b/session/s-1"},
		{"tp.example.com:443", "", "s-1", ""},
		{"tp.example.com:443", "tp", "", ""},
		{"tp.example.com:443", "tp", "../x", ""},
		{"bad::addr", "tp", "s", ""},
	} {
		if got := auditlog.PlaybackURL(c.addr, c.cluster, c.sid); got != c.want {
			t.Errorf("%v: %q", c, got)
		}
	}
}

func TestAllowList(t *testing.T) {
	if !auditlog.Allowed(auditlog.TypeLoginFailure) || auditlog.Allowed("session.print") || auditlog.Allowed("") {
		t.Fatal("allow-list")
	}
	got := auditlog.TeleportTypes([]string{auditlog.TypeLogin, auditlog.TypeLoginFailure, auditlog.TypeSessionStart})
	if strings.Join(got, ",") != "session.start,user.login" {
		t.Fatalf("teleport types %v", got)
	}
	if len(auditlog.TeleportTypes(nil)) == 0 {
		t.Fatal("empty means every allow-listed type")
	}
}

// The module audit trail is the tenant's own rows, filtered and paged.
func TestTrail(t *testing.T) {
	e, s, id := setup(t)
	e.Audit.Flush(context.Background()) // the registration row
	for i := range 3 {
		_ = e.Repo.AppendAudit(context.Background(), repo.AuditRow{ID: "r" + string(rune('0'+i)), Time: time.Now().UTC().Add(time.Duration(i) * time.Second),
			TenantID: ct.TenantA, ActorKind: "user", ActorID: ct.Admin, ClusterID: id, Action: string(audit.LockCreate), TargetKind: "lock",
			TargetName: "l", Outcome: audit.OutcomeFailure, Reason: "forbidden"})
	}
	_ = e.Repo.AppendAudit(context.Background(), repo.AuditRow{ID: "other", Time: time.Now().UTC(), TenantID: ct.TenantB, ActorKind: "user",
		Action: string(audit.LockCreate), TargetKind: "lock", Outcome: audit.OutcomeSuccess})
	ctx := ct.As(ct.TenantA, ct.Auditor)
	req, _ := listquery.New(1, 2, "time", "", auditlog.TrailList)
	p, err := s.Trail(ctx, req, auditlog.TrailFilter{})
	if err != nil || p.Total != 4 || len(p.Items) != 2 || p.Items[0].ID != "r2" {
		t.Fatalf("trail %+v %v", p, err)
	}
	p, _ = s.Trail(ctx, req, auditlog.TrailFilter{Action: string(audit.LockCreate), Outcome: audit.OutcomeFailure, ClusterID: id})
	if p.Total != 3 || p.Items[0].ClusterID != id || p.Items[0].Reason != "forbidden" {
		t.Fatalf("filtered %+v", p)
	}
	asc, _ := listquery.New(5, 2, "time", listquery.Asc, auditlog.TrailList) // beyond the end: the last page
	p, _ = s.Trail(ctx, asc, auditlog.TrailFilter{})
	if p.Page != 2 || len(p.Items) != 2 || p.Items[1].ID != "r2" {
		t.Fatalf("clamped %+v", p)
	}
	if _, err := s.Trail(ctx, req, auditlog.TrailFilter{Action: "teleport.nope"}); field(err) != "action" {
		t.Fatalf("action: %v", err)
	}
	if _, err := s.Trail(ctx, req, auditlog.TrailFilter{Outcome: "maybe"}); field(err) != "outcome" {
		t.Fatalf("outcome: %v", err)
	}
	now := time.Now()
	if _, err := s.Trail(ctx, req, auditlog.TrailFilter{From: now, To: now.Add(-time.Hour)}); field(err) != "to" {
		t.Fatalf("window: %v", err)
	}
	if _, err := s.Trail(ct.As(ct.TenantA, ct.Viewer), req, auditlog.TrailFilter{}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer: %v", err)
	}
	e.Repo.FailNext("ListAudit")
	if _, err := s.Trail(ctx, req, auditlog.TrailFilter{}); err == nil {
		t.Fatal("store failure hidden")
	}
}
