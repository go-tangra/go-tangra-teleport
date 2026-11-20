package alerts_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/alerts"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/auditlog"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

type env struct {
	*ct.Env
	cluster string
	engine  *alerts.Engine
	seq     int
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	return &env{Env: e, cluster: c.ID, engine: engine(e)}
}

func engine(e *ct.Env) *alerts.Engine {
	return &alerts.Engine{Clusters: e.Service, Repo: e.Repo, Notify: e.Notify, Audit: e.Audit, Now: e.Now}
}

func (v *env) rule(t *testing.T, mut func(*repo.AlertRule)) repo.AlertRule {
	t.Helper()
	r := repo.AlertRule{ID: store.NewID(), TenantID: ct.TenantA, ClusterID: v.cluster, Name: "failed logins",
		ConditionKind: repo.ConditionTeleportEvent, EventTypes: []string{auditlog.TypeLoginFailure},
		Recipients: repo.Recipients{UserIDs: []string{"u-sec"}}, Enabled: true}
	if mut != nil {
		mut(&r)
	}
	if err := v.Repo.CreateAlertRule(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	return r
}

// login appends a login event for user at the harness time minus ago.
func (v *env) login(user string, ok bool, ago time.Duration) teleportapi.AuditEvent {
	v.seq++
	code := "T1000I"
	if !ok {
		code = "T1000W"
	}
	at := v.Now().Add(-ago)
	raw, _ := json.Marshal(map[string]any{"user": user, "success": ok, "code": code, "event": "user.login"})
	ev := teleportapi.AuditEvent{ID: fmt.Sprintf("ev-%03d", v.seq), Type: "user.login", Code: code, Time: at, Raw: raw}
	v.Teleport.AuditEvents = append(v.Teleport.AuditEvents, ev)
	return ev
}

func (v *env) sent() []notify.Message { return v.Notify.Sent() }

func (v *env) cursor(t *testing.T) repo.AlertCursor {
	t.Helper()
	c, err := v.Repo.GetAlertCursor(context.Background(), ct.TenantA, v.cluster)
	if err != nil {
		t.Fatalf("cursor: %v", err)
	}
	return c
}

// The cursor advances without gaps or duplicates, across polls and pages,
// including events that share the cursor's timestamp.
func TestCursorHasNoGapsOrDuplicates(t *testing.T) {
	v := newEnv(t)
	v.rule(t, nil)
	v.engine.PageSize, v.engine.MaxPages = 2, 2
	for i := range 5 {
		v.login("mallory", false, time.Duration(4-i)*30*time.Second+time.Minute)
	}
	v.login("alice", true, time.Minute) // not matched by the rule
	if n := v.engine.RunOnce(context.Background()); n != 1 {
		t.Fatalf("polled %d clusters", n)
	}
	if got := len(v.sent()); got != 4 { // two pages of two
		t.Fatalf("first poll sent %d", got)
	}
	if c := v.cursor(t); c.LastEventID != "ev-004" {
		t.Fatalf("cursor %+v", c)
	}
	v.engine.RunOnce(context.Background())
	if got := len(v.sent()); got != 5 {
		t.Fatalf("second poll sent %d", got)
	}
	// Nothing new: no duplicate, and the cursor moves to the settle point.
	v.Advance(time.Minute)
	v.engine.RunOnce(context.Background())
	if got := len(v.sent()); got != 5 {
		t.Fatalf("idle poll sent %d", got)
	}
	idle := v.cursor(t)
	if idle.LastEventID != "" || !idle.LastEventTime.Equal(v.Now().Add(-alerts.DefaultSettle)) {
		t.Fatalf("idle cursor %+v", idle)
	}
	// Two events at the same instant, split by the cursor.
	v.Advance(time.Minute)
	a := v.login("mallory", false, 30*time.Second)
	v.engine.RunOnce(context.Background())
	b := v.login("mallory", false, 0)
	b.Time = a.Time
	v.Teleport.AuditEvents[len(v.Teleport.AuditEvents)-1] = b
	v.engine.RunOnce(context.Background())
	if got := len(v.sent()); got != 7 {
		t.Fatalf("same-instant events sent %d", got)
	}
	seen := map[string]bool{}
	for _, m := range v.sent() {
		if seen[m.Vars["event_id"]] {
			t.Fatalf("event %s delivered twice", m.Vars["event_id"])
		}
		seen[m.Vars["event_id"]] = true
		if m.Template != notify.TemplateAlert || m.To != "u-sec" || m.TenantID != ct.TenantA || m.Vars["cluster_name"] != ct.ClusterName ||
			m.Vars["user"] != "mallory" || m.Vars["time"] == "" || m.Vars["event_type"] != auditlog.TypeLoginFailure {
			t.Fatalf("message %+v", m)
		}
	}
	// A new engine (lease handover) resumes from the stored cursor.
	v.Advance(time.Minute)
	other := engine(v.Env)
	other.RunOnce(context.Background())
	if got := len(v.sent()); got != 7 {
		t.Fatalf("handover re-sent: %d", got)
	}
}

// A count-in-window rule fires once per user and window, also across polls
// and after a lease handover (the window history is rebuilt).
func TestBurstRule(t *testing.T) {
	v := newEnv(t)
	v.rule(t, func(r *repo.AlertRule) { r.ThresholdCount, r.WindowMinutes = 3, 5 })
	// Put the clock 3 minutes into a 5-minute window, so each burst below
	// stays inside one window.
	now := v.Now()
	v.Advance(now.Truncate(5 * time.Minute).Add(8 * time.Minute).Sub(now))
	for i := range 5 {
		v.login("mallory", false, time.Duration(5-i)*10*time.Second+time.Minute)
	}
	v.login("alice", false, 70*time.Second)
	v.login("alice", false, 65*time.Second)
	v.engine.RunOnce(context.Background())
	sent := v.sent()
	if len(sent) != 1 || sent[0].Vars["user"] != "mallory" || sent[0].Vars["count"] != "3" || sent[0].Vars["window_minutes"] != "5" {
		t.Fatalf("burst sent %+v", sent)
	}
	// Spread-out failures never reach the threshold.
	v.Advance(time.Hour)
	for i := range 3 {
		v.login("bob", false, time.Duration(3-i)*4*time.Minute)
	}
	v.engine.RunOnce(context.Background())
	if len(v.sent()) != 1 {
		t.Fatalf("spread failures alerted: %+v", v.sent())
	}
	// Two failures, a poll, a handover, a third failure: one alert.
	v.Advance(time.Hour)
	v.login("carol", false, 2*time.Minute)
	v.login("carol", false, 90*time.Second)
	v.engine.RunOnce(context.Background())
	if len(v.sent()) != 1 {
		t.Fatal("alerted below the threshold")
	}
	v.Advance(30 * time.Second)
	v.login("carol", false, 30*time.Second)
	fresh := engine(v.Env)
	fresh.RunOnce(context.Background())
	if s := v.sent(); len(s) != 2 || s[1].Vars["user"] != "carol" {
		t.Fatalf("handover burst %+v", s)
	}
	// Further failures in the same window are de-duplicated.
	v.Advance(20 * time.Second)
	v.login("carol", false, 15*time.Second)
	fresh.RunOnce(context.Background())
	if len(v.sent()) != 2 {
		t.Fatal("same window delivered twice")
	}
}

// Deliveries are per rule and cluster; scope, enablement and the cluster's
// alert switch apply.
func TestRulesScopeAndDeduplication(t *testing.T) {
	v := newEnv(t)
	other := v.Register(t, ct.TenantA, "staging")
	v.rule(t, nil)                                                               // this cluster
	v.rule(t, func(r *repo.AlertRule) { r.ClusterID, r.Name = "", "all" })       // every cluster
	v.rule(t, func(r *repo.AlertRule) { r.Enabled, r.Name = false, "disabled" }) // never
	v.rule(t, func(r *repo.AlertRule) {
		r.Name, r.EventTypes = "logins", []string{auditlog.TypeLogin}
	}) // other type
	v.login("mallory", false, time.Minute)
	v.engine.RunOnce(context.Background())
	// Both clusters share the fake Teleport: cluster 1 matches two rules, the other only the global rule.
	byCluster := map[string]int{}
	for _, m := range v.sent() {
		byCluster[m.Vars["cluster_id"]]++
	}
	if byCluster[v.cluster] != 2 || byCluster[other.ID] != 1 || len(v.sent()) != 3 {
		t.Fatalf("deliveries %v", byCluster)
	}
	// Alerts switched off on a cluster: nothing more for it.
	c, _ := v.Repo.GetCluster(context.Background(), ct.TenantA, other.ID)
	c.Settings.AlertsEnabled = false
	if _, err := v.Repo.UpdateCluster(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	v.Advance(time.Minute)
	v.login("mallory", false, 10*time.Second)
	v.engine.RunOnce(context.Background())
	if byCluster := len(v.sent()); byCluster != 5 {
		t.Fatalf("after disabling: %d", byCluster)
	}
	for _, m := range v.sent()[3:] {
		if m.Vars["cluster_id"] == other.ID {
			t.Fatal("a disabled cluster alerted")
		}
	}
	v.Audit.Flush(context.Background())
	n := 0
	for _, r := range v.Repo.Audit() {
		if r.Action == "teleport.alert.deliver" && r.Outcome == "success" && r.ActorKind == "worker" {
			n++
		}
	}
	if n != 5 {
		t.Fatalf("%d delivery audit rows", n)
	}
}

// When notification is unavailable the delivery is retried and the cursor
// held; a delivery refused for longer than MaxHold is dropped.
func TestNotificationFailureHoldsTheCursor(t *testing.T) {
	v := newEnv(t)
	v.rule(t, nil)
	v.login("mallory", false, 2*time.Minute)
	v.engine.RunOnce(context.Background())
	held := v.cursor(t)
	v.login("mallory", false, time.Minute)
	v.Notify.SetErr(notify.ErrUnavailable)
	v.engine.RunOnce(context.Background())
	if c := v.cursor(t); c.LastEventID != held.LastEventID || !c.LastEventTime.Equal(held.LastEventTime) {
		t.Fatalf("cursor moved while notification was down: %+v -> %+v", held, c)
	}
	v.Notify.SetErr(nil)
	v.Advance(time.Minute)
	v.engine.RunOnce(context.Background())
	if len(v.sent()) != 2 || v.cursor(t).LastEventID != "ev-002" {
		t.Fatalf("retry: %d sent, cursor %+v", len(v.sent()), v.cursor(t))
	}
	// A refusal that persists past MaxHold is dropped and the cursor moves on.
	v.engine.MaxHold = 10 * time.Minute
	v.login("mallory", false, 15*time.Second)
	v.Notify.SetErr(notify.ErrNotDelivered)
	v.engine.RunOnce(context.Background())
	if v.cursor(t).LastEventID != "ev-002" {
		t.Fatal("cursor not held")
	}
	v.Advance(11 * time.Minute)
	v.engine.RunOnce(context.Background())
	if c := v.cursor(t); c.LastEventID == "ev-002" {
		t.Fatalf("cursor still held after MaxHold: %+v", c)
	}
	v.Notify.SetErr(nil)
	v.engine.RunOnce(context.Background())
	if len(v.sent()) != 2 {
		t.Fatal("a dropped delivery was sent later")
	}
}

// A Teleport outage or a store failure holds the cursor.
func TestPollFailuresHoldTheCursor(t *testing.T) {
	v := newEnv(t)
	v.rule(t, nil)
	v.login("mallory", false, time.Minute)
	v.Teleport.SetErr(errors.New("connection refused"))
	c, _ := v.Repo.GetCluster(context.Background(), ct.TenantA, v.cluster)
	if err := v.engine.PollCluster(context.Background(), c); err == nil {
		t.Fatal("outage not reported")
	}
	if _, err := v.Repo.GetAlertCursor(context.Background(), ct.TenantA, v.cluster); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("cursor written during an outage: %v", err)
	}
	v.Teleport.SetErr(nil)
	v.Repo.FailNext("RecordDelivery")
	if err := v.engine.PollCluster(context.Background(), c); err == nil {
		t.Fatal("store failure not reported")
	}
	v.Repo.FailNext("ListAlertRules")
	if err := v.engine.PollCluster(context.Background(), c); err == nil {
		t.Fatal("rule list failure not reported")
	}
	v.Repo.FailNext("GetAlertCursor")
	if err := v.engine.PollCluster(context.Background(), c); err == nil {
		t.Fatal("cursor failure not reported")
	}
	if err := v.engine.PollCluster(context.Background(), c); err != nil || len(v.sent()) != 1 {
		t.Fatalf("recovered poll: %v, %d sent", err, len(v.sent()))
	}
	v.Repo.FailNext("AllClusters")
	if n := v.engine.RunOnce(context.Background()); n != 0 {
		t.Fatal("polled without a cluster list")
	}
}

// Without an enabled event rule the cursor just follows the clock, so a rule
// enabled later does not replay old events.
func TestNoRulesFollowsTheClock(t *testing.T) {
	v := newEnv(t)
	v.login("mallory", false, time.Minute)
	v.engine.RunOnce(context.Background())
	if c := v.cursor(t); !c.LastEventTime.Equal(v.Now().Add(-alerts.DefaultSettle)) {
		t.Fatalf("cursor %+v", c)
	}
	v.rule(t, nil)
	v.Advance(time.Minute)
	v.engine.RunOnce(context.Background())
	if len(v.sent()) != 0 || v.Teleport.Calls("SearchEvents") != 1 {
		t.Fatalf("old event replayed: %d (%d searches)", len(v.sent()), v.Teleport.Calls("SearchEvents"))
	}
}

// Module conditions (resource_offline from the sweep) go to their rules
// once per occurrence key; a failed send is retried on the next call.
func TestModuleConditionAlerts(t *testing.T) {
	v := newEnv(t)
	v.rule(t, func(r *repo.AlertRule) {
		r.Name, r.ConditionKind, r.EventTypes = "offline", repo.ConditionResourceOffline, nil
	})
	v.rule(t, func(r *repo.AlertRule) {
		r.Name, r.ConditionKind, r.EventTypes = "down", repo.ConditionClusterUnreachable, nil
	})
	c, _ := v.Repo.GetCluster(context.Background(), ct.TenantA, v.cluster)
	vars := map[string]string{"resource": "web-1"}
	v.Notify.SetErr(notify.ErrUnavailable)
	v.engine.Alert(context.Background(), c, repo.ConditionResourceOffline, "snap-1@t", vars)
	v.Notify.SetErr(nil)
	v.engine.Alert(context.Background(), c, repo.ConditionResourceOffline, "snap-1@t", vars)
	v.engine.Alert(context.Background(), c, repo.ConditionResourceOffline, "snap-1@t", vars)
	v.engine.Alert(context.Background(), c, repo.ConditionResourceOffline, "snap-2@t", vars)
	s := v.sent()
	if len(s) != 2 || s[0].Vars["resource"] != "web-1" || s[0].Vars["rule_name"] != "offline" || s[0].Vars["condition"] != repo.ConditionResourceOffline {
		t.Fatalf("module alerts %+v", s)
	}
	if vars["rule_name"] != "" {
		t.Fatal("the caller's variables were changed")
	}
	v.Repo.FailNext("ListAlertRules")
	v.engine.Alert(context.Background(), c, repo.ConditionResourceOffline, "snap-3@t", vars)
	if len(v.sent()) != 2 {
		t.Fatal("alert sent without rules")
	}
}

// Run polls every interval until cancelled and prunes old deliveries.
func TestRunLoop(t *testing.T) {
	v := newEnv(t)
	r := v.rule(t, nil)
	old := repo.AlertDelivery{ID: store.NewID(), TenantID: ct.TenantA, RuleID: r.ID, ClusterID: v.cluster, WindowKey: "old",
		DeliveredAt: v.Now().Add(-40 * 24 * time.Hour)}
	if err := v.Repo.RecordDelivery(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	v.engine.Interval = 5 * time.Millisecond
	v.engine.Now = func() time.Time { return time.Now().UTC() } // the loop needs time to pass
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { v.engine.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for v.Teleport.Calls("SearchEvents") < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the loop did not poll twice")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if err := v.Repo.RecordDelivery(context.Background(), old); err != nil {
		t.Fatalf("the old delivery was not pruned: %v", err)
	}
	if v.engine.IntervalOrDefault() != 5*time.Millisecond || (&alerts.Engine{}).IntervalOrDefault() != alerts.DefaultInterval {
		t.Fatal("interval")
	}
}
