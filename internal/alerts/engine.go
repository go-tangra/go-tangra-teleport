package alerts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/auditlog"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// Defaults (research D8, SC-005).
const (
	DefaultInterval    = 30 * time.Second
	DefaultSettle      = 10 * time.Second // events younger than this wait for the next poll
	DefaultLookback    = 5 * time.Minute  // where a cluster without a cursor starts
	DefaultMaxHold     = time.Hour        // a refused delivery is retried this long
	DefaultPageSize    = 500
	DefaultMaxPages    = 10
	DeliveryRetention  = 30 * 24 * time.Hour
	defaultConcurrency = 4
	pruneEvery         = time.Hour
	maxWindowKey       = 128
	workerName         = "alert-poller"
)

// Store is what the engine reads and writes (repo.Store satisfies it).
type Store interface {
	AllClusters(ctx context.Context) ([]repo.Cluster, error)
	ListAlertRules(ctx context.Context, tenantID string) ([]repo.AlertRule, error)
	GetAlertCursor(ctx context.Context, tenantID, clusterID string) (repo.AlertCursor, error)
	PutAlertCursor(ctx context.Context, c repo.AlertCursor) error
	RecordDelivery(ctx context.Context, d repo.AlertDelivery) error
	ReleaseDelivery(ctx context.Context, tenantID, ruleID, clusterID, windowKey string) error
	PruneDeliveries(ctx context.Context, before time.Time) (int, error)
}

// Engine is the alert poller. It runs as a leased worker (app
// AddLeasedWorker "alert-poller"), so one replica evaluates every tenant's
// clusters at a time, and keeps alerting while the scheduler is down
// (FR-034).
//
// Each poll reads a cluster's events oldest first from its cursor (the last
// processed event's time and id, in alert_cursor) up to now minus Settle,
// restricted to the Teleport types of its enabled rules. Events at the
// cursor's own instant are skipped up to and including the cursor event, so
// nothing is processed twice and nothing in between is skipped. The cursor
// moves only past events whose deliveries are done: when a delivery cannot
// be sent (notification unavailable) its de-duplication record is released,
// the cursor is held at the event before and the next poll retries. A
// delivery still refused after MaxHold is dropped (logged) so one broken
// recipient cannot stall a cluster's alerting for ever. Recipients reached
// before a failure may get the alert again on the retry (at least once).
//
// Any-match rules deliver once per event; burst rules count a user's
// matching events within the rule's window and deliver once per user and
// window (window_key "burst:<user>:<window start>"). The burst history is
// kept in memory per cluster; after a restart or lease handover it is
// rebuilt by reading the largest burst window before the cursor once.
// Deliveries are de-duplicated in alert_delivery per (rule, cluster,
// window), which also makes Alert (module conditions) idempotent per key.
type Engine struct {
	Clusters *clusters.Service // the connection gate (worker subject, audit:read)
	Repo     Store
	Notify   notify.Notifier
	Audit    audit.Recorder
	Log      *slog.Logger
	Now      func() time.Time

	Interval    time.Duration
	Settle      time.Duration
	Lookback    time.Duration
	MaxHold     time.Duration
	PageSize    int
	MaxPages    int
	Concurrency int

	mu     sync.Mutex
	hist   map[string]*history // per cluster
	held   map[string]hold     // per cluster: the event a delivery is held on
	pruned time.Time
}

type hold struct {
	eventID string
	since   time.Time
}

// seen is one processed event in a burst history.
type seen struct {
	at   time.Time
	user string
	typ  string
}

type history struct {
	at     repo.AlertCursor // the cursor the history is consistent with
	events []seen
}

func orDur(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

func orInt(n, def int) int {
	if n <= 0 {
		return def
	}
	return n
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func (e *Engine) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.New(slog.DiscardHandler)
}

// IntervalOrDefault is the effective poll period.
func (e *Engine) IntervalOrDefault() time.Duration { return orDur(e.Interval, DefaultInterval) }

// Run polls every interval until ctx ends (starting at once).
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(e.IntervalOrDefault())
	defer t.Stop()
	for {
		e.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunOnce polls every registered cluster once (and prunes deliveries older
// than 30 days hourly); it returns how many clusters it polled.
func (e *Engine) RunOnce(ctx context.Context) int {
	now := e.now()
	e.mu.Lock()
	prune := now.Sub(e.pruned) >= pruneEvery
	if prune {
		e.pruned = now
	}
	e.mu.Unlock()
	if prune {
		if _, err := e.Repo.PruneDeliveries(ctx, now.Add(-DeliveryRetention)); err != nil && ctx.Err() == nil {
			e.log().WarnContext(ctx, "alert poller: delivery prune failed", "err", err)
		}
	}
	all, err := e.Repo.AllClusters(ctx)
	if err != nil {
		if ctx.Err() == nil {
			e.log().WarnContext(ctx, "alert poller: cluster list failed", "err", err)
		}
		return 0
	}
	live := map[string]bool{}
	sem := make(chan struct{}, orInt(e.Concurrency, defaultConcurrency))
	var wg sync.WaitGroup
	for _, c := range all {
		if ctx.Err() != nil {
			break
		}
		live[c.ID] = true
		sem <- struct{}{}
		wg.Add(1)
		go func(c repo.Cluster) {
			defer func() { <-sem; wg.Done() }()
			if err := e.PollCluster(ctx, c); err != nil && ctx.Err() == nil {
				e.log().WarnContext(ctx, "alert poll held", "cluster_id", c.ID, "reason", clusters.ReasonOf(err))
			}
		}(c)
	}
	wg.Wait()
	e.mu.Lock()
	for id := range e.hist {
		if !live[id] {
			delete(e.hist, id)
		}
	}
	e.mu.Unlock()
	return len(all)
}

// rulesFor returns the tenant's enabled rules of condition that apply to c.
func rulesFor(rs []repo.AlertRule, c repo.Cluster, condition string) []repo.AlertRule {
	var out []repo.AlertRule
	for _, r := range rs {
		if r.Enabled && r.ConditionKind == condition && (r.ClusterID == "" || r.ClusterID == c.ID) {
			out = append(out, r)
		}
	}
	return out
}

func (e *Engine) history(id string) *history {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.hist[id]
}

func (e *Engine) setHistory(id string, h *history) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.hist == nil {
		e.hist = map[string]*history{}
	}
	if h == nil {
		delete(e.hist, id)
		return
	}
	e.hist[id] = h
}

func same(a, b repo.AlertCursor) bool {
	return a.LastEventID == b.LastEventID && a.LastEventTime.Equal(b.LastEventTime)
}

// at is an event's time at the store's precision (microseconds).
func at(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

// PollCluster evaluates one cluster's new events against its rules.
func (e *Engine) PollCluster(ctx context.Context, c repo.Cluster) error {
	now := e.now()
	ctx = authz.WithSubjects(ctx, authz.Worker(c.TenantID, workerName))
	all, err := e.Repo.ListAlertRules(ctx, c.TenantID)
	if err != nil {
		return err
	}
	var rules []repo.AlertRule
	if c.Settings.AlertsEnabled {
		rules = rulesFor(all, c, repo.ConditionTeleportEvent)
	}
	to := at(now.Add(-orDur(e.Settle, DefaultSettle)))
	cur, err := e.Repo.GetAlertCursor(ctx, c.TenantID, c.ID)
	switch {
	case errors.Is(err, repo.ErrNotFound):
		cur = repo.AlertCursor{ClusterID: c.ID, TenantID: c.TenantID, LastEventTime: at(now.Add(-orDur(e.Lookback, DefaultLookback)))}
	case err != nil:
		return err
	}
	if len(rules) == 0 {
		// Nothing to evaluate: follow the clock, so a rule enabled later
		// starts from now instead of replaying old events.
		e.setHistory(c.ID, nil)
		if !to.After(cur.LastEventTime) {
			return nil
		}
		return e.Repo.PutAlertCursor(ctx, repo.AlertCursor{ClusterID: c.ID, TenantID: c.TenantID, LastEventTime: to, UpdatedAt: now})
	}
	if !to.After(cur.LastEventTime) {
		return nil
	}
	var types []string
	var window time.Duration
	for _, r := range rules {
		types = append(types, r.EventTypes...)
		window = max(window, time.Duration(r.WindowMinutes)*time.Minute)
	}
	h := e.history(c.ID)
	from := cur.LastEventTime
	if h == nil || !same(h.at, cur) {
		h = &history{}
		from = from.Add(-window)
	}
	_, cl, err := e.Clusters.Client(ctx, c.ID, authz.AuditRead)
	if err != nil {
		return err
	}
	last := cur
	skipping := cur.LastEventID != "" // within the cursor's instant, until the cursor event
	// commit stores the cursor; the history is kept only when it is
	// complete up to it (a failed read may leave it short).
	commit := func(complete bool) error {
		h.at = last
		h.prune(last.LastEventTime.Add(-window))
		if !complete {
			h = nil
		}
		e.setHistory(c.ID, h)
		if same(last, cur) {
			return nil
		}
		return e.Repo.PutAlertCursor(ctx, repo.AlertCursor{ClusterID: c.ID, TenantID: c.TenantID, LastEventTime: last.LastEventTime,
			LastEventID: last.LastEventID, UpdatedAt: now})
	}
	q := teleportapi.EventQuery{From: from, To: to, Types: auditlog.TeleportTypes(types), Limit: orInt(e.PageSize, DefaultPageSize), Ascending: true}
	done, fresh := false, false
	for range orInt(e.MaxPages, DefaultMaxPages) {
		p, err := cl.SearchEvents(ctx, q)
		if err != nil {
			return errors.Join(err, commit(false))
		}
		for _, raw := range p.Items {
			n := auditlog.Normalize(raw)
			t := at(n.Time)
			old := t.Before(cur.LastEventTime)
			if t.Equal(cur.LastEventTime) && skipping {
				old = true
				skipping = n.ID != cur.LastEventID
			}
			if old {
				h.add(t, n)
				continue
			}
			if err := e.process(ctx, c, rules, h, n, t, now); err != nil {
				return errors.Join(err, commit(true))
			}
			h.add(t, n)
			last = repo.AlertCursor{ClusterID: c.ID, TenantID: c.TenantID, LastEventTime: t, LastEventID: n.ID}
			fresh = true
		}
		if p.Next == "" {
			done = true
			break
		}
		q.Next = p.Next
	}
	if done && !fresh {
		last = repo.AlertCursor{ClusterID: c.ID, TenantID: c.TenantID, LastEventTime: to}
	}
	return commit(true)
}

func (h *history) add(t time.Time, n auditlog.Event) {
	h.events = append(h.events, seen{at: t, user: strings.ToLower(n.User), typ: n.Type})
}

func (h *history) prune(before time.Time) {
	h.events = slices.DeleteFunc(h.events, func(s seen) bool { return s.at.Before(before) })
}

// count is the number of history events of types by user within (from, to].
func (h *history) count(types []string, user string, from, to time.Time) int {
	n := 0
	for _, s := range h.events {
		if s.user == user && s.at.After(from) && !s.at.After(to) && slices.Contains(types, s.typ) {
			n++
		}
	}
	return n
}

// process delivers what event n triggers (n is not in h yet).
func (e *Engine) process(ctx context.Context, c repo.Cluster, rules []repo.AlertRule, h *history, n auditlog.Event, t, now time.Time) error {
	for _, r := range rules {
		if !slices.Contains(r.EventTypes, n.Type) {
			continue
		}
		vars := eventVars(c, r, n)
		key := "event:" + n.ID
		if r.ThresholdCount > 0 {
			w := time.Duration(r.WindowMinutes) * time.Minute
			count := h.count(r.EventTypes, strings.ToLower(n.User), t.Add(-w), t) + 1
			if count < r.ThresholdCount {
				continue
			}
			vars["count"] = strconv.Itoa(count)
			key = "burst:" + strings.ToLower(n.User) + ":" + t.Truncate(w).Format(time.RFC3339)
		}
		err := e.deliver(ctx, c, r, key, vars)
		if err == nil {
			continue
		}
		if e.expired(c.ID, n.ID, now) {
			e.log().ErrorContext(ctx, "alert dropped after retries", "cluster_id", c.ID, "rule_id", r.ID, "reason", clusters.ReasonOf(err))
			continue
		}
		return err
	}
	e.clearHold(c.ID)
	return nil
}

// expired records a failed delivery on event id and reports whether it has
// been held longer than MaxHold.
func (e *Engine) expired(clusterID, eventID string, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.held == nil {
		e.held = map[string]hold{}
	}
	h, ok := e.held[clusterID]
	if !ok || h.eventID != eventID {
		e.held[clusterID] = hold{eventID: eventID, since: now}
		return false
	}
	return now.Sub(h.since) > orDur(e.MaxHold, DefaultMaxHold)
}

func (e *Engine) clearHold(clusterID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.held, clusterID)
}

func eventVars(c repo.Cluster, r repo.AlertRule, n auditlog.Event) map[string]string {
	return map[string]string{
		"condition": repo.ConditionTeleportEvent, "rule_id": r.ID, "rule_name": r.Name,
		"cluster_id": c.ID, "display_name": c.DisplayName, "cluster_name": c.ClusterName,
		"event_id": n.ID, "event_type": n.Type, "event_code": n.Code, "user": n.User, "resource": n.Resource,
		"summary": n.Summary, "time": n.Time.Format(time.RFC3339), "count": "1",
		"window_minutes": strconv.Itoa(r.WindowMinutes),
	}
}

// windowKey bounds a de-duplication key (hashing long ones).
func windowKey(k string) string {
	if len(k) <= maxWindowKey {
		return k
	}
	sum := sha256.Sum256([]byte(k))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// deliver sends rule r's alert once per (rule, cluster, key): the window is
// claimed first and released again when the send fails, so it is retried.
func (e *Engine) deliver(ctx context.Context, c repo.Cluster, r repo.AlertRule, key string, vars map[string]string) error {
	wk := windowKey(key)
	err := e.Repo.RecordDelivery(ctx, repo.AlertDelivery{ID: store.NewID(), TenantID: c.TenantID, RuleID: r.ID, ClusterID: c.ID,
		WindowKey: wk, DeliveredAt: e.now()})
	switch {
	case errors.Is(err, repo.ErrConflict): // delivered already
		return nil
	case errors.Is(err, repo.ErrNotFound): // the rule or cluster is gone
		return nil
	case err != nil:
		return err
	}
	var failed error
	if e.Notify == nil {
		failed = notify.ErrUnavailable
	}
	for _, to := range r.Recipients.UserIDs {
		if failed != nil {
			break
		}
		failed = e.Notify.Send(ctx, notify.Message{TenantID: c.TenantID, Template: notify.TemplateAlert, To: to, Vars: vars, CorrelationID: wk})
	}
	if failed != nil {
		if rerr := e.Repo.ReleaseDelivery(ctx, c.TenantID, r.ID, c.ID, wk); rerr != nil && !errors.Is(rerr, repo.ErrNotFound) {
			failed = errors.Join(failed, rerr)
		}
		return failed
	}
	clusters.Audit(ctx, e.Audit, audit.AlertDeliver, audit.TargetAlertRule, c.ID, r.ID, nil,
		map[string]any{"condition": r.ConditionKind, "window_key": wk, "recipients": len(r.Recipients.UserIDs)})
	return nil
}

// Alert implements resources.Alerter: it delivers a module-condition alert
// (resource_offline, cluster_unreachable, credential_expiring) about c to
// the tenant's enabled rules for condition, once per rule and key. A failed
// send is logged and not recorded, so the same key is delivered when the
// condition is raised again.
func (e *Engine) Alert(ctx context.Context, c repo.Cluster, condition, key string, vars map[string]string) {
	ctx = authz.WithSubjects(ctx, authz.Worker(c.TenantID, workerName))
	all, err := e.Repo.ListAlertRules(ctx, c.TenantID)
	if err != nil {
		e.log().WarnContext(ctx, "alert not sent: rules unavailable", "cluster_id", c.ID, "condition", condition)
		return
	}
	for _, r := range rulesFor(all, c, condition) {
		v := maps.Clone(vars)
		if v == nil {
			v = map[string]string{}
		}
		v["condition"], v["rule_id"], v["rule_name"] = condition, r.ID, r.Name
		if err := e.deliver(ctx, c, r, condition+":"+key, v); err != nil {
			e.log().WarnContext(ctx, "alert not sent", "cluster_id", c.ID, "condition", condition, "rule_id", r.ID, "reason", clusters.ReasonOf(err))
		}
	}
}
