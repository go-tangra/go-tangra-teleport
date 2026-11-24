package resources

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// Change watching and offline detection (research D7). Both run as leased
// workers (app AddLeasedWorker), so one replica owns every cluster's watch
// and the sweep at a time and they keep working while the scheduler is down
// (FR-034).
//
// The Watcher holds one Teleport watch per registered cluster on the server
// kinds plus locks, users and roles. On each (re)start it resynchronises the
// cluster's snapshots from a full listing; afterwards a server put marks the
// resource online (clearing an offline flag) and a server delete — Teleport
// deletes a server whose heartbeat expired — marks it offline. Lock, user
// and role changes invalidate the read cache, so changes made with tctl show
// up at once. New hosts and changed addresses are matched by the Linker.
//
// The Sweep flags resources offline longer than the cluster's threshold
// (settings.offline_threshold_minutes, default 15) once, publishes
// teleport.resource.flagged and raises a resource_offline alert when the
// cluster's alerts are enabled.

// Defaults.
const (
	DefaultRescan         = 30 * time.Second // registered clusters are re-read this often
	DefaultBackoff        = 5 * time.Second  // a dropped watch is reopened after this
	DefaultSweepInterval  = time.Minute
	DefaultThresholdMins  = 15
	resyncPage            = 1000
	maxResync             = 10000 // plan Scale: 10k resources per cluster
	conditionResourceKind = repo.ConditionResourceOffline
)

// Alerter delivers a module-condition alert (resource_offline) about a
// cluster; key identifies the occurrence for de-duplication.
type Alerter interface {
	Alert(ctx context.Context, c repo.Cluster, condition, key string, vars map[string]string)
}

// NotifyAlerter sends teleport.alert to the recipients of the tenant's
// rules for the condition (the US3 default; US4 wires the alert engine,
// which de-duplicates deliveries).
type NotifyAlerter struct {
	Notify     notify.Notifier
	Recipients clusters.RecipientsFunc
	Log        *slog.Logger
}

// Alert implements Alerter.
func (a NotifyAlerter) Alert(ctx context.Context, c repo.Cluster, condition, key string, vars map[string]string) {
	if a.Notify == nil || a.Recipients == nil {
		return
	}
	to := a.Recipients(ctx, c.TenantID, c.ID, condition)
	if err := notify.SendEach(ctx, a.Notify, notify.Message{TenantID: c.TenantID, Template: notify.TemplateAlert, Vars: vars, CorrelationID: key}, to); err != nil && a.Log != nil {
		a.Log.WarnContext(ctx, "alert not sent", "cluster_id", c.ID, "condition", condition, "err", err)
	}
}

// Watcher keeps every registered cluster's snapshots current.
type Watcher struct {
	Clusters *clusters.Service // pool and store
	Repo     Store
	Linker   *Linker
	Cache    *teleportapi.Cache
	Events   events.Publisher
	Log      *slog.Logger
	Now      func() time.Time
	Rescan   time.Duration
	Backoff  time.Duration

	mu      sync.Mutex
	running map[string]context.CancelFunc
	wg      sync.WaitGroup
}

func (w *Watcher) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}

func (w *Watcher) log() *slog.Logger {
	if w.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return w.Log
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// Run watches until ctx ends (the leased worker body).
func (w *Watcher) Run(ctx context.Context) {
	t := time.NewTicker(orDefault(w.Rescan, DefaultRescan))
	defer t.Stop()
	for {
		w.RunOnce(ctx)
		select {
		case <-ctx.Done():
			w.Stop()
			return
		case <-t.C:
		}
	}
}

// RunOnce starts a watch for every registered cluster without one and stops
// the watches of removed clusters; it returns the number of watched clusters.
func (w *Watcher) RunOnce(ctx context.Context) int {
	all, err := w.Repo.AllClusters(ctx)
	if err != nil {
		if ctx.Err() == nil {
			w.log().WarnContext(ctx, "resource watcher: cluster list failed", "err", err)
		}
		return w.Watching()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.running == nil {
		w.running = map[string]context.CancelFunc{}
	}
	present := map[string]bool{}
	for _, c := range all {
		present[c.ID] = true
		if _, ok := w.running[c.ID]; ok || ctx.Err() != nil {
			continue
		}
		cctx, cancel := context.WithCancel(ctx)
		w.running[c.ID] = cancel
		w.wg.Add(1)
		go func(c repo.Cluster) {
			defer w.wg.Done()
			w.watch(cctx, c)
		}(c)
	}
	for id, cancel := range w.running {
		if !present[id] {
			cancel()
			delete(w.running, id)
		}
	}
	return len(w.running)
}

// Watching is the number of clusters with a running watch loop.
func (w *Watcher) Watching() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.running)
}

// Stop ends every watch and waits for them.
func (w *Watcher) Stop() {
	w.mu.Lock()
	for id, cancel := range w.running {
		cancel()
		delete(w.running, id)
	}
	w.mu.Unlock()
	w.wg.Wait()
}

// watch keeps one cluster's watch open until ctx ends, reopening it after a
// drop. The registration is re-read each time (a rotated credential opens a
// new connection); a removed cluster ends the loop.
func (w *Watcher) watch(ctx context.Context, c repo.Cluster) {
	for ctx.Err() == nil {
		fresh, err := w.Repo.GetCluster(ctx, c.TenantID, c.ID)
		if errors.Is(err, repo.ErrNotFound) {
			return
		}
		if err == nil {
			c = fresh
			if err = w.watchOnce(ctx, c); err != nil && ctx.Err() == nil {
				w.log().InfoContext(ctx, "resource watch ended; reopening", "cluster_id", c.ID, "reason", clusters.ReasonOf(err))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(orDefault(w.Backoff, DefaultBackoff)):
		}
	}
}

// state is one open watch's view of the cluster's snapshots.
type state struct {
	c     repo.Cluster
	cl    teleportapi.Client
	snaps map[string]repo.ResourceSnapshot // by kind/name
}

func (w *Watcher) watchOnce(ctx context.Context, c repo.Cluster) error {
	cl, err := w.Clusters.Pool.Get(ctx, clusters.KeyFor(c))
	if err != nil {
		return err
	}
	tw, err := cl.Watch(ctx, teleportapi.WatchKinds)
	if err != nil {
		return err
	}
	defer func() { _ = tw.Close() }()
	st := &state{c: c, cl: cl}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tw.Done():
			return tw.Error()
		case ev, ok := <-tw.Events():
			if !ok {
				return tw.Error()
			}
			if err := w.handle(ctx, st, ev); err != nil {
				return err
			}
		}
	}
}

// handle applies one watch event. An error ends the watch (it is reopened
// and resynchronised).
func (w *Watcher) handle(ctx context.Context, st *state, ev teleportapi.WatchEvent) error {
	if ev.Op == teleportapi.OpInit {
		return w.Resync(ctx, st)
	}
	kind := ModuleKind(ev.Kind)
	if kind == "" {
		_ = w.Cache.Invalidate(ctx, st.c.TenantID, st.c.ID) // lock, user or role
		return nil
	}
	if st.snaps == nil {
		return w.Resync(ctx, st)
	}
	if ev.Op == teleportapi.OpPut {
		ev.Resource.Name = ev.Name
		return w.online(ctx, st, kind, ev.Resource)
	}
	sn, ok := st.snaps[key(kind, ev.Name)]
	if !ok || !sn.Online {
		return nil
	}
	return w.offline(ctx, st, sn)
}

// Resync reads every server kind and reconciles the snapshots: listed
// resources are online, snapshots no longer listed go offline.
func (w *Watcher) Resync(ctx context.Context, st *state) error {
	snaps, err := w.Repo.ListSnapshots(ctx, st.c.TenantID, st.c.ID)
	if err != nil {
		return err
	}
	st.snaps = make(map[string]repo.ResourceSnapshot, len(snaps))
	for _, sn := range snaps {
		st.snaps[key(sn.Kind, sn.TeleportName)] = sn
	}
	seen := map[string]bool{}
	for _, kind := range repo.ResourceKinds {
		next := ""
		for n := 0; n < maxResync; {
			p, err := st.cl.ListResources(ctx, TeleportKind(kind), teleportapi.ListOptions{Limit: resyncPage, Next: next})
			if err != nil {
				return err
			}
			for _, r := range p.Items {
				seen[key(kind, r.Name)] = true
				if err := w.online(ctx, st, kind, r); err != nil {
					return err
				}
			}
			n += len(p.Items)
			if p.Next == "" {
				break
			}
			next = p.Next
		}
	}
	for k, sn := range st.snaps {
		if sn.Online && !seen[k] {
			if err := w.offline(ctx, st, sn); err != nil {
				return err
			}
		}
	}
	_ = w.Cache.Invalidate(ctx, st.c.TenantID, st.c.ID)
	return nil
}

// online records a live resource.
func (w *Watcher) online(ctx context.Context, st *state, kind string, r teleportapi.Resource) error {
	k := key(kind, r.Name)
	prev, known := st.snaps[k]
	sn := SnapshotOf(st.c, kind, r, w.now())
	sn.ID = prev.ID
	saved, err := w.Repo.UpsertSnapshot(ctx, sn)
	if err != nil {
		return err
	}
	st.snaps[k] = saved
	if !known || !prev.Online {
		events.Emit(ctx, w.Events, st.c.TenantID, events.ResourceOnline, events.Resource{ClusterID: st.c.ID, ResourceID: saved.ID, Kind: kind})
	}
	if w.Linker != nil && (!known || prev.Hostname != saved.Hostname || prev.Addr != saved.Addr) {
		if _, err := w.Linker.Match(ctx, saved); err != nil && !errors.Is(err, ErrDirectoryUnavailable) {
			w.log().WarnContext(ctx, "resource link matching failed", "cluster_id", st.c.ID, "resource_id", saved.ID, "err", err)
		}
	}
	return nil
}

// offline records a resource whose heartbeat expired.
func (w *Watcher) offline(ctx context.Context, st *state, sn repo.ResourceSnapshot) error {
	sn.Online, sn.OfflineSince, sn.FlaggedAt = false, w.now(), time.Time{}
	saved, err := w.Repo.UpsertSnapshot(ctx, sn)
	if err != nil {
		return err
	}
	st.snaps[key(sn.Kind, sn.TeleportName)] = saved
	events.Emit(ctx, w.Events, st.c.TenantID, events.ResourceOffline, events.Resource{ClusterID: st.c.ID, ResourceID: saved.ID, Kind: saved.Kind})
	return nil
}

// ---- sweep

// Sweep flags resources offline past their cluster's threshold.
type Sweep struct {
	Repo     Store
	Events   events.Publisher
	Alerter  Alerter
	Log      *slog.Logger
	Now      func() time.Time
	Interval time.Duration // default 1 minute
}

// Run sweeps every interval until ctx ends.
func (s *Sweep) Run(ctx context.Context) {
	t := time.NewTicker(orDefault(s.Interval, DefaultSweepInterval))
	defer t.Stop()
	for {
		s.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunOnce flags every resource past its threshold and returns how many it flagged.
func (s *Sweep) RunOnce(ctx context.Context) int {
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	all, err := s.Repo.AllClusters(ctx)
	if err != nil {
		if ctx.Err() == nil && s.Log != nil {
			s.Log.WarnContext(ctx, "offline sweep: cluster list failed", "err", err)
		}
		return 0
	}
	flagged := 0
	for _, c := range all {
		mins := c.Settings.OfflineThresholdMinutes
		if mins <= 0 {
			mins = DefaultThresholdMins
		}
		snaps, err := s.Repo.ListSnapshots(ctx, c.TenantID, c.ID)
		if err != nil {
			continue
		}
		for _, sn := range snaps {
			if sn.Online || sn.OfflineSince.IsZero() || !sn.FlaggedAt.IsZero() || now.Sub(sn.OfflineSince) < time.Duration(mins)*time.Minute {
				continue
			}
			sn.FlaggedAt = now
			if _, err := s.Repo.UpsertSnapshot(ctx, sn); err != nil {
				continue
			}
			flagged++
			events.Emit(ctx, s.Events, c.TenantID, events.ResourceFlagged, events.Resource{ClusterID: c.ID, ResourceID: sn.ID, Kind: sn.Kind})
			if s.Alerter != nil && c.Settings.AlertsEnabled {
				s.Alerter.Alert(ctx, c, conditionResourceKind, sn.ID+"@"+sn.OfflineSince.Format(time.RFC3339), map[string]string{
					"condition": conditionResourceKind, "cluster_id": c.ID, "display_name": c.DisplayName, "cluster_name": c.ClusterName,
					"resource_id": sn.ID, "resource": sn.TeleportName, "kind": sn.Kind, "hostname": sn.Hostname,
					"offline_since": sn.OfflineSince.Format(time.RFC3339), "time": now.Format(time.RFC3339),
				})
			}
		}
	}
	return flagged
}
