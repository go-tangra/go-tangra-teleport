package resources_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/gravitational/trace"

	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/lease"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/resources"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// eventually polls cond (the watch runs in its own goroutine).
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func watcher(e *ct.Env, l *resources.Linker) *resources.Watcher {
	return &resources.Watcher{Clusters: e.Service, Repo: e.Repo, Linker: l, Events: e.Events, Now: e.Now,
		Cache: &teleportapi.Cache{KV: teleportapi.NewMemoryKV()}, Backoff: 10 * time.Millisecond}
}

func snapshot(t *testing.T, e *ct.Env, clusterID, name string) repo.ResourceSnapshot {
	t.Helper()
	snaps, _ := e.Repo.ListSnapshots(context.Background(), ct.TenantA, clusterID)
	for _, s := range snaps {
		if s.TeleportName == name {
			return s
		}
	}
	return repo.ResourceSnapshot{}
}

// The watcher resynchronises on (re)start, marks a deleted server offline
// and a heartbeat online again, and follows registered clusters.
func TestWatcherTracksServers(t *testing.T) {
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	e.Teleport.Resources = []teleportapi.Resource{{Kind: teleportapi.KindNode, Name: "n1", Hostname: "web-1", Addr: "10.0.0.5:3022", Version: "19.0.1"}}
	w := watcher(e, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); w.Stop() }()
	if n := w.RunOnce(ctx); n != 1 {
		t.Fatalf("watching %d clusters", n)
	}
	eventually(t, "resync", func() bool { return snapshot(t, e, c.ID, "n1").Online })
	s := snapshot(t, e, c.ID, "n1")
	if s.Hostname != "web-1" || s.AgentVersion != "19.0.1" || !s.LastSeenAt.Equal(e.Now()) || s.Kind != repo.KindNode {
		t.Fatalf("snapshot %+v", s)
	}
	if len(e.Events.OfType(events.ResourceOnline)) != 1 {
		t.Fatal("no online event")
	}

	// A server delete (heartbeat expiry) marks it offline.
	e.Advance(time.Minute)
	e.Teleport.Emit(teleportapi.WatchEvent{Op: teleportapi.OpDelete, Kind: teleportapi.KindNode, Name: "n1"})
	eventually(t, "offline", func() bool { return !snapshot(t, e, c.ID, "n1").Online })
	if s := snapshot(t, e, c.ID, "n1"); !s.OfflineSince.Equal(e.Now()) {
		t.Fatalf("offline since %v", s.OfflineSince)
	}
	if ev := e.Events.OfType(events.ResourceOffline); len(ev) != 1 || ev[0].Payload.(events.Resource).ResourceID != s.ID {
		t.Fatalf("offline events %+v", ev)
	}
	// A delete of an offline or unknown server changes nothing.
	e.Teleport.Emit(teleportapi.WatchEvent{Op: teleportapi.OpDelete, Kind: teleportapi.KindNode, Name: "n1"})
	e.Teleport.Emit(teleportapi.WatchEvent{Op: teleportapi.OpDelete, Kind: teleportapi.KindNode, Name: "ghost"})
	// A new app server comes online; a role change invalidates the cache.
	e.Teleport.Emit(teleportapi.WatchEvent{Op: teleportapi.OpPut, Kind: teleportapi.KindApp, Name: "grafana",
		Resource: teleportapi.Resource{Kind: teleportapi.KindApp, Hostname: "apps-1"}})
	e.Teleport.Emit(teleportapi.WatchEvent{Op: teleportapi.OpPut, Kind: "role", Name: "access"})
	eventually(t, "app online", func() bool { return snapshot(t, e, c.ID, "grafana").Kind == repo.KindApp })
	// The heartbeat returns: online again, offline_since cleared.
	e.Teleport.Emit(teleportapi.WatchEvent{Op: teleportapi.OpPut, Kind: teleportapi.KindNode, Name: "n1",
		Resource: teleportapi.Resource{Kind: teleportapi.KindNode, Hostname: "web-1"}})
	eventually(t, "online again", func() bool { return snapshot(t, e, c.ID, "n1").Online })
	if s := snapshot(t, e, c.ID, "n1"); !s.OfflineSince.IsZero() {
		t.Fatalf("still offline since %v", s.OfflineSince)
	}
	if len(e.Events.OfType(events.ResourceOffline)) != 1 || len(e.Events.OfType(events.ResourceOnline)) != 3 {
		t.Fatalf("events %+v", e.Events.All())
	}

	// A dropped stream reopens and resynchronises: a server that vanished
	// while nobody watched is offline.
	e.Teleport.Resources = nil
	e.Teleport.EndWatches(trace.ConnectionProblem(nil, "stream reset"))
	eventually(t, "resync after reopen", func() bool { return !snapshot(t, e, c.ID, "grafana").Online })

	// A removed cluster's watch stops.
	if err := e.Service.Remove(ct.As(ct.TenantA, ct.Admin), c.ID); err != nil {
		t.Fatal(err)
	}
	if n := w.RunOnce(ctx); n != 0 {
		t.Fatalf("still watching %d", n)
	}
	eventually(t, "watch closed", func() bool { return e.Teleport.Watchers() == 0 })
}

// Two replicas: the lease lets only one watch.
func TestWatcherSingleOwnerUnderLease(t *testing.T) {
	e := ct.New(t, nil)
	e.Register(t, ct.TenantA, "prod")
	kv := lease.NewMemory()
	a, b := watcher(e, nil), watcher(e, nil)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	started := make(chan struct{})
	go func() {
		defer wg.Done()
		_, _ = lease.Run(ctx, kv, "teleport:lease:resource-watcher", lease.Options{}, func(ctx context.Context) {
			close(started)
			a.Run(ctx)
		})
	}()
	<-started
	eventually(t, "first watch", func() bool { return e.Teleport.Watchers() == 1 })
	ran, err := lease.Run(ctx, kv, "teleport:lease:resource-watcher", lease.Options{}, b.Run)
	if ran || err != nil {
		t.Fatalf("second replica ran=%v err=%v", ran, err)
	}
	if b.Watching() != 0 || e.Teleport.Watchers() != 1 {
		t.Fatalf("second replica watches %d; %d watches open", b.Watching(), e.Teleport.Watchers())
	}
	cancel()
	wg.Wait()
	if a.Watching() != 0 {
		t.Fatal("watches survive the lease")
	}
}

// The sweep flags a resource offline past the threshold once, alerts once,
// and an online resource clears the flag.
func TestSweepFlagsOnceAndAlerts(t *testing.T) {
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	rule := repo.AlertRule{ID: store.NewID(), TenantID: ct.TenantA, Name: "offline", ConditionKind: repo.ConditionResourceOffline,
		Recipients: repo.Recipients{UserIDs: []string{"u-ops"}}, Enabled: true}
	if err := e.Repo.CreateAlertRule(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	cl, _ := e.Repo.GetCluster(context.Background(), ct.TenantA, c.ID)
	sn, err := e.Repo.UpsertSnapshot(context.Background(), repo.ResourceSnapshot{TenantID: ct.TenantA, ClusterID: c.ID, Kind: repo.KindNode,
		TeleportName: "n1", Hostname: "web-1", Online: false, OfflineSince: e.Now()})
	if err != nil {
		t.Fatal(err)
	}
	sweep := &resources.Sweep{Repo: e.Repo, Events: e.Events, Now: e.Now,
		Alerter: resources.NotifyAlerter{Notify: e.Notify, Recipients: clustersRecipients(e)}}
	e.Advance(time.Duration(cl.Settings.OfflineThresholdMinutes-1) * time.Minute)
	if n := sweep.RunOnce(context.Background()); n != 0 {
		t.Fatal("flagged before the threshold")
	}
	e.Advance(time.Minute)
	if n := sweep.RunOnce(context.Background()); n != 1 {
		t.Fatalf("flagged %d", n)
	}
	if n := sweep.RunOnce(context.Background()); n != 0 {
		t.Fatal("flagged twice")
	}
	got, _ := e.Repo.GetSnapshot(context.Background(), ct.TenantA, sn.ID)
	if !got.FlaggedAt.Equal(e.Now()) {
		t.Fatalf("flagged at %v", got.FlaggedAt)
	}
	alerts := e.Notify.OfTemplate(notify.TemplateAlert)
	if len(alerts) != 1 || alerts[0].To != "u-ops" || alerts[0].Vars["resource"] != "n1" || alerts[0].Vars["condition"] != repo.ConditionResourceOffline {
		t.Fatalf("alerts %+v", alerts)
	}
	if len(e.Events.OfType(events.ResourceFlagged)) != 1 {
		t.Fatal("no flagged event")
	}

	// Coming back online clears the flag.
	e.Teleport.Resources = []teleportapi.Resource{{Kind: teleportapi.KindNode, Name: "n1", Hostname: "web-1"}}
	w := watcher(e, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); w.Stop() }()
	w.RunOnce(ctx)
	eventually(t, "online", func() bool {
		s, _ := e.Repo.GetSnapshot(context.Background(), ct.TenantA, sn.ID)
		return s.Online && s.FlaggedAt.IsZero()
	})

	// Alerts off: flagged without an alert.
	cl, _ = e.Repo.GetCluster(context.Background(), ct.TenantA, c.ID)
	cl.Settings.AlertsEnabled = false
	_, _ = e.Repo.UpdateCluster(context.Background(), cl)
	_, _ = e.Repo.UpsertSnapshot(context.Background(), repo.ResourceSnapshot{TenantID: ct.TenantA, ClusterID: c.ID, Kind: repo.KindDB,
		TeleportName: "pg", OfflineSince: e.Now().Add(-time.Hour)})
	if n := sweep.RunOnce(context.Background()); n != 1 || len(e.Notify.OfTemplate(notify.TemplateAlert)) != 1 {
		t.Fatalf("flagged %d, alerts %d", n, len(e.Notify.OfTemplate(notify.TemplateAlert)))
	}
}
