package clusters_test

import (
	"context"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

// One monitor pass checks every tenant's clusters as a worker pinned to the
// cluster's tenant; three failing passes mark a cluster unreachable.
func TestMonitorChecksEveryTenant(t *testing.T) {
	e := ct.New(t, nil)
	a := e.Register(t, ct.TenantA, "prod")
	b := e.Register(t, ct.TenantB, "prod")
	m := &clusters.Monitor{Service: e.Service, Concurrency: 2}
	pings := e.Teleport.Calls("Ping")
	if n := m.RunOnce(context.Background()); n != 2 || e.Teleport.Calls("Ping") != pings+2 {
		t.Fatalf("checked %d, pings %d", n, e.Teleport.Calls("Ping")-pings)
	}
	e.Teleport.SetErr(down)
	for range 3 {
		e.Advance(time.Minute)
		m.RunOnce(context.Background())
	}
	for _, id := range []struct{ tenant, id string }{{ct.TenantA, a.ID}, {ct.TenantB, b.ID}} {
		c, err := e.Repo.GetCluster(context.Background(), id.tenant, id.id)
		if err != nil || c.Status != repo.StatusUnreachable {
			t.Fatalf("%s: %v %s", id.tenant, err, c.Status)
		}
	}
	var tenants []string
	for _, ev := range e.Events.OfType(events.ClusterStatusChanged) {
		tenants = append(tenants, ev.TenantID)
	}
	if len(tenants) != 2 || tenants[0] == tenants[1] {
		t.Fatalf("status events per tenant: %v", tenants)
	}
}

// Run ticks on its interval and stops with its context.
func TestMonitorRunStops(t *testing.T) {
	e := ct.New(t, nil)
	e.Register(t, ct.TenantA, "prod")
	m := &clusters.Monitor{Service: e.Service, Interval: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	pings := e.Teleport.Calls("Ping")
	go func() { m.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for e.Teleport.Calls("Ping") < pings+2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("monitor did not stop")
	}
	if e.Teleport.Calls("Ping") < pings+2 {
		t.Fatal("monitor did not tick")
	}
	if (&clusters.Monitor{}).IntervalOrDefault() != clusters.DefaultInterval || clusters.DefaultInterval != time.Minute {
		t.Fatal("default interval")
	}
}
