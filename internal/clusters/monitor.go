package clusters

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

// DefaultInterval is the health-check period (contracts/events-and-tasks.md
// teleport:health-check: every minute).
const DefaultInterval = time.Minute

// defaultConcurrency bounds the clusters checked at once.
const defaultConcurrency = 4

// Monitor is the health loop. It runs as a leased worker (app
// AddLeasedWorker), so one replica checks every tenant's clusters at a time
// and status, events and notifications keep flowing when the scheduler is
// down (FR-034). Each cluster is checked as a worker pinned to its tenant.
// The consecutive-failure counts live in the Service: a lease handover
// restarts them, which delays an unreachable verdict by at most one window.
//
// The pattern for the later loops (watchers, alert pollers, offline sweep):
// a struct holding the domain service, Run(ctx) ticking until ctx ends, and
// RunOnce(ctx) doing one pass so tests drive it with an injected clock.
type Monitor struct {
	Service     *Service
	Interval    time.Duration // default 1 minute
	Concurrency int           // default 4
}

// IntervalOrDefault is the effective period.
func (m *Monitor) IntervalOrDefault() time.Duration {
	if m.Interval <= 0 {
		return DefaultInterval
	}
	return m.Interval
}

// Run checks every cluster each interval until ctx ends (starting at once).
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(m.IntervalOrDefault())
	defer t.Stop()
	for {
		m.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunOnce checks every registered cluster once and returns how many it checked.
func (m *Monitor) RunOnce(ctx context.Context) int {
	s := m.Service
	all, err := s.Repo.AllClusters(ctx)
	if err != nil {
		if ctx.Err() == nil {
			s.log().WarnContext(ctx, "health monitor: cluster list failed", "err", err)
		}
		return 0
	}
	n := m.Concurrency
	if n <= 0 {
		n = defaultConcurrency
	}
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for _, c := range all {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(c repo.Cluster) {
			defer func() { <-sem; wg.Done() }()
			wctx := authz.WithSubjects(ctx, authz.Worker(c.TenantID, "health-monitor"))
			if _, err := s.CheckCluster(wctx, c); err != nil && ctx.Err() == nil && !errors.Is(err, repo.ErrNotFound) {
				s.log().WarnContext(ctx, "health check not recorded", "cluster_id", c.ID, "err", err)
			}
		}(c)
	}
	wg.Wait()
	return len(all)
}
