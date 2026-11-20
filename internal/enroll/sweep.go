package enroll

import (
	"context"
	"log/slog"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

// Sweep defaults.
const (
	DefaultSweepInterval = time.Minute
	sweepBatch           = 500
)

// Sweep follows unfinished enrollments on one replica (a leased worker):
// it reads their progress from inventory, links joined nodes and expires
// enrollments inventory no longer knows after their expiry.
type Sweep struct {
	Service  *Service
	Interval time.Duration
	Log      *slog.Logger
}

// Run sweeps until ctx ends.
func (w *Sweep) Run(ctx context.Context) {
	iv := w.Interval
	if iv <= 0 {
		iv = DefaultSweepInterval
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		w.Once(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Once runs one sweep pass.
func (w *Sweep) Once(ctx context.Context) {
	rows, err := w.Service.Repo.ListActiveEnrollments(ctx, sweepBatch)
	if err != nil {
		if w.Log != nil {
			w.Log.Warn("enrollment sweep", "err", err)
		}
		return
	}
	byTenant := map[string][]repo.Enrollment{}
	var order []string
	for _, r := range rows {
		if _, ok := byTenant[r.TenantID]; !ok {
			order = append(order, r.TenantID)
		}
		byTenant[r.TenantID] = append(byTenant[r.TenantID], r)
	}
	for _, tid := range order {
		if ctx.Err() != nil {
			return
		}
		tctx := authz.WithSubjects(ctx, authz.Worker(tid, "enrollment-sweep"))
		if _, stale := w.Service.refresh(tctx, tid, byTenant[tid]); stale && w.Log != nil {
			w.Log.Warn("enrollment sweep: inventory unavailable", "tenant", tid)
		}
	}
}
