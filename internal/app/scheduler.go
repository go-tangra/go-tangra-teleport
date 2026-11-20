package app

import (
	"context"

	"google.golang.org/grpc"

	schedulerv1 "github.com/go-tangra/go-tangra-scheduler/sdk/v4/api/proto/scheduler/v1"
	"github.com/go-tangra/go-tangra-scheduler/sdk/v4/pkg/schedulerclient"
	sdktask "github.com/go-tangra/go-tangra-scheduler/sdk/v4/pkg/taskexec"
	"github.com/go-tangra/go-tangra/v4/authn"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/tasks"
)

// wireScheduler serves scheduler.v1.TaskExecutor (always: the mesh policy
// admits only svc/scheduler for ExecuteTask and the SDK server re-checks the
// verified peer) and, when task_scheduler.enabled, keeps the module's task
// types registered with the scheduler (contracts/events-and-tasks.md).
// Adapted from go-tangra-signing-v4 internal/app/scheduler.go. The leased
// workers (health monitor, watchers, alert poller, offline sweep) keep
// running without the scheduler (FR-034).
func (a *App) wireScheduler() {
	cfg := a.Cfg
	a.Tasks = &tasks.Runner{Store: a.Repo, Clusters: a.Clusters, Provisioning: a.Provisioning, Log: a.Log}
	scheduler := cfg.TaskScheduler.Service
	if scheduler == "" {
		scheduler = sdktask.DefaultScheduler
	}
	schedulerv1.RegisterTaskExecutorServer(a.Freya.GRPC(), sdktask.NewServer(a.Tasks.Handlers(), sdktask.Options{
		Caller: schedulerCaller(cfg.Config.TrustDomain), Scheduler: scheduler, Platform: tasks.Platform(), Log: a.Log,
	}))
	if !cfg.TaskScheduler.Enabled {
		return
	}
	reg := &schedulerclient.Registrar{
		Dial: func(ctx context.Context) (grpc.ClientConnInterface, error) {
			return a.Freya.Client(ctx, scheduler)
		},
		Types: tasks.Descriptors(),
		Log:   a.Log,
	}
	a.AddWorker("scheduler-registrar", reg.Run)
}

// schedulerCaller returns the verified peer's service name, only for a peer
// of the module's own trust domain.
func schedulerCaller(trustDomain string) func(ctx context.Context) (string, bool) {
	return func(ctx context.Context) (string, bool) {
		p, ok := authn.FromContext(ctx)
		if !ok || p.ID.TrustDomain() != trustDomain {
			return "", false
		}
		return p.ID.ServiceName(), true
	}
}

// wireTenantLifecycle consumes tenant-deleted events from
// events.tenant_stream (when configured) as a leased worker: the tenant's
// registrations and credentials are removed, Teleport is untouched (T118).
func (a *App) wireTenantLifecycle() {
	ev := a.Cfg.Events
	if ev.TenantStream == "" {
		return
	}
	c := &events.TenantConsumer{Bus: a.Bus, Stream: ev.TenantStream, Type: ev.TenantDeletedType, Log: a.Log,
		Handle: func(ctx context.Context, tenantID string) error {
			_, err := a.Clusters.PurgeTenant(ctx, tenantID)
			return err
		}}
	a.AddLeasedWorker("tenant-lifecycle", c.Run)
}
