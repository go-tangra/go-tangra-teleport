// Package tasks holds the scheduled task types the Teleport module executes
// for the scheduler module (contracts/events-and-tasks.md, "Scheduler task
// types"):
//
//   - teleport:health-check pings each of the tenant's clusters and records
//     status, counts, version and edition (the backstop of the leased health
//     monitor, research D7);
//   - teleport:credential-expiry evaluates each management credential without
//     dialling: warns once per stage and marks expired credentials (bot
//     renewal is deferred, research D2);
//   - teleport:sync-provisioning reconciles the managed users of each cluster
//     that has role mappings or managed users;
//   - teleport:purge-deprovisioned deletes managed users past their grace
//     period and removes their locks;
//   - teleport:token-gc prunes join-token metadata expired more than 7 days
//     ago and alert deliveries older than 30 days.
//
// Every type is tenant-scoped: it runs for the tenant carried in the task and
// touches only that tenant's rows, as the worker subject of that tenant. Every
// type is idempotent (re-running converges to the same state). A failed step
// answers Retry (the scheduler applies its retry policy) after the other
// clusters were handled; a malformed request answers Permanent. The SDK
// executor server verifies that the caller is the scheduler; handlers never
// log payloads.
package tasks

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-tangra/go-tangra-scheduler/sdk/v4/pkg/schedulerclient"
	sdk "github.com/go-tangra/go-tangra-scheduler/sdk/v4/pkg/taskexec"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/provisioning"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

// Task types.
const (
	TypeHealthCheck      = "teleport:health-check"
	TypeCredentialExpiry = "teleport:credential-expiry" // #nosec G101 -- a name, not a credential
	TypeSyncProvisioning = "teleport:sync-provisioning"
	TypePurge            = "teleport:purge-deprovisioned"
	TypeTokenGC          = "teleport:token-gc"
)

// Retention of teleport:token-gc.
const (
	TokenRetention    = 7 * 24 * time.Hour
	DeliveryRetention = 30 * 24 * time.Hour
)

const emptySchema = `{"type":"object","properties":{},"additionalProperties":false}`

// Descriptors are the task types the module registers with the scheduler.
func Descriptors() []schedulerclient.Descriptor {
	return []schedulerclient.Descriptor{
		{Type: TypeHealthCheck, DisplayName: "Teleport cluster health check",
			Description:   "Pings each registered Teleport cluster of the tenant and records its status, resource counts, version and edition.",
			PayloadSchema: emptySchema, DefaultCron: "* * * * *", DefaultMaxRetry: 0},
		{Type: TypeCredentialExpiry, DisplayName: "Teleport credential expiry",
			Description:   "Warns before management credentials expire (once per stage) and marks expired credentials.",
			PayloadSchema: emptySchema, DefaultCron: "0 * * * *", DefaultMaxRetry: 1},
		{Type: TypeSyncProvisioning, DisplayName: "Teleport provisioning sync",
			Description:   "Reconciles the tenant's managed Teleport users against the role mappings and the tenant membership.",
			PayloadSchema: emptySchema, DefaultCron: "*/15 * * * *", DefaultMaxRetry: 1},
		{Type: TypePurge, DisplayName: "Teleport de-provisioning purge",
			Description:   "Deletes managed Teleport users whose grace period has passed and removes their locks.",
			PayloadSchema: emptySchema, DefaultCron: "0 * * * *", DefaultMaxRetry: 1},
		{Type: TypeTokenGC, DisplayName: "Teleport token and delivery clean-up",
			Description:   "Prunes join-token metadata expired more than 7 days ago and alert deliveries older than 30 days.",
			PayloadSchema: emptySchema, DefaultCron: "0 * * * *", DefaultMaxRetry: 1},
	}
}

// Platform lists the platform-scoped types for the SDK server: none, every
// type runs per tenant.
func Platform() map[string]bool { return map[string]bool{} }

// Store is the persistence the tasks read and prune.
type Store interface {
	ListClusters(ctx context.Context, tenantID string) ([]repo.Cluster, error)
	ListMappings(ctx context.Context, tenantID, clusterID string) ([]repo.RoleMapping, error)
	ListManagedUsers(ctx context.Context, tenantID, clusterID string) ([]repo.ManagedUser, error)
	PruneTenantJoinTokens(ctx context.Context, tenantID string, before time.Time) (int, error)
	PruneTenantDeliveries(ctx context.Context, tenantID string, before time.Time) (int, error)
}

// Clusters checks one cluster (clusters.Service).
type Clusters interface {
	CheckCluster(ctx context.Context, c repo.Cluster) (repo.Cluster, error)
	CheckCredential(ctx context.Context, c repo.Cluster) (repo.Cluster, error)
}

// Provisioner runs the provisioning entry points (provisioning.Service).
type Provisioner interface {
	Reconcile(ctx context.Context, tenantID, clusterID string) (provisioning.Summary, error)
	PurgeDeprovisioned(ctx context.Context, tenantID string) (provisioning.Summary, error)
}

// Runner executes the task types.
type Runner struct {
	Store        Store
	Clusters     Clusters
	Provisioning Provisioner
	Log          *slog.Logger
	Now          func() time.Time
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Runner) warn(ctx context.Context, msg string, args ...any) {
	if r.Log != nil {
		r.Log.WarnContext(ctx, msg, args...)
	}
}

// Handlers maps the task types to their handlers for sdk.NewServer.
func (r *Runner) Handlers() map[string]sdk.Handler {
	return map[string]sdk.Handler{
		TypeHealthCheck: r.HealthCheck, TypeCredentialExpiry: r.CredentialExpiry, TypeSyncProvisioning: r.SyncProvisioning,
		TypePurge: r.Purge, TypeTokenGC: r.TokenGC,
	}
}

// Counts is the result data of the per-cluster tasks.
type Counts struct {
	Clusters int `json:"clusters"`
	Done     int `json:"done"`
	Skipped  int `json:"skipped,omitempty"`
	Failed   int `json:"failed"`
}

// tenant validates the request and returns the worker context of its tenant.
func tenant(ctx context.Context, req sdk.Request, worker string) (context.Context, *sdk.Result) {
	if !sdk.ValidTenant(req.TenantID) {
		res := sdk.Permanent(req.Type + " is tenant-scoped: a tenant id is required")
		return nil, &res
	}
	var p struct{}
	if err := sdk.DecodeStrict(req.Payload, &p); err != nil {
		res := sdk.Permanent("invalid payload: " + err.Error())
		return nil, &res
	}
	return authz.WithSubjects(ctx, authz.Worker(req.TenantID, worker)), nil
}

// perCluster runs fn on every cluster of the request's tenant.
func (r *Runner) perCluster(ctx context.Context, req sdk.Request, worker string,
	fn func(ctx context.Context, c repo.Cluster) (skipped bool, err error)) sdk.Result {
	wctx, bad := tenant(ctx, req, worker)
	if bad != nil {
		return *bad
	}
	cs, err := r.Store.ListClusters(wctx, req.TenantID)
	if err != nil {
		return sdk.Retry("cluster list unavailable")
	}
	n := Counts{Clusters: len(cs)}
	for _, c := range cs {
		if c.TenantID != req.TenantID { // defence in depth: never act across tenants
			continue
		}
		if ctx.Err() != nil {
			return sdk.Retry(fmt.Sprintf("%s cancelled after %d of %d clusters", req.Type, n.Done, n.Clusters))
		}
		skipped, err := fn(wctx, c)
		switch {
		case err != nil:
			n.Failed++
			r.warn(ctx, "scheduled task step failed", "type", req.Type, "cluster_id", c.ID, "err", err)
		case skipped:
			n.Skipped++
		default:
			n.Done++
		}
	}
	msg := fmt.Sprintf("%d clusters: %d done, %d skipped, %d failed", n.Clusters, n.Done, n.Skipped, n.Failed)
	if n.Failed > 0 {
		res := sdk.Retry(msg)
		res.Data = n
		return res
	}
	res := sdk.OK(msg)
	res.Data = n
	return res
}

// HealthCheck runs teleport:health-check. A failed probe is not a task
// failure (it moves the cluster's status); a store or secret store failure is.
func (r *Runner) HealthCheck(ctx context.Context, req sdk.Request) sdk.Result {
	return r.perCluster(ctx, req, "health-check", func(ctx context.Context, c repo.Cluster) (bool, error) {
		_, err := r.Clusters.CheckCluster(ctx, c)
		if errors.Is(err, repo.ErrNotFound) { // removed meanwhile
			return true, nil
		}
		return false, err
	})
}

// CredentialExpiry runs teleport:credential-expiry.
func (r *Runner) CredentialExpiry(ctx context.Context, req sdk.Request) sdk.Result {
	return r.perCluster(ctx, req, "credential-expiry", func(ctx context.Context, c repo.Cluster) (bool, error) {
		_, err := r.Clusters.CheckCredential(ctx, c)
		if errors.Is(err, repo.ErrNotFound) {
			return true, nil
		}
		return false, err
	})
}

// SyncProvisioning runs teleport:sync-provisioning. A cluster without role
// mappings and managed users has nothing to reconcile and is skipped, so the
// task does not fail while the membership source is unavailable and nothing
// is configured.
func (r *Runner) SyncProvisioning(ctx context.Context, req sdk.Request) sdk.Result {
	return r.perCluster(ctx, req, provisioning.WorkerName, func(ctx context.Context, c repo.Cluster) (bool, error) {
		maps, err := r.Store.ListMappings(ctx, c.TenantID, c.ID)
		if err != nil {
			return false, err
		}
		if len(maps) == 0 {
			users, err := r.Store.ListManagedUsers(ctx, c.TenantID, c.ID)
			if err != nil {
				return false, err
			}
			if len(users) == 0 {
				return true, nil
			}
		}
		sum, err := r.Provisioning.Reconcile(ctx, c.TenantID, c.ID)
		if errors.Is(err, repo.ErrNotFound) {
			return true, nil
		}
		if err == nil && sum.Errors > 0 {
			err = fmt.Errorf("tasks: %d provisioning steps failed", sum.Errors)
		}
		return false, err
	})
}

// Purge runs teleport:purge-deprovisioned.
func (r *Runner) Purge(ctx context.Context, req sdk.Request) sdk.Result {
	wctx, bad := tenant(ctx, req, provisioning.WorkerName)
	if bad != nil {
		return *bad
	}
	sum, err := r.Provisioning.PurgeDeprovisioned(wctx, req.TenantID)
	if err != nil {
		return sdk.Retry("purge unavailable: " + provisioning.ReasonOf(err))
	}
	msg := fmt.Sprintf("deleted %d, errors %d", sum.Deleted, sum.Errors)
	res := sdk.OK(msg)
	if sum.Errors > 0 {
		res = sdk.Retry(msg)
	}
	res.Data = sum
	return res
}

// GC is the result data of teleport:token-gc.
type GC struct {
	Tokens     int `json:"tokens"`
	Deliveries int `json:"deliveries"`
}

// TokenGC runs teleport:token-gc.
func (r *Runner) TokenGC(ctx context.Context, req sdk.Request) sdk.Result {
	wctx, bad := tenant(ctx, req, "token-gc")
	if bad != nil {
		return *bad
	}
	now := r.now()
	var gc GC
	var err error
	if gc.Tokens, err = r.Store.PruneTenantJoinTokens(wctx, req.TenantID, now.Add(-TokenRetention)); err != nil {
		return sdk.Retry("token metadata prune failed")
	}
	if gc.Deliveries, err = r.Store.PruneTenantDeliveries(wctx, req.TenantID, now.Add(-DeliveryRetention)); err != nil {
		return sdk.Retry(fmt.Sprintf("pruned %d tokens; delivery prune failed", gc.Tokens))
	}
	res := sdk.OK(fmt.Sprintf("pruned %d tokens, %d deliveries", gc.Tokens, gc.Deliveries))
	res.Data = gc
	return res
}
