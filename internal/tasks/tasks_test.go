package tasks_test

// T115: every scheduler task type of contracts/events-and-tasks.md is
// registered tenant-scoped, works only on the tenant carried in the task, is
// idempotent, and answers a retryable failure when a step fails (permanent
// for a malformed request). The executor server admits only the scheduler.

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	schedulerv1 "github.com/go-tangra/go-tangra-scheduler/sdk/v4/api/proto/scheduler/v1"
	sdk "github.com/go-tangra/go-tangra-scheduler/sdk/v4/pkg/taskexec"

	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/locks"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/provisioning"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/tasks"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/users"
)

const bobID = "018f3a2b-0000-7000-8000-0000000000b1"

var contractTypes = []string{"teleport:health-check", "teleport:credential-expiry", "teleport:sync-provisioning",
	"teleport:purge-deprovisioned", "teleport:token-gc"}

type env struct {
	*ct.Env
	prov   *provisioning.Service
	auth   *provisioning.FakeMembership
	runner *tasks.Runner
}

func setup(t *testing.T) *env {
	t.Helper()
	e := ct.New(t, nil)
	cache := &teleportapi.Cache{KV: teleportapi.NewMemoryKV()}
	auth := provisioning.NewFakeMembership()
	prov := &provisioning.Service{
		Clusters: e.Service, Repo: e.Repo, Membership: auth, Notify: e.Notify, Audit: e.Audit, Events: e.Events,
		Users: &users.Service{Clusters: e.Service, Audit: e.Audit, Events: e.Events, Cache: cache},
		Locks: &locks.Service{Clusters: e.Service, Audit: e.Audit, Events: e.Events, Cache: cache, Now: e.Now},
		Grace: time.Hour, Now: e.Now,
	}
	return &env{Env: e, prov: prov, auth: auth, runner: &tasks.Runner{Store: e.Repo, Clusters: e.Service, Provisioning: prov, Now: e.Now}}
}

func req(typ, tenant string) sdk.Request {
	return sdk.Request{ExecutionID: "x1", Type: typ, TenantID: tenant, Payload: json.RawMessage(`{}`), Attempt: 1, MaxAttempts: 2}
}

func (e *env) run(t *testing.T, typ, tenant string) sdk.Result {
	t.Helper()
	return e.runner.Handlers()[typ](context.Background(), req(typ, tenant))
}

func wantOK(t *testing.T, r sdk.Result) {
	t.Helper()
	if !r.Success {
		t.Fatalf("failed: %+v", r)
	}
}

func wantRetry(t *testing.T, r sdk.Result) {
	t.Helper()
	if r.Success || r.Permanent {
		t.Fatalf("want a retryable failure, got %+v", r)
	}
}

func cluster(t *testing.T, e *env, tenant, id string) repo.Cluster {
	t.Helper()
	c, err := e.Repo.GetCluster(context.Background(), tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDescriptorsMatchContract(t *testing.T) {
	ds := tasks.Descriptors()
	var types []string
	for _, d := range ds {
		types = append(types, d.Type)
		if d.Platform || d.DefaultCron == "" || d.PayloadSchema == "" || d.DisplayName == "" || d.Description == "" {
			t.Errorf("%s: %+v", d.Type, d)
		}
	}
	if !slices.Equal(types, contractTypes) {
		t.Fatalf("types %v", types)
	}
	h := (&tasks.Runner{}).Handlers()
	for _, typ := range contractTypes {
		if h[typ] == nil {
			t.Errorf("no handler for %s", typ)
		}
	}
	if len(h) != len(contractTypes) || len(tasks.Platform()) != 0 {
		t.Fatalf("handlers %d, platform %v", len(h), tasks.Platform())
	}
}

// Every type refuses a request without a valid tenant or with an unknown
// payload field, permanently.
func TestTenantRequiredAndStrictPayload(t *testing.T) {
	e := setup(t)
	for _, typ := range contractTypes {
		for _, tenant := range []string{"", "not-a-uuid"} {
			if r := e.run(t, typ, tenant); r.Success || !r.Permanent {
				t.Errorf("%s tenant %q: %+v", typ, tenant, r)
			}
		}
		bad := req(typ, ct.TenantA)
		bad.Payload = json.RawMessage(`{"tenant_id":"` + ct.TenantB + `"}`)
		if r := e.runner.Handlers()[typ](context.Background(), bad); r.Success || !r.Permanent {
			t.Errorf("%s accepted an unknown payload field: %+v", typ, r)
		}
	}
}

func TestHealthCheckTenantScopedIdempotent(t *testing.T) {
	e := setup(t)
	e.Register(t, ct.TenantA, "prod")
	e.Register(t, ct.TenantA, "staging")
	b := e.Register(t, ct.TenantB, "prod")
	before := cluster(t, e, ct.TenantB, b.ID)
	pings := e.Teleport.Calls("Ping")
	e.Advance(time.Minute)
	for range 2 {
		r := e.run(t, tasks.TypeHealthCheck, ct.TenantA)
		wantOK(t, r)
		if n := r.Data.(tasks.Counts); n.Clusters != 2 || n.Done != 2 || n.Failed != 0 {
			t.Fatalf("counts %+v", n)
		}
	}
	if got := e.Teleport.Calls("Ping") - pings; got != 4 {
		t.Fatalf("pings %d, want 2 per run", got)
	}
	if after := cluster(t, e, ct.TenantB, b.ID); !after.LastContactAt.Equal(before.LastContactAt) {
		t.Fatal("tenant B's cluster was checked")
	}
	// An unreachable cluster is a status change, not a task failure.
	e.Teleport.SetErr(errors.New("dial tcp: connection refused"))
	wantOK(t, e.run(t, tasks.TypeHealthCheck, ct.TenantA))
	e.Teleport.SetErr(nil)
	// Store failures are retryable failures.
	e.Repo.FailNext("ListClusters")
	wantRetry(t, e.run(t, tasks.TypeHealthCheck, ct.TenantA))
	e.Repo.FailNext("UpdateCluster")
	r := e.run(t, tasks.TypeHealthCheck, ct.TenantA)
	wantRetry(t, r)
	if n := r.Data.(tasks.Counts); n.Failed != 1 || n.Done != 1 {
		t.Fatalf("counts %+v", n)
	}
	// No cluster: nothing to do.
	wantOK(t, e.run(t, tasks.TypeHealthCheck, "33333333-3333-7333-8333-333333333333"))
}

func TestCredentialExpiryWarnsOnceThenMarksExpired(t *testing.T) {
	e := setup(t)
	a := e.Register(t, ct.TenantA, "prod") // 30-day identity
	b := e.Register(t, ct.TenantB, "prod")
	pings := e.Teleport.Calls("Ping")
	e.Advance(24 * 24 * time.Hour) // within the 7-day threshold
	for range 2 {
		wantOK(t, e.run(t, tasks.TypeCredentialExpiry, ct.TenantA))
	}
	if c := cluster(t, e, ct.TenantA, a.ID); c.Status != repo.StatusCredentialExpiring {
		t.Fatalf("status %s", c.Status)
	}
	warned := 0
	for _, ev := range e.Events.OfType(events.CredentialExpiring) {
		if ev.TenantID == ct.TenantB {
			t.Fatal("tenant B was evaluated")
		}
		warned++
	}
	if warned != 1 {
		t.Fatalf("expiring events %d, want 1 (once per stage)", warned)
	}
	if c := cluster(t, e, ct.TenantB, b.ID); c.Status != repo.StatusConnected {
		t.Fatalf("tenant B status %s", c.Status)
	}
	e.Advance(7 * 24 * time.Hour) // past expiry
	wantOK(t, e.run(t, tasks.TypeCredentialExpiry, ct.TenantA))
	wantOK(t, e.run(t, tasks.TypeCredentialExpiry, ct.TenantA))
	if c := cluster(t, e, ct.TenantA, a.ID); c.Status != repo.StatusCredentialInvalid {
		t.Fatalf("status %s", c.Status)
	}
	if e.Teleport.Calls("Ping") != pings {
		t.Fatal("the credential evaluation dialled the cluster")
	}
	e.Repo.FailNext("GetCluster")
	wantRetry(t, e.run(t, tasks.TypeCredentialExpiry, ct.TenantA))
	e.Repo.FailNext("ListClusters")
	wantRetry(t, e.run(t, tasks.TypeCredentialExpiry, ct.TenantA))
}

func TestCredentialExpiryStoreWriteFailure(t *testing.T) {
	e := setup(t)
	e.Register(t, ct.TenantA, "prod")
	e.Advance(24 * 24 * time.Hour)
	e.Repo.FailNext("UpdateCluster")
	wantRetry(t, e.run(t, tasks.TypeCredentialExpiry, ct.TenantA))
	wantOK(t, e.run(t, tasks.TypeCredentialExpiry, ct.TenantA))
}

func (e *env) mapping(t *testing.T, tenant, clusterID string) {
	t.Helper()
	if _, err := e.prov.CreateMapping(ct.As(tenant, ct.Admin), clusterID, provisioning.MappingInput{SubjectKind: repo.SubjectModuleRole,
		SubjectRef: "operator", TeleportRoles: []string{"access"}, Logins: []string{"ubuntu"}}); err != nil {
		t.Fatal(err)
	}
}

func TestSyncProvisioningTenantScopedIdempotent(t *testing.T) {
	e := setup(t)
	a := e.Register(t, ct.TenantA, "prod")
	e.Register(t, ct.TenantA, "unmapped")
	b := e.Register(t, ct.TenantB, "prod")
	e.mapping(t, ct.TenantA, a.ID)
	e.mapping(t, ct.TenantB, b.ID)
	e.auth.Set(provisioning.Member{UserID: bobID, Login: "bob", Roles: []string{"operator"}})
	r := e.run(t, tasks.TypeSyncProvisioning, ct.TenantA)
	wantOK(t, r)
	if n := r.Data.(tasks.Counts); n.Done != 1 || n.Skipped != 1 {
		t.Fatalf("counts %+v", n)
	}
	if mu, _ := e.Repo.ListManagedUsers(context.Background(), ct.TenantA, a.ID); len(mu) != 1 {
		t.Fatalf("managed users %d", len(mu))
	}
	if mu, _ := e.Repo.ListManagedUsers(context.Background(), ct.TenantB, b.ID); len(mu) != 0 {
		t.Fatal("tenant B was reconciled")
	}
	created := len(e.Events.OfType(events.UserCreated))
	wantOK(t, e.run(t, tasks.TypeSyncProvisioning, ct.TenantA))
	if len(e.Events.OfType(events.UserCreated)) != created {
		t.Fatal("a second run created users again")
	}
	// The membership source down is a retryable failure.
	e.auth.SetErr(errors.New("auth unavailable"))
	wantRetry(t, e.run(t, tasks.TypeSyncProvisioning, ct.TenantA))
	e.auth.SetErr(nil)
	e.Repo.FailNext("ListMappings")
	wantRetry(t, e.run(t, tasks.TypeSyncProvisioning, ct.TenantA))
}

func TestSyncProvisioningCountsStepErrors(t *testing.T) {
	e := setup(t)
	a := e.Register(t, ct.TenantA, "prod")
	e.mapping(t, ct.TenantA, a.ID)
	e.auth.Set(provisioning.Member{UserID: bobID, Login: "bob", Roles: []string{"operator"}})
	e.Teleport.FailNext("CreateUser", errors.New("boom"))
	wantRetry(t, e.run(t, tasks.TypeSyncProvisioning, ct.TenantA))
	// Without mappings but with managed users left, the cluster is still
	// reconciled (users are revoked).
	wantOK(t, e.run(t, tasks.TypeSyncProvisioning, ct.TenantA))
	ms, _ := e.Repo.ListMappings(context.Background(), ct.TenantA, a.ID)
	for _, m := range ms {
		if err := e.Repo.DeleteMapping(context.Background(), ct.TenantA, m.ID); err != nil {
			t.Fatal(err)
		}
	}
	e.Repo.FailNext("ListManagedUsers")
	wantRetry(t, e.run(t, tasks.TypeSyncProvisioning, ct.TenantA))
	r := e.run(t, tasks.TypeSyncProvisioning, ct.TenantA)
	wantOK(t, r)
	if n := r.Data.(tasks.Counts); n.Done != 1 {
		t.Fatalf("counts %+v", n)
	}
}

func TestPurgeDeprovisioned(t *testing.T) {
	e := setup(t)
	a := e.Register(t, ct.TenantA, "prod")
	e.mapping(t, ct.TenantA, a.ID)
	e.auth.Set(provisioning.Member{UserID: bobID, Login: "bob", Roles: []string{"operator"}})
	wantOK(t, e.run(t, tasks.TypeSyncProvisioning, ct.TenantA))
	e.auth.Set() // bob left the tenant: locked, then deleted after the grace period
	wantOK(t, e.run(t, tasks.TypeSyncProvisioning, ct.TenantA))
	e.Advance(2 * time.Hour)
	r := e.run(t, tasks.TypePurge, ct.TenantB)
	wantOK(t, r)
	if r.Data.(provisioning.Summary).Deleted != 0 {
		t.Fatal("tenant B's run purged tenant A")
	}
	r = e.run(t, tasks.TypePurge, ct.TenantA)
	wantOK(t, r)
	if s := r.Data.(provisioning.Summary); s.Deleted != 1 {
		t.Fatalf("summary %+v", s)
	}
	wantOK(t, e.run(t, tasks.TypePurge, ct.TenantA)) // idempotent
	if _, err := e.Teleport.GetUser(context.Background(), "bob"); err == nil {
		t.Fatal("bob still exists")
	}
	e.Repo.FailNext("ListClusters")
	wantRetry(t, e.run(t, tasks.TypePurge, ct.TenantA))
	e.Repo.FailNext("ListMappings")
	wantRetry(t, e.run(t, tasks.TypePurge, ct.TenantA))
}

func TestTokenGCTenantScoped(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	a := e.Register(t, ct.TenantA, "prod")
	b := e.Register(t, ct.TenantB, "prod")
	now := e.Now()
	tok := func(tenant, cluster string, exp time.Time) {
		t.Helper()
		if err := e.Repo.CreateJoinToken(ctx, repo.JoinToken{ID: store.NewID(), TenantID: tenant, ClusterID: cluster, TokenHash: []byte{1},
			ResourceType: repo.KindNode, ExpiresAt: exp, CreatedBy: ct.Admin, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	tok(ct.TenantA, a.ID, now.Add(-8*24*time.Hour))
	tok(ct.TenantA, a.ID, now.Add(-time.Hour)) // expired, but within 7 days: kept
	tok(ct.TenantB, b.ID, now.Add(-8*24*time.Hour))
	rule := repo.AlertRule{ID: store.NewID(), TenantID: ct.TenantA, Name: "r", ConditionKind: repo.ConditionClusterUnreachable,
		Recipients: repo.Recipients{UserIDs: []string{ct.Admin}}, Enabled: true, CreatedBy: ct.Admin, CreatedAt: now, UpdatedAt: now}
	if err := e.Repo.CreateAlertRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	if err := e.Repo.RecordDelivery(ctx, repo.AlertDelivery{ID: store.NewID(), TenantID: ct.TenantA, RuleID: rule.ID, ClusterID: a.ID,
		WindowKey: "w", DeliveredAt: now.Add(-31 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	r := e.run(t, tasks.TypeTokenGC, ct.TenantA)
	wantOK(t, r)
	if gc := r.Data.(tasks.GC); gc.Tokens != 1 || gc.Deliveries != 1 {
		t.Fatalf("gc %+v", gc)
	}
	r = e.run(t, tasks.TypeTokenGC, ct.TenantA) // idempotent
	wantOK(t, r)
	if gc := r.Data.(tasks.GC); gc.Tokens != 0 || gc.Deliveries != 0 {
		t.Fatalf("second gc %+v", gc)
	}
	if ts, _ := e.Repo.ListJoinTokens(ctx, ct.TenantA, a.ID); len(ts) != 1 {
		t.Fatalf("tenant A tokens %d", len(ts))
	}
	if ts, _ := e.Repo.ListJoinTokens(ctx, ct.TenantB, b.ID); len(ts) != 1 {
		t.Fatal("tenant B's token was pruned")
	}
	e.Repo.FailNext("PruneTenantJoinTokens")
	wantRetry(t, e.run(t, tasks.TypeTokenGC, ct.TenantA))
	e.Repo.FailNext("PruneTenantDeliveries")
	wantRetry(t, e.run(t, tasks.TypeTokenGC, ct.TenantA))
}

// A cancelled run stops early and asks for a retry.
func TestCancelledRunRetries(t *testing.T) {
	e := setup(t)
	e.Register(t, ct.TenantA, "prod")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	wantRetry(t, e.runner.HealthCheck(ctx, req(tasks.TypeHealthCheck, ct.TenantA)))
}

// The executor server built as in internal/app admits only the scheduler and
// requires a tenant for every type.
func TestExecutorAdmitsOnlyTheScheduler(t *testing.T) {
	e := setup(t)
	e.Register(t, ct.TenantA, "prod")
	caller := "gateway"
	srv := sdk.NewServer(e.runner.Handlers(), sdk.Options{
		Caller:   func(context.Context) (string, bool) { return caller, true },
		Platform: tasks.Platform(),
	})
	call := func(tenant string) (*schedulerv1.ExecuteTaskResponse, error) {
		return srv.ExecuteTask(context.Background(), &schedulerv1.ExecuteTaskRequest{ExecutionId: "x", TaskType: tasks.TypeHealthCheck, TenantId: tenant})
	}
	if _, err := call(ct.TenantA); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("gateway: %v", err)
	}
	caller = "scheduler"
	if _, err := call(""); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("no tenant: %v", err)
	}
	res, err := call(ct.TenantA)
	if err != nil || !res.GetSuccess() {
		t.Fatalf("scheduler: %v %+v", err, res)
	}
}
