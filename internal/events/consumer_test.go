package events_test

// T118: a tenant-deleted event removes the tenant's registrations and
// credentials (and nothing of another tenant); Teleport is not contacted; a
// failed deletion is retried; malformed and unrelated entries are skipped.

import (
	"context"
	"errors"
	"testing"
	"time"

	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/stream"
)

const lifecycle = "platform:events:system"

func teleportCalls(e *ct.Env) int {
	n := 0
	for _, m := range []string{"Ping", "GetUser", "ListUsers", "DeleteUser", "DeleteRole", "DeleteLock", "UpsertLock", "Watch"} {
		n += e.Teleport.Calls(m)
	}
	return n
}

func publish(t *testing.T, bus *stream.Memory, typ, data string) {
	t.Helper()
	if _, err := bus.XAdd(context.Background(), lifecycle, map[string]string{"type": typ, "data": data, "to": "*"}, 0); err != nil {
		t.Fatal(err)
	}
}

func TestTenantDeletedRemovesRegistrationsAndSecrets(t *testing.T) {
	ctx := context.Background()
	e := ct.New(t, nil)
	e.Register(t, ct.TenantA, "prod")
	e.Register(t, ct.TenantA, "staging")
	b := e.Register(t, ct.TenantB, "prod")
	now := e.Now()
	if err := e.Repo.CreateAlertRule(ctx, repo.AlertRule{ID: store.NewID(), TenantID: ct.TenantA, Name: "r", ConditionKind: repo.ConditionClusterUnreachable,
		Recipients: repo.Recipients{UserIDs: []string{ct.Admin}}, Enabled: true, CreatedBy: ct.Admin, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := e.Repo.CreateDraft(ctx, repo.DeploymentDraft{ID: store.NewID(), TenantID: ct.TenantA, Domain: "tp.example.test", CertMode: repo.CertACME,
		ACMEEmail: "ops@example.test", TeleportVersion: "19.0.1", AdminUsername: "admin", AdminLogins: []string{"root"}, Checks: []repo.DraftCheck{},
		CreatedBy: ct.Admin, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if e.Secrets.Len() != 3 {
		t.Fatalf("secrets %d", e.Secrets.Len())
	}
	bus := stream.NewMemory()
	c := &events.TenantConsumer{Bus: bus, Stream: lifecycle, Handle: func(ctx context.Context, tenant string) error {
		_, err := e.Service.PurgeTenant(ctx, tenant)
		return err
	}}
	// The first pass starts at the tail: history is not replayed.
	publish(t, bus, events.DefaultTenantDeletedType, `{"tenant_id":"`+ct.TenantB+`"}`)
	if n, err := c.RunOnce(ctx, 0); err != nil || n != 0 {
		t.Fatalf("first pass %d %v", n, err)
	}
	calls := teleportCalls(e)
	publish(t, bus, "auth.invite", `{"tenant_id":"`+ct.TenantB+`"}`)
	publish(t, bus, events.DefaultTenantDeletedType, `{"tenant_id":"not-a-uuid"}`)
	publish(t, bus, events.DefaultTenantDeletedType, `{"tenant_id":"`+ct.TenantA+`"}`)
	n, err := c.RunOnce(ctx, 0)
	if err != nil || n != 1 {
		t.Fatalf("handled %d %v", n, err)
	}
	if cs, _ := e.Repo.ListClusters(ctx, ct.TenantA); len(cs) != 0 {
		t.Fatalf("tenant A clusters left: %d", len(cs))
	}
	if rs, _ := e.Repo.ListAlertRules(ctx, ct.TenantA); len(rs) != 0 {
		t.Fatalf("rules left: %d", len(rs))
	}
	if ds, _ := e.Repo.ListDrafts(ctx, ct.TenantA); len(ds) != 0 {
		t.Fatalf("drafts left: %d", len(ds))
	}
	if _, err := e.Repo.GetCluster(ctx, ct.TenantB, b.ID); err != nil {
		t.Fatalf("tenant B touched: %v", err)
	}
	if e.Secrets.Len() != 1 {
		t.Fatalf("secrets left %d, want tenant B's only", e.Secrets.Len())
	}
	if teleportCalls(e) != calls {
		t.Fatal("Teleport was contacted")
	}
	removed := 0
	for _, ev := range e.Events.OfType(events.ClusterRemoved) {
		if ev.TenantID == ct.TenantA {
			removed++
		}
	}
	if removed != 2 {
		t.Fatalf("removed events %d", removed)
	}
	// Idempotent: running the deletion again changes nothing.
	if n, err := e.Service.PurgeTenant(ctx, ct.TenantA); err != nil || n != 0 {
		t.Fatalf("again: %d %v", n, err)
	}
}

func TestTenantDeletedRetriesAfterSecretStoreFailure(t *testing.T) {
	ctx := context.Background()
	e := ct.New(t, nil)
	e.Register(t, ct.TenantA, "prod")
	bus := stream.NewMemory()
	c := &events.TenantConsumer{Bus: bus, Stream: lifecycle, Handle: func(ctx context.Context, tenant string) error {
		_, err := e.Service.PurgeTenant(ctx, tenant)
		return err
	}}
	if _, err := c.RunOnce(ctx, 0); err != nil {
		t.Fatal(err)
	}
	publish(t, bus, events.DefaultTenantDeletedType, `{"tenant_id":"`+ct.TenantA+`"}`)
	e.Secrets.SetErr(secrets.ErrUnavailable)
	if _, err := c.RunOnce(ctx, 0); !errors.Is(err, secrets.ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if cs, _ := e.Repo.ListClusters(ctx, ct.TenantA); len(cs) != 1 {
		t.Fatal("registration removed although its secret was kept")
	}
	e.Secrets.SetErr(nil)
	if n, err := c.RunOnce(ctx, 0); err != nil || n != 1 {
		t.Fatalf("retry %d %v", n, err)
	}
	if cs, _ := e.Repo.ListClusters(ctx, ct.TenantA); len(cs) != 0 || e.Secrets.Len() != 0 {
		t.Fatal("not removed on retry")
	}
}

func TestTenantConsumerFailures(t *testing.T) {
	ctx := context.Background()
	if _, err := (&events.TenantConsumer{}).RunOnce(ctx, 0); !errors.Is(err, events.ErrConsumer) {
		t.Fatal(err)
	}
	bus := stream.NewMemory()
	c := &events.TenantConsumer{Bus: bus, Stream: lifecycle, Type: "x.deleted", Handle: func(context.Context, string) error { return nil }}
	bus.SetErr(errors.New("down"))
	if _, err := c.RunOnce(ctx, 0); err == nil {
		t.Fatal("bus outage not reported")
	}
	bus.SetErr(nil)
	if _, err := c.RunOnce(ctx, 0); err != nil {
		t.Fatal(err)
	}
	bus.SetErr(errors.New("down"))
	if _, err := c.RunOnce(ctx, 0); err == nil {
		t.Fatal("read outage not reported")
	}
	bus.SetErr(nil)
	publish(t, bus, "x.deleted", `{"tenant_id":"`+ct.TenantA+`"}`)
	if n, err := c.RunOnce(ctx, 0); err != nil || n != 1 {
		t.Fatalf("custom type %d %v", n, err)
	}
	// PurgeTenant refuses an empty tenant.
	e := ct.New(t, nil)
	if _, err := e.Service.PurgeTenant(ctx, ""); err == nil {
		t.Fatal("empty tenant accepted")
	}
	e.Repo.FailNext("ListClusters")
	if _, err := e.Service.PurgeTenant(ctx, ct.TenantA); err == nil {
		t.Fatal("store failure not reported")
	}
}

// Run stops with its context and keeps going after a failed pass.
func TestTenantConsumerRun(t *testing.T) {
	bus := stream.NewMemory()
	got := make(chan string, 1)
	c := &events.TenantConsumer{Bus: bus, Stream: lifecycle, Poll: 10 * time.Millisecond, Handle: func(_ context.Context, tenant string) error {
		got <- tenant
		return nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		publish(t, bus, events.DefaultTenantDeletedType, `{"tenant_id":"`+ct.TenantA+`"}`)
		select {
		case tn := <-got:
			if tn != ct.TenantA {
				t.Fatal(tn)
			}
			deadline = time.Time{}
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
}
