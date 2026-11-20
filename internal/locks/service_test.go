package locks_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/trace"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/locks"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

var (
	admin    = ct.As(ct.TenantA, ct.Admin)
	operator = ct.As(ct.TenantA, ct.Operator)
	viewer   = ct.As(ct.TenantA, ct.Viewer)
)

func setup(t *testing.T) (*ct.Env, *locks.Service, string) {
	t.Helper()
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	return e, &locks.Service{Clusters: e.Service, Audit: e.Audit, Events: e.Events, Now: e.Now}, c.ID
}

func guard(err error) string {
	var g *clusters.GuardError
	if errors.As(err, &g) {
		return g.Guard
	}
	return ""
}

func lastAudit(t *testing.T, e *ct.Env, action string) repo.AuditRow {
	t.Helper()
	e.Audit.Flush(context.Background())
	rows := e.Repo.Audit()
	for i := len(rows) - 1; i >= 0; i-- {
		if rows[i].Action == action {
			return rows[i]
		}
	}
	t.Fatalf("no %s audit row in %v", action, e.AuditRows())
	return repo.AuditRow{}
}

func TestListActiveLocks(t *testing.T) {
	e, s, id := setup(t)
	exp := e.Now().Add(time.Hour)
	e.Teleport.Locks = []teleportapi.Lock{
		{Name: "l1", TargetKind: "user", Target: "alice", Message: "incident 42", CreatedBy: "u1", ExpiresAt: exp},
		{Name: "l2", TargetKind: "server_id", Target: "n-1", Message: "compromised"},
		{Name: "old", TargetKind: "role", Target: "access", ExpiresAt: e.Now().Add(-time.Minute)},
	}
	p, err := s.List(viewer, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Items) != 2 || p.Items[0].Target.User != "alice" || p.Items[0].TargetKind != "user" || p.Items[0].Message != "incident 42" ||
		p.Items[0].CreatedBy != "u1" || p.Items[0].ExpiresAt == nil || !p.Items[0].ExpiresAt.Equal(exp) ||
		p.Items[1].Target.ServerID != "n-1" || p.Items[1].ExpiresAt != nil {
		t.Fatalf("list %+v", p.Items)
	}
	if _, err := s.List(ct.As(ct.TenantB, ct.Admin), id); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("other tenant %v", err)
	}
}

func TestCreateLock(t *testing.T) {
	e, s, id := setup(t)
	exp := e.Now().Add(2 * time.Hour)
	v, err := s.Create(operator, id, locks.CreateInput{TargetKind: "user", Target: "alice", Reason: "  incident 42 ", ExpiresAt: &exp})
	if err != nil {
		t.Fatal(err)
	}
	if v.Name == "" || v.Target.User != "alice" || v.Message != "incident 42" || v.CreatedBy != ct.Operator || v.ExpiresAt == nil {
		t.Fatalf("view %+v", v)
	}
	got := e.Teleport.Locks
	if len(got) != 1 || got[0].Name != v.Name || got[0].Message != "incident 42" || got[0].CreatedBy != ct.Operator || !got[0].ExpiresAt.Equal(exp) {
		t.Fatalf("teleport locks %+v", got)
	}
	ev := e.Events.OfType(events.LockCreated)
	if len(ev) != 1 || ev[0].Payload != (events.Lock{ClusterID: id, LockName: v.Name, TargetKind: "user"}) {
		t.Fatalf("events %+v", ev)
	}
	row := lastAudit(t, e, "teleport.lock.create")
	if row.Outcome != "success" || row.TargetName != v.Name || row.Detail["target_kind"] != "user" || row.Detail["target"] != "alice" {
		t.Fatalf("audit %+v", row)
	}
	if v, err := s.Create(admin, id, locks.CreateInput{TargetKind: "server_id", Target: "n-1", Reason: "x"}); err != nil || v.ExpiresAt != nil {
		t.Fatalf("server lock %+v %v", v, err)
	}
}

func TestCreateLockValidation(t *testing.T) {
	e, s, id := setup(t)
	past := e.Now().Add(-time.Minute)
	for name, in := range map[string]locks.CreateInput{
		"no reason":    {TargetKind: "user", Target: "alice"},
		"blank reason": {TargetKind: "user", Target: "alice", Reason: "   "},
		"long reason":  {TargetKind: "user", Target: "alice", Reason: strings.Repeat("x", 257)},
		"control":      {TargetKind: "user", Target: "alice", Reason: "a\x00b"},
		"past expiry":  {TargetKind: "user", Target: "alice", Reason: "x", ExpiresAt: &past},
		"bad kind":     {TargetKind: "login", Target: "root", Reason: "x"},
		"no target":    {TargetKind: "user", Reason: "x"},
		"bad target":   {TargetKind: "user", Target: "a b", Reason: "x"},
	} {
		if _, err := s.Create(admin, id, in); !errors.Is(err, clusters.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if e.Teleport.Calls("UpsertLock") != 0 {
		t.Fatal("an invalid lock reached Teleport")
	}
	if row := lastAudit(t, e, "teleport.lock.create"); row.Outcome != "failure" || row.Reason != "validation_failed" {
		t.Fatalf("audit %+v", row)
	}
	if _, err := s.Create(viewer, id, locks.CreateInput{TargetKind: "user", Target: "alice", Reason: "x"}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer %v", err)
	}
}

// Locks that would cut off the management identity are refused: the
// identity itself and every role it holds.
func TestManagementIdentityCannotBeLocked(t *testing.T) {
	e, s, id := setup(t)
	if _, err := s.Create(admin, id, locks.CreateInput{TargetKind: "user", Target: ct.Management, Reason: "x"}); guard(err) != clusters.GuardSelfIdentity {
		t.Fatalf("lock the identity: %v", err)
	}
	if _, err := s.Create(admin, id, locks.CreateInput{TargetKind: "role", Target: ct.ManagerRole, Reason: "x"}); guard(err) != clusters.GuardManagementRole {
		t.Fatalf("lock its role: %v", err)
	}
	if row := lastAudit(t, e, "teleport.lock.create"); row.Outcome != "failure" || row.Reason != clusters.GuardManagementRole {
		t.Fatalf("audit %+v", row)
	}
	// Without the identity's roles the guard cannot decide: it refuses.
	e.Teleport.FailNext("GetUser", trace.ConnectionProblem(errors.New("dial"), "refused"))
	if _, err := s.Create(admin, id, locks.CreateInput{TargetKind: "role", Target: "access", Reason: "x"}); !errors.Is(err, teleportapi.ErrUnreachable) {
		t.Fatalf("fail closed: %v", err)
	}
	if len(e.Teleport.Locks) != 0 {
		t.Fatalf("locks written: %+v", e.Teleport.Locks)
	}
	if _, err := s.Create(admin, id, locks.CreateInput{TargetKind: "role", Target: "access", Reason: "x"}); err != nil {
		t.Fatalf("another role: %v", err)
	}
}

func TestRemoveLock(t *testing.T) {
	e, s, id := setup(t)
	v, _ := s.Create(admin, id, locks.CreateInput{TargetKind: "role", Target: "access", Reason: "x"})
	if err := s.Remove(viewer, id, v.Name); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer %v", err)
	}
	if err := s.Remove(operator, id, v.Name); err != nil {
		t.Fatal(err)
	}
	if ev := e.Events.OfType(events.LockRemoved); len(ev) != 1 || ev[0].Payload != (events.Lock{ClusterID: id, LockName: v.Name, TargetKind: "role"}) {
		t.Fatalf("events %+v", ev)
	}
	if err := s.Remove(admin, id, v.Name); !errors.Is(err, teleportapi.ErrNotFound) {
		t.Fatalf("twice %v", err)
	}
	if row := lastAudit(t, e, "teleport.lock.delete"); row.Outcome != "failure" || row.Reason != "not_found" {
		t.Fatalf("audit %+v", row)
	}
	e.Teleport.Locks = []teleportapi.Lock{{Name: "l9", TargetKind: "user", Target: "bob"}}
	e.Teleport.FailNext("DeleteLock", trace.AccessDenied("denied"))
	if err := s.Remove(admin, id, "l9"); !errors.Is(err, teleportapi.ErrRejected) {
		t.Fatalf("rejected %v", err)
	}
	if row := lastAudit(t, e, "teleport.lock.delete"); row.Reason != "teleport_rejected" {
		t.Fatalf("audit %+v", row)
	}
}
