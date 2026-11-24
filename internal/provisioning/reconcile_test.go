package provisioning_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/trace"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/locks"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/provisioning"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/users"
)

const (
	bobID   = "018f3a2b-0000-7000-8000-0000000000b1"
	carolID = "018f3a2b-0000-7000-8000-0000000000c1"
	grace   = time.Hour
)

var (
	admin    = ct.As(ct.TenantA, ct.Admin)
	viewer   = ct.As(ct.TenantA, ct.Viewer)
	operator = ct.As(ct.TenantA, ct.Operator)
	bob      = provisioning.Member{UserID: bobID, Login: "Bob.Smith", Roles: []string{"operator"}}
)

type env struct {
	*ct.Env
	svc  *provisioning.Service
	auth *provisioning.FakeMembership
	id   string
}

func setup(t *testing.T) *env {
	t.Helper()
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	cache := &teleportapi.Cache{KV: teleportapi.NewMemoryKV()}
	auth := provisioning.NewFakeMembership()
	svc := &provisioning.Service{
		Clusters: e.Service, Repo: e.Repo, Membership: auth, Notify: e.Notify, Audit: e.Audit, Events: e.Events,
		Users: &users.Service{Clusters: e.Service, Audit: e.Audit, Events: e.Events, Cache: cache},
		Locks: &locks.Service{Clusters: e.Service, Audit: e.Audit, Events: e.Events, Cache: cache, Now: e.Now},
		Grace: grace, Now: e.Now,
	}
	en := &env{Env: e, svc: svc, auth: auth, id: c.ID}
	en.mapping(t, repo.SubjectModuleRole, "operator", []string{"access"}, []string{"ubuntu"})
	return en
}

func (e *env) mapping(t *testing.T, kind, ref string, roles, logins []string) provisioning.MappingView {
	t.Helper()
	m, err := e.svc.CreateMapping(admin, e.id, provisioning.MappingInput{SubjectKind: kind, SubjectRef: ref, TeleportRoles: roles, Logins: logins})
	if err != nil {
		t.Fatalf("mapping %s: %v", ref, err)
	}
	return m
}

func (e *env) sync(t *testing.T) provisioning.Summary {
	t.Helper()
	s, err := e.svc.Reconcile(context.Background(), ct.TenantA, e.id)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	return s
}

func (e *env) user(name string) (teleportapi.User, bool) {
	u, err := e.Teleport.GetUser(context.Background(), name)
	return u, err == nil
}

func (e *env) row(t *testing.T, tangraID string) (repo.ManagedUser, bool) {
	t.Helper()
	rows, err := e.Repo.ListManagedUsers(context.Background(), ct.TenantA, e.id)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.TangraUserID == tangraID {
			return r, true
		}
	}
	return repo.ManagedUser{}, false
}

func (e *env) userLocks(name string) []teleportapi.Lock {
	ls, _ := e.Teleport.ListLocks(context.Background())
	return slices.DeleteFunc(ls, func(l teleportapi.Lock) bool { return l.TargetKind != "user" || l.Target != name })
}

func TestCreateThenActive(t *testing.T) {
	e := setup(t)
	e.auth.Set(bob)
	if s := e.sync(t); s != (provisioning.Summary{Created: 1}) {
		t.Fatalf("summary %+v", s)
	}
	u, ok := e.user("bob.smith")
	if !ok || !slices.Equal(u.Roles, []string{"access"}) || !slices.Equal(u.Logins, []string{"ubuntu"}) {
		t.Fatalf("teleport user %+v %v", u, ok)
	}
	if u.Labels[users.LabelManaged] != "true" || u.Labels[users.LabelUser] != bobID || u.Labels[users.LabelTenant] != ct.TenantA {
		t.Fatalf("labels %v", u.Labels)
	}
	r, ok := e.row(t, bobID)
	if !ok || r.State != repo.UserActive || r.TeleportUsername != "bob.smith" || !slices.Equal(r.AppliedRoles, []string{"access"}) || r.LastSyncedAt.IsZero() {
		t.Fatalf("row %+v", r)
	}
	inv := e.Notify.OfTemplate(notify.TemplateInvite)
	urls := e.Teleport.IssuedURLs()
	if len(inv) != 1 || len(urls) != 1 || inv[0].To != bobID || inv[0].Vars["invite_url"] != urls[0] || inv[0].Vars["teleport_username"] != "bob.smith" {
		t.Fatalf("invite %+v urls %d", inv, len(urls))
	}
	ev := e.Events.OfType(events.ProvisioningChanged)
	if len(ev) == 0 || ev[len(ev)-1].Payload != (events.Provisioning{ClusterID: e.id, TangraUserID: bobID, State: repo.UserActive}) {
		t.Fatalf("events %+v", ev)
	}
	// Idempotent: a second run changes nothing and sends no second invite.
	if s := e.sync(t); s != (provisioning.Summary{}) {
		t.Fatalf("re-run %+v", s)
	}
	if len(e.Notify.OfTemplate(notify.TemplateInvite)) != 1 || e.Teleport.Calls("CreateUser") != 1 || e.Teleport.Calls("UpdateUser") != 0 {
		t.Fatal("the re-run wrote")
	}
	rows := e.AuditRows()
	if !slices.Contains(rows, "teleport.provision.create:success") || !slices.Contains(rows, "teleport.provision.sync:success") {
		t.Fatalf("audit %v", rows)
	}
}

func TestRoleChangeUpdatesRolesAndLogins(t *testing.T) {
	e := setup(t)
	e.auth.Set(bob)
	e.sync(t)
	e.mapping(t, repo.SubjectGroup, "devs", []string{"editor", "access"}, []string{"dev"})
	b := bob
	b.Groups = []string{"devs"}
	e.auth.Set(b)
	if s := e.sync(t); s != (provisioning.Summary{Updated: 1}) {
		t.Fatalf("summary %+v", s)
	}
	u, _ := e.user("bob.smith")
	if !slices.Equal(u.Roles, []string{"access", "editor"}) || !slices.Equal(u.Logins, []string{"dev", "ubuntu"}) {
		t.Fatalf("user %+v", u)
	}
	if u.Labels[users.LabelManaged] != "true" {
		t.Fatal("the update dropped the managed label")
	}
	r, _ := e.row(t, bobID)
	if !slices.Equal(r.AppliedRoles, []string{"access", "editor"}) || !slices.Equal(r.AppliedLogins, []string{"dev", "ubuntu"}) {
		t.Fatalf("row %+v", r)
	}
	// Drift made in Teleport is corrected on the next run.
	e.Teleport.Users[slices.IndexFunc(e.Teleport.Users, func(u teleportapi.User) bool { return u.Name == "bob.smith" })].Roles = []string{"access"}
	if s := e.sync(t); s != (provisioning.Summary{Updated: 1}) {
		t.Fatalf("drift %+v", s)
	}
}

func TestLosingMappingsLocksThenRegainingUnlocks(t *testing.T) {
	e := setup(t)
	e.auth.Set(bob)
	e.sync(t)
	b := bob
	b.Roles = []string{"viewer"}
	e.auth.Set(b)
	if s := e.sync(t); s != (provisioning.Summary{Locked: 1}) {
		t.Fatalf("summary %+v", s)
	}
	r, _ := e.row(t, bobID)
	ls := e.userLocks("bob.smith")
	if r.State != repo.UserLockedPendingDeletion || !r.DeprovisionAfter.Equal(e.Now().Add(grace)) || len(ls) != 1 || r.LockName != ls[0].Name ||
		ls[0].Message != provisioning.LockReason {
		t.Fatalf("row %+v locks %+v", r, ls)
	}
	if _, ok := e.user("bob.smith"); !ok {
		t.Fatal("locking deleted the user")
	}
	// Still locked, nothing new to do.
	if s := e.sync(t); s != (provisioning.Summary{}) {
		t.Fatalf("re-run %+v", s)
	}
	e.auth.Set(bob)
	if s := e.sync(t); s != (provisioning.Summary{Unlocked: 1}) {
		t.Fatalf("regain %+v", s)
	}
	r, _ = e.row(t, bobID)
	if r.State != repo.UserActive || r.LockName != "" || !r.DeprovisionAfter.IsZero() || len(e.userLocks("bob.smith")) != 0 {
		t.Fatalf("row %+v locks %v", r, e.userLocks("bob.smith"))
	}
	if !slices.Contains(e.AuditRows(), "teleport.provision.lock:success") {
		t.Fatal("lock not audited")
	}
}

// Leaving the tenant (no longer listed, and auth confirms) locks as well.
func TestLeavingTheTenantLocks(t *testing.T) {
	e := setup(t)
	e.auth.Set(bob)
	e.sync(t)
	e.auth.Set()
	if s := e.sync(t); s != (provisioning.Summary{Locked: 1}) {
		t.Fatalf("summary %+v", s)
	}
}

func TestGracePeriodDeletes(t *testing.T) {
	e := setup(t)
	e.auth.Set(bob)
	e.sync(t)
	e.auth.Set()
	e.sync(t)
	e.Advance(grace - time.Minute)
	if s := e.sync(t); s != (provisioning.Summary{}) {
		t.Fatalf("before the grace period %+v", s)
	}
	e.Advance(2 * time.Minute)
	if s := e.sync(t); s != (provisioning.Summary{Deleted: 1}) {
		t.Fatalf("summary %+v", s)
	}
	if _, ok := e.user("bob.smith"); ok {
		t.Fatal("user not deleted")
	}
	if _, ok := e.row(t, bobID); ok || len(e.userLocks("bob.smith")) != 0 {
		t.Fatal("row or lock left")
	}
	ev := e.Events.OfType(events.ProvisioningChanged)
	if ev[len(ev)-1].Payload != (events.Provisioning{ClusterID: e.id, TangraUserID: bobID, State: provisioning.StateDeleted}) {
		t.Fatalf("events %+v", ev)
	}
	if !slices.Contains(e.AuditRows(), "teleport.provision.delete:success") {
		t.Fatal("delete not audited")
	}
}

func TestPurgeDeprovisioned(t *testing.T) {
	e := setup(t)
	e.auth.Set(bob)
	e.sync(t)
	e.auth.Set()
	e.sync(t)
	e.Advance(grace + time.Minute)
	s, err := e.svc.PurgeDeprovisioned(context.Background(), ct.TenantA)
	if err != nil || s != (provisioning.Summary{Deleted: 1}) {
		t.Fatalf("purge %+v %v", s, err)
	}
	// A user who regained a mapping before the purge is re-verified and kept.
	e.auth.Set(provisioning.Member{UserID: carolID, Login: "carol", Roles: []string{"operator"}})
	e.sync(t)
	e.auth.SetListed()
	e.sync(t)
	e.Advance(grace + time.Minute)
	if s := e.sync(t); s.Deleted != 0 {
		t.Fatalf("listing-only removal deleted %+v", s)
	}
	if s, _ := e.svc.PurgeDeprovisioned(context.Background(), ct.TenantA); s.Deleted != 0 {
		t.Fatalf("purge deleted a member %+v", s)
	}
	// An unreachable cluster is an error, not a stop.
	e.Teleport.SetErr(trace.ConnectionProblem(errors.New("dial"), "down"))
	defer e.Teleport.SetErr(nil)
	e.auth.Set()
	e.Advance(grace)
	if s, err := e.svc.PurgeDeprovisioned(context.Background(), ct.TenantA); err != nil || s.Deleted != 0 {
		t.Fatalf("purge on an outage %+v %v", s, err)
	}
}

func TestUnmanagedUsersAreNeverTouched(t *testing.T) {
	e := setup(t)
	// alice exists in Teleport, created by hand: a member whose login maps to
	// alice is a collision, not an adoption.
	e.auth.Set(provisioning.Member{UserID: carolID, Login: "alice", Roles: []string{"operator"}})
	if s := e.sync(t); s != (provisioning.Summary{Errors: 1}) {
		t.Fatalf("summary %+v", s)
	}
	a, _ := e.user("alice")
	if a.Labels[users.LabelManaged] != "" || !slices.Equal(a.Roles, []string{"access"}) || a.Revision != "u2" {
		t.Fatalf("alice changed %+v", a)
	}
	// A managed user replaced in Teleport by an unmanaged one is left alone too.
	e.auth.Set(bob)
	e.sync(t)
	i := slices.IndexFunc(e.Teleport.Users, func(u teleportapi.User) bool { return u.Name == "bob.smith" })
	e.Teleport.Users[i].Labels = nil
	e.auth.Set()
	s := e.sync(t)
	if s.Locked != 0 || s.Errors == 0 || len(e.userLocks("bob.smith")) != 0 {
		t.Fatalf("unmanaged bob was locked %+v", s)
	}
	b := bob
	b.Groups = []string{"x"}
	e.auth.Set(b)
	if s := e.sync(t); s.Updated != 0 {
		t.Fatalf("unmanaged bob was updated %+v", s)
	}
	if e.Teleport.Calls("DeleteUser") != 0 || e.Teleport.Calls("UpdateUser") != 0 {
		t.Fatal("an unmanaged user was written")
	}
	// Never the management identity either.
	e.auth.Set(provisioning.Member{UserID: carolID, Login: ct.Management, Roles: []string{"operator"}})
	if s := e.sync(t); s.Created != 0 || s.Errors == 0 {
		t.Fatalf("management identity %+v", s)
	}
}

func TestUsername(t *testing.T) {
	for in, want := range map[string]string{
		"Bob.Smith":              "bob.smith",
		"  alice ":               "alice",
		"ana maria":              "ana-maria",
		"o'brien":                "o-brien",
		"__x":                    "x",
		"user@corp.test":         "user@corp.test",
		"jörg":                   "j-rg",
		"$(rm -rf /)":            "rm--rf",
		strings.Repeat("a", 200): strings.Repeat("a", 128),
	} {
		got, err := provisioning.Username(in)
		if err != nil || got != want {
			t.Errorf("Username(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "   ", "---", "ü"} {
		if got, err := provisioning.Username(in); err == nil {
			t.Errorf("Username(%q) = %q, want an error", in, got)
		}
	}
}

func TestUsernameCollisionsAreRejected(t *testing.T) {
	e := setup(t)
	e.auth.Set(bob, provisioning.Member{UserID: carolID, Login: "BOB.smith", Roles: []string{"operator"}},
		provisioning.Member{UserID: "018f3a2b-0000-7000-8000-0000000000d1", Login: "", Roles: []string{"operator"}})
	if s := e.sync(t); s != (provisioning.Summary{Created: 1, Errors: 2}) {
		t.Fatalf("summary %+v", s)
	}
	if _, ok := e.row(t, carolID); ok {
		t.Fatal("the colliding member got a row")
	}
}

func TestMembershipUnavailable(t *testing.T) {
	e := setup(t)
	e.auth.Set(bob)
	e.sync(t)
	e.auth.SetErr(errors.New("auth down"))
	if _, err := e.svc.Reconcile(context.Background(), ct.TenantA, e.id); !errors.Is(err, provisioning.ErrMembershipUnavailable) {
		t.Fatalf("err %v", err)
	}
	if r, _ := e.row(t, bobID); r.State != repo.UserActive || len(e.userLocks("bob.smith")) != 0 {
		t.Fatal("an auth outage changed a user")
	}
	// The production membership is unavailable altogether.
	e.svc.Membership = provisioning.Unavailable{}
	if _, err := e.svc.Reconcile(context.Background(), ct.TenantA, e.id); !errors.Is(err, provisioning.ErrMembershipUnavailable) {
		t.Fatalf("unavailable: %v", err)
	}
	if _, _, err := (provisioning.Unavailable{}).Member(context.Background(), ct.TenantA, bobID); !errors.Is(err, provisioning.ErrMembershipUnavailable) {
		t.Fatalf("unavailable member: %v", err)
	}
	e.svc.Membership = nil
	if _, err := e.svc.Reconcile(context.Background(), ct.TenantA, e.id); !errors.Is(err, provisioning.ErrMembershipUnavailable) {
		t.Fatalf("nil membership: %v", err)
	}
}

// SR-006: a removal seen only in the listing (a stale page or a forged hint)
// is re-verified with auth before anything is locked.
func TestRemovalIsReverified(t *testing.T) {
	e := setup(t)
	e.auth.Set(bob)
	e.sync(t)
	e.auth.SetListed()
	if s := e.sync(t); s != (provisioning.Summary{}) {
		t.Fatalf("summary %+v", s)
	}
	if len(e.userLocks("bob.smith")) != 0 {
		t.Fatal("locked on an unverified removal")
	}
	// A failed verification fails closed.
	e.auth.SetMemberErr(errors.New("auth down"))
	if s := e.sync(t); s != (provisioning.Summary{Errors: 1}) || len(e.userLocks("bob.smith")) != 0 {
		t.Fatalf("summary %+v", s)
	}
}

func TestInviteFailureRollsBack(t *testing.T) {
	e := setup(t)
	e.auth.Set(bob)
	e.Notify.SetErr(notify.ErrUnavailable)
	if s := e.sync(t); s != (provisioning.Summary{Errors: 1}) {
		t.Fatalf("summary %+v", s)
	}
	if _, ok := e.user("bob.smith"); ok {
		t.Fatal("user kept without an invite")
	}
	if r, _ := e.row(t, bobID); r.State != repo.UserError {
		t.Fatalf("row %+v", r)
	}
	e.Notify.SetErr(nil)
	if s := e.sync(t); s != (provisioning.Summary{Created: 1}) {
		t.Fatalf("retry %+v", s)
	}
	if r, _ := e.row(t, bobID); r.State != repo.UserActive {
		t.Fatalf("row %+v", r)
	}
	// A Teleport refusal on create leaves the row in error for the next run.
	e.auth.Set(bob, provisioning.Member{UserID: carolID, Login: "carol", Roles: []string{"operator"}})
	e.Teleport.FailNext("CreateUser", trace.AccessDenied("denied"))
	if s := e.sync(t); s != (provisioning.Summary{Errors: 1}) {
		t.Fatalf("refused %+v", s)
	}
	if s := e.sync(t); s != (provisioning.Summary{Created: 1}) {
		t.Fatalf("retry %+v", s)
	}
}

// A managed user deleted in Teleport by hand is provisioned again.
func TestDeletedOutOfBandIsRecreated(t *testing.T) {
	e := setup(t)
	e.auth.Set(bob)
	e.sync(t)
	_ = e.Teleport.DeleteUser(context.Background(), "bob.smith")
	if s := e.sync(t); s != (provisioning.Summary{Created: 1}) {
		t.Fatalf("summary %+v", s)
	}
	// A locked user that vanished is simply forgotten at the purge.
	e.auth.Set()
	e.sync(t)
	_ = e.Teleport.DeleteUser(context.Background(), "bob.smith")
	e.Advance(grace + time.Minute)
	if s := e.sync(t); s != (provisioning.Summary{Deleted: 1}) {
		t.Fatalf("purge %+v", s)
	}
}

func TestReconcileScope(t *testing.T) {
	e := setup(t)
	if _, err := e.svc.Reconcile(ct.As(ct.TenantB, ct.Admin), ct.TenantA, e.id); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("cross-tenant: %v", err)
	}
	if _, err := e.svc.Reconcile(context.Background(), "", e.id); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("no tenant: %v", err)
	}
	if _, err := e.svc.Reconcile(context.Background(), ct.TenantB, e.id); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("another tenant's cluster: %v", err)
	}
	if _, err := e.svc.PurgeDeprovisioned(ct.As(ct.TenantB, ct.Admin), ct.TenantA); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("purge cross-tenant: %v", err)
	}
	if _, err := e.svc.Sync(operator, e.id); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("operator sync: %v", err)
	}
	e.auth.Set(bob)
	if s, err := e.svc.Sync(admin, e.id); err != nil || s.Created != 1 {
		t.Fatalf("admin sync %+v %v", s, err)
	}
	e.Repo.FailNext("ListMappings")
	if _, err := e.svc.Sync(admin, e.id); err == nil {
		t.Fatal("store failure ignored")
	}
	e.Repo.FailNext("ListClusters")
	if _, err := e.svc.PurgeDeprovisioned(context.Background(), ct.TenantA); err == nil {
		t.Fatal("store failure ignored")
	}
}

func TestProvisionOne(t *testing.T) {
	e := setup(t)
	e.auth.Set(bob, provisioning.Member{UserID: carolID, Login: "carol", Roles: []string{"viewer"}})
	if _, err := e.svc.Provision(operator, e.id, provisioning.ProvisionInput{TangraUserID: bobID}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("operator: %v", err)
	}
	v, err := e.svc.Provision(admin, e.id, provisioning.ProvisionInput{TangraUserID: bobID})
	if err != nil || v.State != repo.UserActive || v.TeleportUsername != "bob.smith" || v.Locked {
		t.Fatalf("provision %+v %v", v, err)
	}
	if _, err := e.svc.Provision(admin, e.id, provisioning.ProvisionInput{TangraUserID: bobID}); !errors.Is(err, repo.ErrConflict) {
		t.Fatalf("again: %v", err)
	}
	for id, field := range map[string]string{carolID: "tangra_user_id", "018f3a2b-0000-7000-8000-0000000000ee": "tangra_user_id", "../x": "tangra_user_id"} {
		if _, err := e.svc.Provision(admin, e.id, provisioning.ProvisionInput{TangraUserID: id}); fieldOf(err) != field {
			t.Errorf("%s: %v", id, err)
		}
	}
	e.Notify.SetErr(notify.ErrUnavailable)
	e.auth.Set(bob, provisioning.Member{UserID: carolID, Login: "carol", Roles: []string{"operator"}})
	if _, err := e.svc.Provision(admin, e.id, provisioning.ProvisionInput{TangraUserID: carolID}); !errors.Is(err, notify.ErrUnavailable) {
		t.Fatalf("notification down: %v", err)
	}
	if _, err := e.svc.Provision(admin, e.id, provisioning.ProvisionInput{TangraUserID: carolID}); !errors.Is(err, notify.ErrUnavailable) {
		t.Fatalf("retry while notification is down: %v", err)
	}
	e.Notify.SetErr(nil)
	if v, err := e.svc.Provision(admin, e.id, provisioning.ProvisionInput{TangraUserID: carolID}); err != nil || v.State != repo.UserActive {
		t.Fatalf("retry %+v %v", v, err)
	}
	e.auth.SetErr(errors.New("down"))
	if _, err := e.svc.Provision(admin, e.id, provisioning.ProvisionInput{TangraUserID: "018f3a2b-0000-7000-8000-0000000000d1"}); !errors.Is(err, provisioning.ErrMembershipUnavailable) {
		t.Fatalf("auth down: %v", err)
	}
	p, err := e.svc.ListManaged(viewer, e.id)
	if err != nil || len(p.Items) != 2 {
		t.Fatalf("list %+v %v", p, err)
	}
	if _, err := e.svc.ListManaged(ct.As(ct.TenantA, ct.Nobody), e.id); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("nobody: %v", err)
	}
}

func TestLockedViewAndReasons(t *testing.T) {
	e := setup(t)
	e.auth.Set(bob)
	e.sync(t)
	e.auth.Set()
	e.sync(t)
	p, _ := e.svc.ListManaged(viewer, e.id)
	if len(p.Items) != 1 || !p.Items[0].Locked || p.Items[0].DeprovisionAfter == nil || p.Items[0].LastSyncedAt == nil {
		t.Fatalf("view %+v", p)
	}
	for err, want := range map[error]string{
		provisioning.ErrMembershipUnavailable: "dependency_unavailable",
		notify.ErrNotDelivered:                "dependency_unavailable",
		provisioning.ErrCollision:             "conflict",
		repo.ErrNotFound:                      "not_found",
	} {
		if got := provisioning.ReasonOf(err); got != want {
			t.Errorf("ReasonOf(%v) = %s, want %s", err, got, want)
		}
	}
}

// Store failures inside a run are counted, never fatal, and leave Teleport
// consistent with the rows.
func TestStoreFailuresAreCounted(t *testing.T) {
	e := setup(t)
	e.auth.Set(bob)
	e.Repo.FailNext("CreateManagedUser")
	if s := e.sync(t); s.Errors != 1 || s.Created != 0 {
		t.Fatalf("create row %+v", s)
	}
	e.sync(t)
	e.auth.Set()
	e.Teleport.FailNext("UpsertLock", trace.AccessDenied("denied"))
	if s := e.sync(t); s != (provisioning.Summary{Errors: 1}) {
		t.Fatalf("lock refused %+v", s)
	}
	e.sync(t)
	e.Advance(grace + time.Minute)
	e.Teleport.FailNext("DeleteUser", trace.AccessDenied("denied"))
	if s := e.sync(t); s != (provisioning.Summary{Errors: 1}) {
		t.Fatalf("delete refused %+v", s)
	}
	e.Teleport.FailNext("DeleteLock", trace.AccessDenied("denied"))
	if s := e.sync(t); s != (provisioning.Summary{Errors: 1}) {
		t.Fatalf("unlock refused %+v", s)
	}
	if s := e.sync(t); s != (provisioning.Summary{Deleted: 1}) {
		t.Fatalf("purge retry %+v", s)
	}
	// An update refused by Teleport is an error; the next run retries.
	e.auth.Set(bob)
	e.sync(t)
	e.mapping(t, repo.SubjectGroup, "devs", []string{"editor"}, nil)
	b := bob
	b.Groups = []string{"devs"}
	e.auth.Set(b)
	e.Teleport.FailNext("UpdateUser", trace.AccessDenied("denied"))
	if s := e.sync(t); s != (provisioning.Summary{Errors: 1}) {
		t.Fatalf("update refused %+v", s)
	}
	// An unlock refused by Teleport keeps the user locked.
	e.sync(t)
	e.auth.Set()
	e.sync(t)
	e.auth.Set(b)
	e.Teleport.FailNext("DeleteLock", trace.AccessDenied("denied"))
	if s := e.sync(t); s != (provisioning.Summary{Errors: 1}) {
		t.Fatalf("unlock refused %+v", s)
	}
	if r, _ := e.row(t, bobID); r.State != repo.UserLockedPendingDeletion {
		t.Fatalf("row %+v", r)
	}
}

// A member holding no mapped role or group is refused on the member field
// with a message the provision dialog shows as is.
func TestProvisionUnmappedMemberNamesTheReason(t *testing.T) {
	e := setup(t)
	e.auth.Set(provisioning.Member{UserID: carolID, Login: "carol@example.com", Roles: []string{"viewer"}})
	_, err := e.svc.Provision(admin, e.id, provisioning.ProvisionInput{TangraUserID: carolID})
	var fe *clusters.FieldError
	if !errors.As(err, &fe) || fe.Field != "tangra_user_id" || fe.Msg != "this member holds no mapped tangra role or group" {
		t.Fatalf("err %v", err)
	}
}
