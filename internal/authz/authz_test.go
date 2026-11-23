package authz

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repotest"
)

const (
	tn    = repotest.TenantA
	other = repotest.TenantB
	inv   = "spiffe://example.org/svc/inventory"
)

var ctx = context.Background()

// contractPermissions is the permission table of contracts/http-api.md.
var contractPermissions = []string{
	"clusters:read", "clusters:manage", "users:read", "users:manage", "roles:read", "roles:manage",
	"locks:read", "locks:manage", "tokens:manage", "resources:read", "resources:link", "resources:enroll", "audit:read",
	"alerts:read", "alerts:manage", "provisioning:manage", "deployments:manage", "sessions:play",
}

func TestPermissionsMatchContract(t *testing.T) {
	if len(Permissions) != len(contractPermissions) {
		t.Fatalf("permissions %v", Permissions)
	}
	for _, p := range contractPermissions {
		if !Known(p) {
			t.Errorf("%s unknown", p)
		}
	}
	if Known("clusters:fly") || Known("") {
		t.Fatal("unknown accepted")
	}
}

func TestRequireUserEveryPermission(t *testing.T) {
	for _, p := range contractPermissions {
		holder := User(tn, "u-"+p, nil)
		c := Static{"u-" + p: {p}}
		if err := Require(ctx, c, holder, p); err != nil {
			t.Fatalf("%s holder refused: %v", p, err)
		}
		for _, q := range contractPermissions {
			if q != p && Allowed(ctx, c, holder, q) {
				t.Fatalf("holder of %s allowed %s", p, q)
			}
		}
	}
	admin := User(tn, "admin", nil)
	if Allowed(ctx, nil, admin, ClustersRead) {
		t.Fatal("nil checker must refuse")
	}
	if Allowed(ctx, Static{"": {ClustersRead}}, Subjects{TenantID: tn, ActorKind: ActorUser}, ClustersRead) {
		t.Fatal("user without id")
	}
	if Allowed(ctx, Static{"admin": {ClustersRead}}, Subjects{UserID: "admin", ActorKind: ActorUser}, ClustersRead) {
		t.Fatal("no tenant")
	}
	if Allowed(ctx, Static{"admin": {"clusters:fly"}}, admin, "clusters:fly") {
		t.Fatal("unknown permission")
	}
	if Allowed(ctx, Static{"admin": {ClustersRead}}, Subjects{TenantID: tn, UserID: "admin", ActorKind: "robot"}, ClustersRead) {
		t.Fatal("unknown actor kind")
	}
	called := false
	fn := CheckerFunc(func(_ context.Context, tenant, user, perm string) bool {
		called = true
		return tenant == tn && user == "admin" && perm == AuditRead
	})
	if !Allowed(ctx, fn, admin, AuditRead) || !called {
		t.Fatal("checker func")
	}
}

func TestActorKinds(t *testing.T) {
	u := User(tn, "alice", []string{"owner"})
	if !u.IsHuman() || u.ActorID() != "alice" || u.ActorKind != ActorUser || !u.HasRole("owner") || u.HasRole("admin") {
		t.Fatalf("user %+v", u)
	}

	m := Module(tn, inv)
	if m.IsHuman() || m.ActorID() != inv {
		t.Fatalf("module %+v", m)
	}
	for _, p := range contractPermissions {
		want := p == ClustersRead || p == ResourcesRead
		if got := Allowed(ctx, nil, m, p); got != want {
			t.Errorf("module %s = %v", p, got)
		}
	}
	if Allowed(ctx, nil, Subjects{TenantID: tn, ActorKind: ActorModule}, ClustersRead) {
		t.Fatal("module without a verified SPIFFE id")
	}

	w := Worker(tn, "provisioning-sync")
	if w.IsHuman() || w.ActorID() != "provisioning-sync" || w.ActorKind != ActorWorker {
		t.Fatalf("worker %+v", w)
	}
	// Spec 003 R13: watching a recording is human-only.
	for _, p := range []string{RolesManage, DeploymentsManage, TokensManage, SessionsPlay} {
		if Allowed(ctx, nil, w, p) {
			t.Errorf("worker allowed %s", p)
		}
	}
	for _, p := range []string{ClustersRead, ClustersManage, UsersManage, LocksManage, ResourcesLink, ProvisioningManage, AlertsRead, AuditRead} {
		if !Allowed(ctx, nil, w, p) {
			t.Errorf("worker refused %s", p)
		}
	}
	if Allowed(ctx, nil, Worker("", "x"), ClustersRead) {
		t.Fatal("worker without tenant")
	}

	s := System(tn)
	for _, p := range contractPermissions {
		if !Allowed(ctx, nil, s, p) {
			t.Errorf("system refused %s", p)
		}
	}
	if (Subjects{ActorKind: ActorWorker}).ActorID() != ActorWorker {
		t.Fatal("ActorID fallback")
	}
}

func TestRequireTenantAndCaller(t *testing.T) {
	u := User(tn, "alice", nil)
	if err := RequireTenant(u, tn); err != nil {
		t.Fatal(err)
	}
	if err := RequireTenant(u, other); !errors.Is(err, ErrForbidden) {
		t.Fatal("other tenant")
	}
	if err := RequireTenant(u, ""); !errors.Is(err, ErrForbidden) {
		t.Fatal("empty tenant")
	}
	m := Module(tn, inv)
	if err := CallerIs(m, inv); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "spiffe://example.org/svc/asset", "spiffe://example.org/svc/*"} {
		if err := CallerIs(m, id); !errors.Is(err, ErrForbidden) {
			t.Errorf("CallerIs(%q) admitted", id)
		}
	}
	if err := CallerIs(u, inv); !errors.Is(err, ErrForbidden) {
		t.Fatal("user as module")
	}
	if err := CallerIs(Module(tn, "spiffe://example.org/svc/*"), "spiffe://example.org/svc/*"); !errors.Is(err, ErrForbidden) {
		t.Fatal("wildcard honoured")
	}
	if r, a, ok := Split("clusters:read"); !ok || r != "clusters" || a != "read" {
		t.Fatal("split")
	}
	for _, bad := range []string{"clusters", ":read", "clusters:"} {
		if _, _, ok := Split(bad); ok {
			t.Errorf("split %q", bad)
		}
	}
}

func TestContext(t *testing.T) {
	if _, ok := FromContext(ctx); ok {
		t.Fatal("empty context has subjects")
	}
	u := User(tn, "alice", []string{"r"})
	c := WithSubjects(ctx, u)
	got, ok := FromContext(c)
	if !ok || got.UserID != "alice" || got.TenantID != tn {
		t.Fatalf("FromContext %+v", got)
	}
}

func TestAuthorizerRequireCluster(t *testing.T) {
	st := memstore.New()
	mine := repotest.NewCluster(tn, "mine")
	theirs := repotest.NewCluster(other, "theirs")
	if err := st.CreateCluster(ctx, mine); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateCluster(ctx, theirs); err != nil {
		t.Fatal(err)
	}
	a := Authorizer{Checker: Static{"alice": {ClustersRead}}, Clusters: st}
	c := WithSubjects(ctx, User(tn, "alice", nil))

	got, err := a.RequireCluster(c, mine.ID, ClustersRead)
	if err != nil || got.ID != mine.ID {
		t.Fatalf("own cluster: %v", err)
	}
	// Another tenant's id answers not_found, never forbidden (no existence leak).
	if _, err := a.RequireCluster(c, theirs.ID, ClustersRead); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("other tenant's cluster: %v", err)
	}
	if _, err := a.RequireCluster(c, "not-a-uuid", ClustersRead); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("bad id: %v", err)
	}
	// The permission is checked before the lookup.
	if _, err := a.RequireCluster(c, mine.ID, ClustersManage); !errors.Is(err, ErrForbidden) {
		t.Fatalf("missing permission: %v", err)
	}
	if _, err := a.RequireCluster(ctx, mine.ID, ClustersRead); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("no subjects: %v", err)
	}
	if err := a.Require(c, ClustersRead); err != nil {
		t.Fatal(err)
	}
	if err := a.Require(ctx, ClustersRead); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("Require without subjects")
	}
	// A store failure is passed through (it is not a permission answer).
	st.FailNext("GetCluster")
	if _, err := a.RequireCluster(c, mine.ID, ClustersRead); err == nil || errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("store failure: %v", err)
	}
}

type fakeAuth struct {
	authv1.AuthorizationClient
	got *authv1.CheckRequest
	res *authv1.CheckResponse
	err error
}

func (f *fakeAuth) Check(_ context.Context, in *authv1.CheckRequest, _ ...grpc.CallOption) (*authv1.CheckResponse, error) {
	f.got = in
	return f.res, f.err
}

func TestAuthChecker(t *testing.T) {
	f := &fakeAuth{res: &authv1.CheckResponse{Allowed: true}}
	c := AuthChecker{Client: f, Module: "teleport"}
	if !c.Has(ctx, tn, "alice", ClustersManage) {
		t.Fatal("allowed")
	}
	if f.got.GetTenantId() != tn || f.got.GetUserId() != "alice" || f.got.GetResource() != "clusters" || f.got.GetAction() != "manage" || f.got.GetModule() != "teleport" {
		t.Fatalf("request %+v", f.got)
	}
	f.res = &authv1.CheckResponse{Allowed: false}
	if c.Has(ctx, tn, "alice", ClustersManage) {
		t.Fatal("denied")
	}
	f.err = errors.New("down")
	if c.Has(ctx, tn, "alice", ClustersManage) {
		t.Fatal("error must fail closed")
	}
	if c.Has(ctx, tn, "alice", "malformed") || (AuthChecker{}).Has(ctx, tn, "alice", ClustersRead) {
		t.Fatal("malformed / unwired")
	}
}
