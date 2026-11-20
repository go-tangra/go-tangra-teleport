package teleportapi

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
)

func TestWriteConversions(t *testing.T) {
	u, err := newUserV2(UserSpec{Name: "alice", Roles: []string{"access"}, Logins: []string{"ubuntu"}, Labels: map[string]string{"tangra.io/managed": "true"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := userOf(u); got.Name != "alice" || got.Roles[0] != "access" || got.Logins[0] != "ubuntu" || got.Labels["tangra.io/managed"] != "true" {
		t.Fatalf("user %+v", got)
	}
	if _, err := newUserV2(UserSpec{}); err == nil {
		t.Fatal("a nameless user was built")
	}
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	for _, kind := range []string{"user", "role", "server_id"} {
		l, err := lockV2Of(Lock{Name: "l1", TargetKind: kind, Target: "x", Message: "incident", ExpiresAt: exp, CreatedBy: "u1"})
		if err != nil {
			t.Fatal(err)
		}
		if got := lockOf(l); got.TargetKind != kind || got.Target != "x" || got.Message != "incident" || !got.ExpiresAt.Equal(exp) || got.CreatedBy != "u1" {
			t.Fatalf("lock %+v", got)
		}
	}
	l, _ := lockV2Of(Lock{Name: "l2", TargetKind: "user", Target: "bob", Message: "m", CreatedBy: "tangra-user"})
	l.Spec.CreatedBy = "tangra-mgmt" // Teleport records its own author
	if got := lockOf(l); got.CreatedBy != "tangra-user" {
		t.Fatalf("the tangra author is lost: %+v", got)
	}
	if l.LockExpiry() != nil {
		t.Fatal("a lock without expiry got one")
	}
	if _, err := lockV2Of(Lock{Name: "l3", TargetKind: "login", Target: "root"}); !trace.IsBadParameter(err) {
		t.Fatalf("unknown target kind: %v", err)
	}
	r, _ := types.NewRole("editor", types.RoleSpecV6{})
	r.SetStaticLabels(map[string]string{types.TeleportInternalResourceType: types.PresetResource})
	if !roleOf(r).Preset {
		t.Fatal("the preset label is not detected")
	}
}

func TestFakeUserWrites(t *testing.T) {
	f := NewFake()
	f.Info.ClusterName = "prod.example.com"
	c := Limit(f, Limits{})
	u, err := c.CreateUser(ctx, UserSpec{Name: "alice", Roles: []string{"access"}, Logins: []string{"ubuntu"}})
	if err != nil || u.Revision == "" || u.Created.IsZero() {
		t.Fatalf("create %+v %v", u, err)
	}
	if _, err := c.CreateUser(ctx, UserSpec{Name: "alice"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate %v", err)
	}
	if _, err := c.UpdateUser(ctx, UserSpec{Name: "alice", Roles: []string{"editor"}, Revision: "stale"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision %v", err)
	}
	up, err := c.UpdateUser(ctx, UserSpec{Name: "alice", Roles: []string{"editor"}, Logins: []string{"root"}, Revision: u.Revision})
	if err != nil || up.Revision == u.Revision || up.Roles[0] != "editor" || up.Logins[0] != "root" {
		t.Fatalf("update %+v %v", up, err)
	}
	if _, err := c.UpdateUser(ctx, UserSpec{Name: "nobody", Revision: "1"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing %v", err)
	}
	tok, err := c.CreateUserToken(ctx, "alice", UserTokenInvite, 0)
	if err != nil || tok.URL.IsZero() || !tok.ExpiresAt.After(time.Now()) {
		t.Fatalf("token %+v %v", tok, err)
	}
	if s := fmt.Sprint(tok); strings.Contains(s, "https://") {
		t.Fatalf("a printed token reveals its URL: %s", s)
	}
	if urls := f.IssuedURLs(); len(urls) != 1 || urls[0] != string(tok.URL.Reveal()) {
		t.Fatalf("issued %v", urls)
	}
	if _, err := c.CreateUserToken(ctx, "nobody", UserTokenReset, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("token for a missing user %v", err)
	}
	if _, err := c.CreateUserToken(ctx, "alice", "bogus", 0); !errors.Is(err, ErrRejected) {
		t.Fatalf("unknown token kind %v", err)
	}
	if err := c.DeleteUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteUser(ctx, "alice"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice %v", err)
	}
}

func TestFakeRoleWrites(t *testing.T) {
	f := NewFake()
	f.Roles = []Role{{Name: "access", Preset: true, Revision: "1"}}
	c := Limit(f, Limits{})
	def, err := c.GetRoleDefinition(ctx, "access")
	if err != nil || def.GetName() != "access" || def.GetRevision() != "1" || def.GetStaticLabels()[types.TeleportInternalResourceType] != types.PresetResource {
		t.Fatalf("synthesized definition %+v %v", def, err)
	}
	if _, err := c.GetRoleDefinition(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing role %v", err)
	}
	r, _ := types.NewRole("dev", types.RoleSpecV6{Allow: types.RoleConditions{Logins: []string{"dev"}}})
	created, err := c.CreateRole(ctx, r.(*types.RoleV6))
	if err != nil || created.Name != "dev" || created.Revision == "" {
		t.Fatalf("create %+v %v", created, err)
	}
	if _, err := c.CreateRole(ctx, r.(*types.RoleV6)); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate %v", err)
	}
	stale := r.(*types.RoleV6)
	stale.SetRevision("stale")
	if _, err := c.UpdateRole(ctx, stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale %v", err)
	}
	stale.SetRevision(created.Revision)
	stale.Spec.Allow.Logins = []string{"dev", "ops"}
	updated, err := c.UpdateRole(ctx, stale)
	if err != nil || updated.Revision == created.Revision {
		t.Fatalf("update %+v %v", updated, err)
	}
	got, _ := c.GetRoleDefinition(ctx, "dev")
	if len(got.Spec.Allow.Logins) != 2 {
		t.Fatalf("stored %+v", got.Spec.Allow)
	}
	got.Spec.Allow.Logins = nil // a returned definition is a copy
	if again, _ := c.GetRoleDefinition(ctx, "dev"); len(again.Spec.Allow.Logins) != 2 {
		t.Fatal("the fake shares its stored definition")
	}
	if err := c.DeleteRole(ctx, "dev"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetRole(ctx, "dev"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted role %v", err)
	}
	if err := c.DeleteRole(ctx, "dev"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice %v", err)
	}
}

func TestFakeLockWrites(t *testing.T) {
	f := NewFake()
	c := Limit(f, Limits{})
	if err := c.UpsertLock(ctx, Lock{Name: "l1", TargetKind: "user", Target: "alice", Message: "incident", CreatedBy: "u1"}); err != nil {
		t.Fatal(err)
	}
	if err := c.UpsertLock(ctx, Lock{Name: "l2", TargetKind: "nope", Target: "x"}); !errors.Is(err, ErrRejected) {
		t.Fatalf("bad target %v", err)
	}
	ls, _ := c.ListLocks(ctx)
	if len(ls) != 1 || ls[0].Target != "alice" || ls[0].CreatedBy != "u1" {
		t.Fatalf("locks %+v", ls)
	}
	if err := c.DeleteLock(ctx, "l1"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteLock(ctx, "l1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice %v", err)
	}
	f.FailNext("UpsertLock", trace.BadParameter("bad lock\nsecond line"))
	if err := c.UpsertLock(ctx, Lock{Name: "l3", TargetKind: "user", Target: "a"}); Detail(err) != "bad lock" || Detail(errors.New("x")) != "" {
		t.Fatalf("detail %q", Detail(err))
	}
	f.FailNext("UpsertLock", trace.AccessDenied("denied"))
	if err := c.UpsertLock(ctx, Lock{Name: "l3", TargetKind: "user", Target: "a"}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("injected %v", err)
	}
}
