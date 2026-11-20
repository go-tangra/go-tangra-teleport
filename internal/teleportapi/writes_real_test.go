package teleportapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
)

// stubAPI records what the real adapter sends to Teleport.
type stubAPI struct {
	user     types.User
	role     types.Role
	sent     any
	tokenReq *proto.CreateResetPasswordTokenRequest
	lock     types.Lock
	deleted  string
	err      error
}

func (s *stubAPI) GetUser(context.Context, string, bool) (types.User, error) { return s.user, s.err }
func (s *stubAPI) CreateUser(_ context.Context, u types.User) (types.User, error) {
	s.sent = u
	return u, s.err
}
func (s *stubAPI) UpdateUser(_ context.Context, u types.User) (types.User, error) {
	s.sent = u
	return u, s.err
}
func (s *stubAPI) DeleteUser(_ context.Context, n string) error { s.deleted = n; return s.err }
func (s *stubAPI) CreateResetPasswordToken(_ context.Context, r *proto.CreateResetPasswordTokenRequest) (types.UserToken, error) {
	s.tokenReq = r
	if s.err != nil {
		return nil, s.err
	}
	tok, err := types.NewUserToken("tok")
	if err != nil {
		return nil, err
	}
	tok.SetURL("https://prod.example.com/web/invite/tok")
	tok.SetExpiry(time.Unix(2000000000, 0))
	return tok, nil
}
func (s *stubAPI) GetRole(context.Context, string) (types.Role, error) { return s.role, s.err }
func (s *stubAPI) CreateRole(_ context.Context, r types.Role) (types.Role, error) {
	s.sent = r
	return r, s.err
}
func (s *stubAPI) UpdateRole(_ context.Context, r types.Role) (types.Role, error) {
	s.sent = r
	return r, s.err
}
func (s *stubAPI) DeleteRole(_ context.Context, n string) error     { s.deleted = n; return s.err }
func (s *stubAPI) UpsertLock(_ context.Context, l types.Lock) error { s.lock = l; return s.err }
func (s *stubAPI) DeleteLock(_ context.Context, n string) error     { s.deleted = n; return s.err }

func TestRealUserWrites(t *testing.T) {
	cur, _ := newUserV2(UserSpec{Name: "alice", Roles: []string{"access"}})
	cur.SetRevision("rev-1")
	st := &stubAPI{user: cur}
	r := &real{w: st}
	if u, err := r.CreateUser(ctx, UserSpec{Name: "bob", Roles: []string{"access"}, Logins: []string{"ubuntu"}}); err != nil || u.Name != "bob" || u.Logins[0] != "ubuntu" {
		t.Fatalf("create %+v %v", u, err)
	}
	if _, err := r.CreateUser(ctx, UserSpec{}); err == nil {
		t.Fatal("a nameless user was sent")
	}
	if _, err := r.UpdateUser(ctx, UserSpec{Name: "alice", Roles: []string{"editor"}, Revision: "stale"}); !trace.IsCompareFailed(err) {
		t.Fatalf("stale %v", err)
	}
	u, err := r.UpdateUser(ctx, UserSpec{Name: "alice", Roles: []string{"editor"}, Logins: []string{"root"}, Revision: "rev-1"})
	sent := st.sent.(types.User)
	if err != nil || u.Roles[0] != "editor" || sent.GetRevision() != "rev-1" || sent.GetLogins()[0] != "root" {
		t.Fatalf("update %+v %v (sent revision %q)", u, err, sent.GetRevision())
	}
	if err := r.DeleteUser(ctx, "alice"); err != nil || st.deleted != "alice" {
		t.Fatalf("delete %v", err)
	}
	tok, err := r.CreateUserToken(ctx, "alice", UserTokenInvite, 2*time.Hour)
	if err != nil || string(tok.URL.Reveal()) != "https://prod.example.com/web/invite/tok" || tok.ExpiresAt.Unix() != 2000000000 ||
		st.tokenReq.Type != "invite" || time.Duration(st.tokenReq.TTL) != 2*time.Hour {
		t.Fatalf("token %+v %v %+v", tok, err, st.tokenReq)
	}
	if _, err := r.CreateUserToken(ctx, "alice", "x", 0); !trace.IsBadParameter(err) {
		t.Fatalf("kind %v", err)
	}
	st.err = trace.NotFound("gone")
	for _, err := range []error{
		func() error { _, err := r.CreateUser(ctx, UserSpec{Name: "bob"}); return err }(),
		func() error { _, err := r.UpdateUser(ctx, UserSpec{Name: "alice", Revision: "rev-1"}); return err }(),
		func() error { _, err := r.CreateUserToken(ctx, "alice", UserTokenReset, 0); return err }(),
	} {
		if !trace.IsNotFound(err) {
			t.Errorf("error not passed through: %v", err)
		}
	}
}

func TestRealRoleAndLockWrites(t *testing.T) {
	cur, _ := types.NewRole("dev", types.RoleSpecV6{})
	cur.SetRevision("rev-1")
	st := &stubAPI{role: cur}
	r := &real{w: st}
	def, err := r.GetRoleDefinition(ctx, "dev")
	if err != nil || def.GetRevision() != "rev-1" {
		t.Fatalf("get %v", err)
	}
	next := def.Clone().(*types.RoleV6)
	if ro, err := r.CreateRole(ctx, next); err != nil || ro.Name != "dev" {
		t.Fatalf("create %+v %v", ro, err)
	}
	next.SetRevision("stale")
	if _, err := r.UpdateRole(ctx, next); !trace.IsCompareFailed(err) {
		t.Fatalf("stale %v", err)
	}
	next.SetRevision("rev-1")
	if _, err := r.UpdateRole(ctx, next); err != nil || st.sent.(types.Role).GetRevision() != "rev-1" {
		t.Fatalf("update %v", err)
	}
	if err := r.DeleteRole(ctx, "dev"); err != nil || st.deleted != "dev" {
		t.Fatalf("delete %v", err)
	}
	if err := r.UpsertLock(ctx, Lock{Name: "l1", TargetKind: "role", Target: "dev", Message: "m", CreatedBy: "u1"}); err != nil ||
		st.lock.Target().Role != "dev" || st.lock.GetMetadata().Labels[LabelLockAuthor] != "u1" {
		t.Fatalf("lock %v %+v", err, st.lock)
	}
	if err := r.UpsertLock(ctx, Lock{Name: "l2", TargetKind: "login"}); !trace.IsBadParameter(err) {
		t.Fatalf("bad lock %v", err)
	}
	if err := r.DeleteLock(ctx, "l1"); err != nil || st.deleted != "l1" {
		t.Fatalf("unlock %v", err)
	}
	st.err = errors.New("down")
	if _, err := r.GetRoleDefinition(ctx, "dev"); err == nil {
		t.Fatal("get error lost")
	}
	if _, err := r.CreateRole(ctx, next); err == nil {
		t.Fatal("create error lost")
	}
	if _, err := r.UpdateRole(ctx, next); err == nil {
		t.Fatal("update error lost")
	}
}
