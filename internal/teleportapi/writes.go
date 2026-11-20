package teleportapi

import (
	"context"
	"time"

	tclient "github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
)

// The writes of US2 (users, roles, locks). Updates are conditional on the
// revision the caller read (research D5): the current object is read first
// and a different revision is trace.CompareFailed (conflict); the revision
// is also sent with the write, so a cluster that compares revisions itself
// closes the remaining race.

// UserSpec is a user write. Labels are applied on create only; Revision is
// the revision read (update only).
type UserSpec struct {
	Name     string
	Roles    []string
	Logins   []string
	Labels   map[string]string
	Revision string
}

// User token kinds (Teleport's reset-password token types).
const (
	UserTokenInvite = "invite"   // sign-up link of a new user
	UserTokenReset  = "password" // password and second-factor reset
)

// UserToken is a one-time sign-up or reset link. The URL stays a
// secrets.Secret until the one response that returns it (SR-002).
type UserToken struct {
	URL       secrets.Secret
	ExpiresAt time.Time
}

// Lock target kinds.
const (
	LockTargetUser     = "user"
	LockTargetRole     = "role"
	LockTargetServerID = "server_id"
)

// LabelLockAuthor carries the tangra author of a lock (Teleport records its
// own author, the management identity, in CreatedBy).
const LabelLockAuthor = "tangra.io/created-by"

// LockTargetKinds lists the lock targets the module offers.
var LockTargetKinds = []string{LockTargetUser, LockTargetRole, LockTargetServerID}

// IsPreset reports a Teleport built-in role: the preset resource-type label
// (research D6) or the defaults origin.
func IsPreset(r types.Role) bool {
	if r == nil {
		return false
	}
	return r.GetStaticLabels()[types.TeleportInternalResourceType] == types.PresetResource || r.Origin() == types.OriginDefaults
}

func newUserV2(s UserSpec) (*types.UserV2, error) {
	u, err := types.NewUser(s.Name)
	if err != nil {
		return nil, err
	}
	uv, ok := u.(*types.UserV2)
	if !ok {
		return nil, trace.BadParameter("unsupported user type %T", u)
	}
	uv.SetRoles(s.Roles)
	uv.SetLogins(s.Logins)
	if len(s.Labels) > 0 {
		uv.SetStaticLabels(s.Labels)
	}
	return uv, nil
}

func lockTarget(kind, target string) (types.LockTarget, error) {
	switch kind {
	case LockTargetUser:
		return types.LockTarget{User: target}, nil
	case LockTargetRole:
		return types.LockTarget{Role: target}, nil
	case LockTargetServerID:
		return types.LockTarget{ServerID: target}, nil
	}
	return types.LockTarget{}, trace.BadParameter("unsupported lock target %q", kind)
}

func lockV2Of(l Lock) (*types.LockV2, error) {
	t, err := lockTarget(l.TargetKind, l.Target)
	if err != nil {
		return nil, err
	}
	spec := types.LockSpecV2{Target: t, Message: l.Message, CreatedBy: l.CreatedBy}
	if !l.ExpiresAt.IsZero() {
		exp := l.ExpiresAt.UTC()
		spec.Expires = &exp
	}
	lk, err := types.NewLock(l.Name, spec)
	if err != nil {
		return nil, err
	}
	lv, ok := lk.(*types.LockV2)
	if !ok {
		return nil, trace.BadParameter("unsupported lock type %T", lk)
	}
	if l.CreatedBy != "" {
		lv.Metadata.Labels = map[string]string{LabelLockAuthor: l.CreatedBy}
	}
	return lv, nil
}

func staleRevision(kind, name string) error {
	return trace.CompareFailed("%s %q was changed since it was read", kind, name)
}

// ---- real

// writeAPI is the part of *tclient.Client the writes use (a test seam: the
// revision checks below are unit-tested against a stub).
type writeAPI interface {
	GetUser(ctx context.Context, name string, withSecrets bool) (types.User, error)
	CreateUser(ctx context.Context, user types.User) (types.User, error)
	UpdateUser(ctx context.Context, user types.User) (types.User, error)
	DeleteUser(ctx context.Context, user string) error
	CreateResetPasswordToken(ctx context.Context, req *proto.CreateResetPasswordTokenRequest) (types.UserToken, error)
	GetRole(ctx context.Context, name string) (types.Role, error)
	CreateRole(ctx context.Context, role types.Role) (types.Role, error)
	UpdateRole(ctx context.Context, role types.Role) (types.Role, error)
	DeleteRole(ctx context.Context, name string) error
	UpsertLock(ctx context.Context, lock types.Lock) error
	DeleteLock(ctx context.Context, name string) error
}

var _ writeAPI = (*tclient.Client)(nil)

func (r *real) CreateUser(ctx context.Context, s UserSpec) (User, error) {
	u, err := newUserV2(s)
	if err != nil {
		return User{}, err
	}
	created, err := r.w.CreateUser(ctx, u)
	if err != nil {
		return User{}, err
	}
	return userOf(created), nil
}

func (r *real) UpdateUser(ctx context.Context, s UserSpec) (User, error) {
	cur, err := r.w.GetUser(ctx, s.Name, false)
	if err != nil {
		return User{}, err
	}
	if cur.GetRevision() != s.Revision {
		return User{}, staleRevision("user", s.Name)
	}
	cur.SetRoles(s.Roles)
	cur.SetLogins(s.Logins)
	cur.SetRevision(s.Revision)
	updated, err := r.w.UpdateUser(ctx, cur)
	if err != nil {
		return User{}, err
	}
	return userOf(updated), nil
}

func (r *real) DeleteUser(ctx context.Context, name string) error { return r.w.DeleteUser(ctx, name) }

func (r *real) CreateUserToken(ctx context.Context, name, kind string, ttl time.Duration) (UserToken, error) {
	if kind != UserTokenInvite && kind != UserTokenReset {
		return UserToken{}, trace.BadParameter("unsupported user token kind %q", kind)
	}
	tok, err := r.w.CreateResetPasswordToken(ctx, &proto.CreateResetPasswordTokenRequest{Name: name, Type: kind, TTL: proto.Duration(ttl)})
	if err != nil {
		return UserToken{}, err
	}
	return UserToken{URL: secrets.NewSecret([]byte(tok.GetURL())), ExpiresAt: tok.Expiry()}, nil
}

func (r *real) GetRoleDefinition(ctx context.Context, name string) (*types.RoleV6, error) {
	ro, err := r.w.GetRole(ctx, name)
	if err != nil {
		return nil, err
	}
	rv, ok := ro.(*types.RoleV6)
	if !ok {
		return nil, trace.BadParameter("unsupported role type %T", ro)
	}
	return rv, nil
}

func (r *real) CreateRole(ctx context.Context, role *types.RoleV6) (Role, error) {
	created, err := r.w.CreateRole(ctx, role)
	if err != nil {
		return Role{}, err
	}
	return roleOf(created), nil
}

func (r *real) UpdateRole(ctx context.Context, role *types.RoleV6) (Role, error) {
	cur, err := r.w.GetRole(ctx, role.GetName())
	if err != nil {
		return Role{}, err
	}
	if cur.GetRevision() != role.GetRevision() {
		return Role{}, staleRevision("role", role.GetName())
	}
	updated, err := r.w.UpdateRole(ctx, role)
	if err != nil {
		return Role{}, err
	}
	return roleOf(updated), nil
}

func (r *real) DeleteRole(ctx context.Context, name string) error { return r.w.DeleteRole(ctx, name) }

func (r *real) UpsertLock(ctx context.Context, l Lock) error {
	lk, err := lockV2Of(l)
	if err != nil {
		return err
	}
	return r.w.UpsertLock(ctx, lk)
}

func (r *real) DeleteLock(ctx context.Context, name string) error { return r.w.DeleteLock(ctx, name) }

// ---- limited

func (c *limited) CreateUser(ctx context.Context, s UserSpec) (User, error) {
	return call(c, ctx, func(ctx context.Context) (User, error) { return c.inner.CreateUser(ctx, s) })
}

func (c *limited) UpdateUser(ctx context.Context, s UserSpec) (User, error) {
	return call(c, ctx, func(ctx context.Context) (User, error) { return c.inner.UpdateUser(ctx, s) })
}

func (c *limited) DeleteUser(ctx context.Context, name string) error {
	return do(c, ctx, func(ctx context.Context) error { return c.inner.DeleteUser(ctx, name) })
}

func (c *limited) CreateUserToken(ctx context.Context, name, kind string, ttl time.Duration) (UserToken, error) {
	return call(c, ctx, func(ctx context.Context) (UserToken, error) { return c.inner.CreateUserToken(ctx, name, kind, ttl) })
}

func (c *limited) GetRoleDefinition(ctx context.Context, name string) (*types.RoleV6, error) {
	return call(c, ctx, func(ctx context.Context) (*types.RoleV6, error) { return c.inner.GetRoleDefinition(ctx, name) })
}

func (c *limited) CreateRole(ctx context.Context, role *types.RoleV6) (Role, error) {
	return call(c, ctx, func(ctx context.Context) (Role, error) { return c.inner.CreateRole(ctx, role) })
}

func (c *limited) UpdateRole(ctx context.Context, role *types.RoleV6) (Role, error) {
	return call(c, ctx, func(ctx context.Context) (Role, error) { return c.inner.UpdateRole(ctx, role) })
}

func (c *limited) DeleteRole(ctx context.Context, name string) error {
	return do(c, ctx, func(ctx context.Context) error { return c.inner.DeleteRole(ctx, name) })
}

func (c *limited) UpsertLock(ctx context.Context, l Lock) error {
	return do(c, ctx, func(ctx context.Context) error { return c.inner.UpsertLock(ctx, l) })
}

func (c *limited) DeleteLock(ctx context.Context, name string) error {
	return do(c, ctx, func(ctx context.Context) error { return c.inner.DeleteLock(ctx, name) })
}

func do(c *limited, ctx context.Context, fn func(context.Context) error) error {
	_, err := call(c, ctx, func(ctx context.Context) (struct{}, error) { return struct{}{}, fn(ctx) })
	return err
}
