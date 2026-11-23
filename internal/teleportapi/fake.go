package teleportapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
)

// Fake is a scriptable in-memory Client. Set its fields to the cluster
// state, FailNext to inject one error into a method, SetErr to fail every
// call (an outage) and Denied to refuse probes; Calls counts calls. Writes
// keep the fields current: every write gets a new revision, and an update
// with a revision other than the stored one is trace.CompareFailed, as on a
// real cluster. Role definitions written through the fake are kept in full;
// a role only listed in Roles is synthesized (with the preset label when
// Preset is set). IssuedURLs lists every invite and reset URL handed out, so
// leak tests can look for them in every output channel.
// Errors are returned raw (as teleport/api would), so wrap it with Limit to
// get mapped errors.
type Fake struct {
	mu        sync.Mutex
	Info      Info
	Users     []User
	Roles     []Role
	Locks     []Lock
	Resources []Resource
	Denied    map[string]bool // ProbeRead kinds answered with an access denial
	// AuditEvents and SessionEvents are searched by SearchEvents and
	// SearchSessions (by time and type).
	AuditEvents   []AuditEvent
	SessionEvents []AuditEvent
	// Recordings are streamed by StreamRecording by session id (an event's
	// Index is its position); a missing id is trace.NotFound. RecordingErr
	// is sent after a recording's events (a cut mid-playback).
	Recordings   map[string][]RecordingEvent
	RecordingErr map[string]error

	// CACerts is the PEM the fake's CAPins reads (nil: one generated CA).
	CACerts []byte
	// TokenPrefix prefixes issued join-token names (a redaction sentinel).
	TokenPrefix string

	tokens   map[string]fakeToken // join tokens by name (fake_enroll.go)
	issued   []string             // every join-token name handed out
	watchers []*FakeWatcher

	defs   map[string]*types.RoleV6
	urls   []string
	rev    int
	fail   map[string]error
	down   error
	calls  map[string]int
	closed bool
}

// NewFake builds an empty fake.
func NewFake() *Fake { return &Fake{} }

// FailNext makes the next call to method return err.
func (f *Fake) FailNext(method string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail == nil {
		f.fail = map[string]error{}
	}
	f.fail[method] = err
}

// SetErr makes every call fail with err until SetErr(nil).
func (f *Fake) SetErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = err
}

// Calls is the number of calls to method.
func (f *Fake) Calls(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[method]
}

// Closed reports whether Close was called.
func (f *Fake) Closed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// enter counts the call and returns any injected error. Callers hold mu.
func (f *Fake) enter(method string) error {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[method]++
	if err, ok := f.fail[method]; ok {
		delete(f.fail, method)
		return err
	}
	return f.down
}

// page slices items by an offset cursor.
func page[T any](items []T, o ListOptions) (Page[T], error) {
	start := 0
	if o.Next != "" {
		n, err := strconv.Atoi(o.Next)
		if err != nil || n < 0 || n > len(items) {
			return Page[T]{}, trace.BadParameter("invalid page token")
		}
		start = n
	}
	end := len(items)
	if o.Limit > 0 && start+o.Limit < end {
		end = start + o.Limit
	}
	p := Page[T]{Items: slices.Clone(items[start:end])}
	if end < len(items) {
		p.Next = strconv.Itoa(end)
	}
	return p, nil
}

// Ping implements Client.
func (f *Fake) Ping(context.Context) (Info, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("Ping"); err != nil {
		return Info{}, err
	}
	return f.Info, nil
}

// ListUsers implements Client.
func (f *Fake) ListUsers(_ context.Context, o ListOptions) (Page[User], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("ListUsers"); err != nil {
		return Page[User]{}, err
	}
	return page(f.Users, o)
}

// GetUser implements Client.
func (f *Fake) GetUser(_ context.Context, name string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("GetUser"); err != nil {
		return User{}, err
	}
	for _, u := range f.Users {
		if u.Name == name {
			return u, nil
		}
	}
	return User{}, trace.NotFound("user %q is not found", name)
}

// ListRoles implements Client.
func (f *Fake) ListRoles(_ context.Context, o ListOptions) (Page[Role], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("ListRoles"); err != nil {
		return Page[Role]{}, err
	}
	return page(f.Roles, o)
}

// GetRole implements Client.
func (f *Fake) GetRole(_ context.Context, name string) (Role, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("GetRole"); err != nil {
		return Role{}, err
	}
	for _, r := range f.Roles {
		if r.Name == name {
			return r, nil
		}
	}
	return Role{}, trace.NotFound("role %q is not found", name)
}

// ListLocks implements Client.
func (f *Fake) ListLocks(context.Context) ([]Lock, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("ListLocks"); err != nil {
		return nil, err
	}
	return slices.Clone(f.Locks), nil
}

// ListResources implements Client.
func (f *Fake) ListResources(_ context.Context, kind string, o ListOptions) (Page[Resource], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("ListResources"); err != nil {
		return Page[Resource]{}, err
	}
	var of []Resource
	for _, r := range f.Resources {
		if r.Kind == kind && labelsMatch(r.Labels, o.Labels) && keywordsMatch(r, o.Search) {
			of = append(of, r)
		}
	}
	return page(of, o)
}

// IssuedURLs lists every invite and reset URL the fake handed out.
func (f *Fake) IssuedURLs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.urls)
}

// nextRev returns a fresh revision. Callers hold mu.
func (f *Fake) nextRev() string {
	f.rev++
	return "fake-rev-" + strconv.Itoa(f.rev)
}

func (f *Fake) userIndex(name string) int {
	return slices.IndexFunc(f.Users, func(u User) bool { return u.Name == name })
}

func (f *Fake) roleIndex(name string) int {
	return slices.IndexFunc(f.Roles, func(r Role) bool { return r.Name == name })
}

// CreateUser implements Client.
func (f *Fake) CreateUser(_ context.Context, s UserSpec) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("CreateUser"); err != nil {
		return User{}, err
	}
	if s.Name == "" {
		return User{}, trace.BadParameter("missing user name")
	}
	if f.userIndex(s.Name) >= 0 {
		return User{}, trace.AlreadyExists("user %q already registered", s.Name)
	}
	u := User{Name: s.Name, Roles: slices.Clone(s.Roles), Logins: slices.Clone(s.Logins), Labels: s.Labels,
		Created: time.Now().UTC(), Revision: f.nextRev()}
	f.Users = append(f.Users, u)
	return u, nil
}

// UpdateUser implements Client.
func (f *Fake) UpdateUser(_ context.Context, s UserSpec) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("UpdateUser"); err != nil {
		return User{}, err
	}
	i := f.userIndex(s.Name)
	if i < 0 {
		return User{}, trace.NotFound("user %q is not found", s.Name)
	}
	if f.Users[i].Revision != s.Revision {
		return User{}, staleRevision("user", s.Name)
	}
	u := f.Users[i]
	u.Roles, u.Logins, u.Revision = slices.Clone(s.Roles), slices.Clone(s.Logins), f.nextRev()
	f.Users[i] = u
	return u, nil
}

// DeleteUser implements Client.
func (f *Fake) DeleteUser(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("DeleteUser"); err != nil {
		return err
	}
	i := f.userIndex(name)
	if i < 0 {
		return trace.NotFound("user %q is not found", name)
	}
	f.Users = slices.Delete(f.Users, i, i+1)
	return nil
}

// CreateUserToken implements Client: a random URL on the fake's cluster,
// valid for ttl (1 hour by default).
func (f *Fake) CreateUserToken(_ context.Context, name, kind string, ttl time.Duration) (UserToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("CreateUserToken"); err != nil {
		return UserToken{}, err
	}
	if kind != UserTokenInvite && kind != UserTokenReset {
		return UserToken{}, trace.BadParameter("unsupported user token kind %q", kind)
	}
	if f.userIndex(name) < 0 {
		return UserToken{}, trace.NotFound("user %q is not found", name)
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	path := "invite"
	if kind == UserTokenReset {
		path = "reset"
	}
	url := "https://" + f.Info.ClusterName + "/web/" + path + "/" + hex.EncodeToString(b)
	f.urls = append(f.urls, url)
	return UserToken{URL: secrets.NewSecret([]byte(url)), ExpiresAt: time.Now().Add(ttl).UTC()}, nil
}

// GetRoleDefinition implements Client (a copy of the stored definition).
func (f *Fake) GetRoleDefinition(_ context.Context, name string) (*types.RoleV6, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("GetRoleDefinition"); err != nil {
		return nil, err
	}
	i := f.roleIndex(name)
	if i < 0 {
		return nil, trace.NotFound("role %q is not found", name)
	}
	if d, ok := f.defs[name]; ok {
		return cloneRole(d), nil
	}
	r, err := types.NewRole(name, types.RoleSpecV6{})
	if err != nil {
		return nil, err
	}
	rv := r.(*types.RoleV6)
	if f.Roles[i].Preset {
		rv.SetStaticLabels(map[string]string{types.TeleportInternalResourceType: types.PresetResource})
	}
	rv.SetRevision(f.Roles[i].Revision)
	return rv, nil
}

func cloneRole(r *types.RoleV6) *types.RoleV6 {
	c, ok := r.Clone().(*types.RoleV6)
	if !ok {
		return r
	}
	return c
}

// storeRole keeps a copy of role with a new revision. Callers hold mu.
func (f *Fake) storeRole(role *types.RoleV6) Role {
	d := cloneRole(role)
	d.SetRevision(f.nextRev())
	if f.defs == nil {
		f.defs = map[string]*types.RoleV6{}
	}
	f.defs[d.GetName()] = d
	sum := roleOf(d)
	if i := f.roleIndex(d.GetName()); i >= 0 {
		f.Roles[i] = sum
	} else {
		f.Roles = append(f.Roles, sum)
	}
	return sum
}

// CreateRole implements Client.
func (f *Fake) CreateRole(_ context.Context, role *types.RoleV6) (Role, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("CreateRole"); err != nil {
		return Role{}, err
	}
	if f.roleIndex(role.GetName()) >= 0 {
		return Role{}, trace.AlreadyExists("role %q already exists", role.GetName())
	}
	return f.storeRole(role), nil
}

// UpdateRole implements Client.
func (f *Fake) UpdateRole(_ context.Context, role *types.RoleV6) (Role, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("UpdateRole"); err != nil {
		return Role{}, err
	}
	i := f.roleIndex(role.GetName())
	if i < 0 {
		return Role{}, trace.NotFound("role %q is not found", role.GetName())
	}
	if f.Roles[i].Revision != role.GetRevision() {
		return Role{}, staleRevision("role", role.GetName())
	}
	return f.storeRole(role), nil
}

// DeleteRole implements Client.
func (f *Fake) DeleteRole(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("DeleteRole"); err != nil {
		return err
	}
	i := f.roleIndex(name)
	if i < 0 {
		return trace.NotFound("role %q is not found", name)
	}
	f.Roles = slices.Delete(f.Roles, i, i+1)
	delete(f.defs, name)
	return nil
}

// UpsertLock implements Client.
func (f *Fake) UpsertLock(_ context.Context, l Lock) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("UpsertLock"); err != nil {
		return err
	}
	if _, err := lockTarget(l.TargetKind, l.Target); err != nil {
		return err
	}
	if i := slices.IndexFunc(f.Locks, func(x Lock) bool { return x.Name == l.Name }); i >= 0 {
		f.Locks[i] = l
		return nil
	}
	f.Locks = append(f.Locks, l)
	return nil
}

// DeleteLock implements Client.
func (f *Fake) DeleteLock(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("DeleteLock"); err != nil {
		return err
	}
	i := slices.IndexFunc(f.Locks, func(x Lock) bool { return x.Name == name })
	if i < 0 {
		return trace.NotFound("lock %q is not found", name)
	}
	f.Locks = slices.Delete(f.Locks, i, i+1)
	return nil
}

// Close implements Client.
func (f *Fake) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

var _ Client = (*Fake)(nil)
