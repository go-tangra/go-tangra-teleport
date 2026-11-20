// Package teleportapi is the module's only door to a Teleport cluster
// (research D1): an abstract Client, its implementation over the
// Apache-2.0 `github.com/gravitational/teleport/api` module (never `lib/`),
// a scriptable Fake, per-cluster limits (10 s per call, 4 MiB per message, 4
// calls in flight), a pool keyed by cluster and credential, and a short read
// cache. Every error is mapped to a module reason (errors.go); identity files
// travel only as secrets.Secret and never reach logs or errors.
//
// The connection goes through the cluster's public proxy address with TLS
// routing (ALPN "teleport-auth@<cluster>") over the netguard dialler, which
// is pinned to the checked IP of the registered proxy address — whatever
// address teleport/api asks for (research D12).
package teleportapi

import (
	"context"
	"math"
	"net"
	"time"

	tclient "github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	userspb "github.com/gravitational/teleport/api/gen/proto/go/teleport/users/v1"
	"github.com/gravitational/teleport/api/types"
	"google.golang.org/grpc"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
)

// Editions (research D13).
const (
	EditionCommunity  = "community"
	EditionEnterprise = "enterprise"
)

// Resource kinds listed by ListResources.
const (
	KindNode    = types.KindNode
	KindApp     = types.KindAppServer
	KindDB      = types.KindDatabaseServer
	KindKube    = types.KindKubeServer
	KindDesktop = types.KindWindowsDesktop
)

// Info is what Ping reports.
type Info struct {
	ClusterName   string
	ServerVersion string
	Edition       string
}

// User is a Teleport user (never with secrets).
type User struct {
	Name     string
	Roles    []string
	Logins   []string
	Labels   map[string]string
	Created  time.Time
	Revision string
}

// Role is a Teleport role summary.
type Role struct {
	Name     string
	Preset   bool
	Revision string
}

// Lock is an active Teleport lock.
type Lock struct {
	Name       string
	TargetKind string // user | role | server_id
	Target     string
	Message    string
	CreatedBy  string
	ExpiresAt  time.Time
}

// Resource is one enrolled resource.
type Resource struct {
	Kind     string
	Name     string
	Hostname string
	Addr     string
	Labels   map[string]string
	Version  string
}

// ListOptions page a Teleport list (opaque Next cursor). Labels and Search
// filter ListResources on the cluster (exact labels; keywords matched
// against names, hostnames and labels).
type ListOptions struct {
	Limit  int
	Next   string
	Labels map[string]string
	Search []string
}

// Page is one page of a Teleport list.
type Page[T any] struct {
	Items []T
	Next  string
}

// Client is the module's view of one cluster. Story phases extend it with
// writes; every method returns errors mapped by MapError.
type Client interface {
	Ping(ctx context.Context) (Info, error)
	ListUsers(ctx context.Context, o ListOptions) (Page[User], error)
	GetUser(ctx context.Context, name string) (User, error)
	ListRoles(ctx context.Context, o ListOptions) (Page[Role], error)
	GetRole(ctx context.Context, name string) (Role, error)
	ListLocks(ctx context.Context) ([]Lock, error)
	ListResources(ctx context.Context, kind string, o ListOptions) (Page[Resource], error)
	// ProbeRead checks read access to one ProbeKinds kind (research D3).
	ProbeRead(ctx context.Context, kind string) error

	// Writes (US2, writes.go). Updates compare the revision read (D5).
	CreateUser(ctx context.Context, s UserSpec) (User, error)
	UpdateUser(ctx context.Context, s UserSpec) (User, error)
	DeleteUser(ctx context.Context, name string) error
	// CreateUserToken issues a one-time invite or reset link (ttl 0: the
	// cluster's default).
	CreateUserToken(ctx context.Context, name, kind string, ttl time.Duration) (UserToken, error)
	// GetRoleDefinition returns the full role (for YAML editing).
	GetRoleDefinition(ctx context.Context, name string) (*types.RoleV6, error)
	CreateRole(ctx context.Context, role *types.RoleV6) (Role, error)
	// UpdateRole writes role if its Metadata.Revision is still current.
	UpdateRole(ctx context.Context, role *types.RoleV6) (Role, error)
	DeleteRole(ctx context.Context, name string) error
	UpsertLock(ctx context.Context, l Lock) error
	DeleteLock(ctx context.Context, name string) error

	// Enrollment (US3, enroll.go). Token names never leave IssuedToken;
	// DeleteJoinToken finds the token by the stored TokenHash.
	CreateJoinToken(ctx context.Context, s JoinTokenSpec) (IssuedToken, error)
	DeleteJoinToken(ctx context.Context, hash []byte) error
	// CAPins returns the cluster's TLS CA pins ("sha256:<hex SPKI digest>"),
	// what a joining node verifies the cluster with (spec 002).
	CAPins(ctx context.Context) ([]string, error)
	// Watch opens a change watch on kinds (WatchKinds).
	Watch(ctx context.Context, kinds []string) (Watcher, error)

	// Audit (US4, auditlog.go).
	SearchEvents(ctx context.Context, q EventQuery) (Page[AuditEvent], error)
	SearchSessions(ctx context.Context, q EventQuery) (Page[AuditEvent], error)

	Close() error
}

// DialParams name one cluster connection.
type DialParams struct {
	ProxyAddr string          // host:port as registered
	Identity  secrets.Secret  // the identity file
	Guard     *netguard.Guard // SSRF guard (required)
	Limits    Limits
}

// DialOptions are the gRPC options every cluster connection carries: the
// per-message receive and send caps.
func DialOptions(l Limits) []grpc.DialOption {
	l = l.withDefaults()
	return []grpc.DialOption{grpc.WithDefaultCallOptions(
		grpc.MaxCallRecvMsgSize(l.MaxMessageBytes),
		grpc.MaxCallSendMsgSize(l.MaxMessageBytes),
	)}
}

// Dial connects to a cluster through its proxy and returns the limited client.
func Dial(ctx context.Context, p DialParams) (Client, error) {
	if p.Guard == nil {
		return nil, ErrBlockedTarget
	}
	id, err := ParseIdentity(p.Identity)
	if err != nil {
		return nil, err
	}
	// Resolve and check now so a blocked address fails as blocked_target.
	if _, err := p.Guard.Resolve(ctx, p.ProxyAddr); err != nil {
		return nil, ErrBlockedTarget
	}
	pinned := p.Guard.Dialer(p.ProxyAddr)
	l := p.Limits.withDefaults()
	c, err := tclient.New(ctx, tclient.Config{
		Dialer: tclient.ContextDialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
			return pinned(ctx, network, p.ProxyAddr)
		}),
		Credentials:                []tclient.Credentials{tclient.LoadIdentityFileFromString(string(p.Identity.Reveal()))},
		ALPNSNIAuthDialClusterName: id.ClusterName,
		DialTimeout:                l.CallTimeout,
		DialOpts:                   DialOptions(l),
	})
	if err != nil {
		return nil, MapError(err)
	}
	return Limit(&real{c: c, w: c, e: c}, l), nil
}

// real adapts *tclient.Client to Client (errors are mapped by Limit); w and
// e are the same client, seen through the writes and the enrollment and
// audit calls they use (test seams).
type real struct {
	c *tclient.Client
	w writeAPI
	e enrollAPI
}

func (r *real) Ping(ctx context.Context) (Info, error) {
	res, err := r.c.Ping(ctx)
	if err != nil {
		return Info{}, err
	}
	ed := EditionCommunity
	if f := res.GetServerFeatures(); f != nil && f.GetAdvancedAccessWorkflows() {
		ed = EditionEnterprise
	}
	return Info{ClusterName: res.ClusterName, ServerVersion: res.ServerVersion, Edition: ed}, nil
}

func userOf(u types.User) User {
	return User{Name: u.GetName(), Roles: u.GetRoles(), Logins: u.GetTraits()["logins"], Labels: u.GetAllLabels(),
		Created: u.GetCreatedBy().Time, Revision: u.GetRevision()}
}

// pageSize converts a page limit for the Teleport API, clamped to int32.
func pageSize(n int) int32 {
	switch {
	case n <= 0:
		return 0
	case n > math.MaxInt32:
		return math.MaxInt32
	}
	return int32(n)
}

func (r *real) ListUsers(ctx context.Context, o ListOptions) (Page[User], error) {
	res, err := r.c.ListUsers(ctx, &userspb.ListUsersRequest{PageSize: pageSize(o.Limit), PageToken: o.Next})
	if err != nil {
		return Page[User]{}, err
	}
	out := Page[User]{Next: res.GetNextPageToken()}
	for _, u := range res.GetUsers() {
		out.Items = append(out.Items, userOf(u))
	}
	return out, nil
}

func (r *real) GetUser(ctx context.Context, name string) (User, error) {
	u, err := r.c.GetUser(ctx, name, false)
	if err != nil {
		return User{}, err
	}
	return userOf(u), nil
}

func roleOf(ro types.Role) Role {
	return Role{Name: ro.GetName(), Preset: IsPreset(ro), Revision: ro.GetRevision()}
}

func (r *real) ListRoles(ctx context.Context, o ListOptions) (Page[Role], error) {
	res, err := r.c.ListRoles(ctx, &proto.ListRolesRequest{Limit: pageSize(o.Limit), StartKey: o.Next})
	if err != nil {
		return Page[Role]{}, err
	}
	out := Page[Role]{Next: res.NextKey}
	for _, ro := range res.Roles {
		out.Items = append(out.Items, roleOf(ro))
	}
	return out, nil
}

func (r *real) GetRole(ctx context.Context, name string) (Role, error) {
	ro, err := r.c.GetRole(ctx, name)
	if err != nil {
		return Role{}, err
	}
	return roleOf(ro), nil
}

func lockOf(l types.Lock) Lock {
	out := Lock{Name: l.GetName(), Message: l.Message(), CreatedBy: l.CreatedBy()}
	if a := l.GetMetadata().Labels[LabelLockAuthor]; a != "" {
		out.CreatedBy = a
	}
	if exp := l.LockExpiry(); exp != nil {
		out.ExpiresAt = *exp
	}
	t := l.Target()
	switch {
	case t.User != "":
		out.TargetKind, out.Target = "user", t.User
	case t.Role != "":
		out.TargetKind, out.Target = "role", t.Role
	case t.ServerID != "":
		out.TargetKind, out.Target = "server_id", t.ServerID
	}
	return out
}

func (r *real) ListLocks(ctx context.Context) ([]Lock, error) {
	ls, err := r.c.GetLocks(ctx, true)
	if err != nil {
		return nil, err
	}
	out := make([]Lock, 0, len(ls))
	for _, l := range ls {
		out = append(out, lockOf(l))
	}
	return out, nil
}

func (r *real) ListResources(ctx context.Context, kind string, o ListOptions) (Page[Resource], error) {
	res, err := r.c.ListResources(ctx, proto.ListResourcesRequest{ResourceType: kind, Limit: pageSize(o.Limit), StartKey: o.Next,
		Labels: o.Labels, SearchKeywords: o.Search})
	if err != nil {
		return Page[Resource]{}, err
	}
	out := Page[Resource]{Next: res.NextKey}
	for _, rs := range res.Resources {
		out.Items = append(out.Items, resourceOf(rs))
	}
	return out, nil
}

func (r *real) Close() error { return r.c.Close() }

var _ Client = (*real)(nil)
