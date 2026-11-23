// Package authz is the Teleport module's access model, adapted from dns-v4
// internal/authz. Every browser route declares one API permission
// (x-freya-permission); the module enforces it itself (defence in depth
// behind the gateway) by asking the auth service through a Checker. Callers
// are scoped to exactly one tenant.
//
// Non-human actors never go through the Checker:
//   - mesh modules (gRPC, SPIFFE-authenticated and policy allow-listed:
//     inventory, asset, portal) may only read clusters and resources of the
//     tenant named in the request (teleport.v1.Access is read-only);
//   - workers (scheduler tasks, the watcher, provisioning sync) act as
//     Worker(tenant, name): pinned to one tenant and limited to what the
//     background jobs need — never roles, join tokens or deployments, which
//     are human-only;
//   - the system scope (start-up, retention) may do everything.
//
// Cluster ownership: RequireCluster loads the cluster in the caller's tenant
// only, so another tenant's cluster id answers not_found, never forbidden —
// existence is not disclosed across tenants.
package authz

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

// Errors.
var (
	// ErrForbidden is returned when a caller lacks the required permission or scope.
	ErrForbidden = errors.New("authz: forbidden")
	// ErrUnauthenticated is returned when the context carries no subject.
	ErrUnauthenticated = errors.New("authz: unauthenticated")
)

// Actor kinds (closed set).
const (
	ActorUser   = "user"   // a signed-in platform user (via the gateway)
	ActorModule = "module" // a mesh peer (SPIFFE) acting for a tenant
	ActorWorker = "worker" // a background job pinned to one tenant
	ActorSystem = "system" // trusted internal maintenance
)

// API permissions (resource:action), contracts/http-api.md.
const (
	ClustersRead       = "clusters:read"
	ClustersManage     = "clusters:manage"
	UsersRead          = "users:read"
	UsersManage        = "users:manage"
	RolesRead          = "roles:read"
	RolesManage        = "roles:manage"
	LocksRead          = "locks:read"
	LocksManage        = "locks:manage"
	TokensManage       = "tokens:manage"
	ResourcesRead      = "resources:read"
	ResourcesLink      = "resources:link"
	ResourcesEnroll    = "resources:enroll"
	AuditRead          = "audit:read"
	AlertsRead         = "alerts:read"
	AlertsManage       = "alerts:manage"
	ProvisioningManage = "provisioning:manage"
	DeploymentsManage  = "deployments:manage"
	// SessionsPlay replays a recorded SSH session in the portal (spec 003):
	// separate from AuditRead because a recording shows everything that was
	// on the terminal. Human-only (not in moduleAllowed or workerAllowed).
	SessionsPlay = "sessions:play"
	// AccessTerminal opens an SSH terminal in the portal as the caller's
	// provisioned Teleport user; AccessDownload downloads a short-lived
	// identity file for tsh (spec 004 R13). Human-only (not in
	// moduleAllowed or workerAllowed).
	AccessTerminal = "access:terminal"
	AccessDownload = "access:download"
)

// Permissions lists every module permission.
var Permissions = []string{
	ClustersRead, ClustersManage, UsersRead, UsersManage, RolesRead, RolesManage, LocksRead, LocksManage,
	TokensManage, ResourcesRead, ResourcesLink, ResourcesEnroll, AuditRead, AlertsRead, AlertsManage, ProvisioningManage, DeploymentsManage,
	SessionsPlay, AccessTerminal, AccessDownload,
}

// moduleAllowed is what a mesh peer may do (contracts/grpc.md: Access is read-only).
var moduleAllowed = map[string]bool{ClustersRead: true, ResourcesRead: true}

// workerAllowed is what a background job may do within its tenant: health
// and status, inventory sync and links, provisioning (users and locks),
// alert evaluation, and fulfilling enrollments a user created (spec 002:
// the join token is minted when the agent fetches it). Roles, standalone
// join tokens and deployments stay human-only.
var workerAllowed = map[string]bool{
	ClustersRead: true, ClustersManage: true, UsersRead: true, UsersManage: true, LocksRead: true, LocksManage: true,
	ResourcesRead: true, ResourcesLink: true, ResourcesEnroll: true, AuditRead: true, AlertsRead: true, ProvisioningManage: true,
}

// Subjects is the authenticated caller.
type Subjects struct {
	TenantID   string
	UserID     string // user id, SPIFFE id (module) or job name (worker)
	Roles      []string
	ActorKind  string // user | module | worker | system
	PeerSPIFFE string // the verified SPIFFE ID of a module caller
	// AMR is the authentication methods of a signed-in user's portal
	// session, from the verified token only (spec 004 R3).
	AMR []string
}

// User returns the subject of a signed-in user.
func User(tenantID, userID string, roles []string) Subjects {
	return Subjects{TenantID: tenantID, UserID: userID, Roles: slices.Clone(roles), ActorKind: ActorUser}
}

// Module returns the subject of a mesh peer acting for tenantID.
func Module(tenantID, spiffeID string) Subjects {
	return Subjects{TenantID: tenantID, UserID: spiffeID, ActorKind: ActorModule, PeerSPIFFE: spiffeID}
}

// Worker returns the subject a background job acts as, pinned to tenantID
// and recorded under name.
func Worker(tenantID, name string) Subjects {
	return Subjects{TenantID: tenantID, UserID: name, ActorKind: ActorWorker}
}

// System returns the trusted system subject for one tenant.
func System(tenantID string) Subjects {
	return Subjects{TenantID: tenantID, UserID: ActorSystem, ActorKind: ActorSystem}
}

// WithAMR returns s with a copy of the session's authentication methods.
func (s Subjects) WithAMR(amr []string) Subjects {
	s.AMR = slices.Clone(amr)
	return s
}

// MFA reports whether a signed-in user's portal session was established
// with a second factor: amr carries "otp" (TOTP) or "hwk" (security key).
func (s Subjects) MFA() bool {
	return s.IsHuman() && (slices.Contains(s.AMR, "otp") || slices.Contains(s.AMR, "hwk"))
}

// HasRole reports whether the caller carries role.
func (s Subjects) HasRole(role string) bool { return slices.Contains(s.Roles, role) }

// ActorID is the user id (or SPIFFE ID / job name), falling back to the actor kind.
func (s Subjects) ActorID() string {
	if s.UserID != "" {
		return s.UserID
	}
	return s.ActorKind
}

// IsHuman reports whether the caller is a signed-in user.
func (s Subjects) IsHuman() bool { return s.ActorKind == ActorUser }

// Known reports whether perm is a module permission.
func Known(perm string) bool { return slices.Contains(Permissions, perm) }

// Checker answers "does this user hold this API permission in this tenant"
// (the auth service's Authorization/Check; a map in tests). A failed lookup is
// a "no".
type Checker interface {
	Has(ctx context.Context, tenantID, userID, permission string) bool
}

// CheckerFunc adapts a function to Checker.
type CheckerFunc func(ctx context.Context, tenantID, userID, permission string) bool

// Has implements Checker.
func (f CheckerFunc) Has(ctx context.Context, tenantID, userID, permission string) bool {
	return f(ctx, tenantID, userID, permission)
}

// Static is a Checker over a fixed user → permissions map (tests, dev).
type Static map[string][]string

// Has implements Checker.
func (s Static) Has(_ context.Context, _, userID, permission string) bool {
	return slices.Contains(s[userID], permission)
}

// AuthChecker asks the auth service's Authorization/Check. A failed call is a
// "no" (fail closed).
type AuthChecker struct {
	Client authv1.AuthorizationClient
	Module string // the module owning the permissions ("teleport")
}

// Has implements Checker.
func (c AuthChecker) Has(ctx context.Context, tenantID, userID, permission string) bool {
	resource, action, ok := Split(permission)
	if !ok || c.Client == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	res, err := c.Client.Check(ctx, &authv1.CheckRequest{TenantId: tenantID, UserId: userID, Resource: resource, Action: action, Module: c.Module})
	return err == nil && res.GetAllowed()
}

// Require checks that the caller holds perm within its own tenant. Users are
// checked through c (nil c refuses); module and worker actors are limited to
// their fixed allow-lists; the system scope is allowed everything.
func Require(ctx context.Context, c Checker, s Subjects, perm string) error {
	if s.TenantID == "" {
		return fmt.Errorf("%w: tenant required", ErrForbidden)
	}
	if !Known(perm) {
		return fmt.Errorf("%w: unknown permission %q", ErrForbidden, perm)
	}
	switch s.ActorKind {
	case ActorSystem:
		return nil
	case ActorWorker:
		if workerAllowed[perm] {
			return nil
		}
	case ActorModule:
		if s.PeerSPIFFE != "" && moduleAllowed[perm] {
			return nil
		}
	case ActorUser:
		if c != nil && s.UserID != "" && c.Has(ctx, s.TenantID, s.UserID, perm) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s required", ErrForbidden, perm)
}

// Allowed is Require as a boolean.
func Allowed(ctx context.Context, c Checker, s Subjects, perm string) bool {
	return Require(ctx, c, s, perm) == nil
}

// RequireTenant ensures the caller acts within tenantID (its own tenant only;
// there is no cross-tenant actor on the request paths).
func RequireTenant(s Subjects, tenantID string) error {
	if tenantID == "" || s.TenantID != tenantID {
		return fmt.Errorf("%w: tenant mismatch", ErrForbidden)
	}
	return nil
}

// CallerIs permits only a module caller whose verified peer SPIFFE ID equals
// spiffeID exactly. The ID is the transport-verified peer, never a request
// field; no wildcard is honoured.
func CallerIs(s Subjects, spiffeID string) error {
	if s.ActorKind != ActorModule || spiffeID == "" || s.PeerSPIFFE != spiffeID || strings.Contains(spiffeID, "*") {
		return fmt.Errorf("%w: caller not allowed", ErrForbidden)
	}
	return nil
}

// Split returns the resource and action of a "resource:action" permission.
func Split(perm string) (resource, action string, ok bool) {
	resource, action, ok = strings.Cut(perm, ":")
	return resource, action, ok && resource != "" && action != ""
}

// ---- context

type ctxKey struct{}

// WithSubjects attaches the authenticated caller to ctx (the HTTP and gRPC
// edges do this once per request).
func WithSubjects(ctx context.Context, s Subjects) context.Context {
	return context.WithValue(ctx, ctxKey{}, s)
}

// FromContext returns the caller attached by WithSubjects.
func FromContext(ctx context.Context) (Subjects, bool) {
	s, ok := ctx.Value(ctxKey{}).(Subjects)
	return s, ok
}

// ---- authorizer

// ClusterGetter loads a cluster within a tenant (repo.Store satisfies it).
type ClusterGetter interface {
	GetCluster(ctx context.Context, tenantID, id string) (repo.Cluster, error)
}

// Authorizer binds a Checker and the cluster store for handlers.
type Authorizer struct {
	Checker  Checker
	Clusters ClusterGetter
}

// Require checks perm for the caller in ctx.
func (a Authorizer) Require(ctx context.Context, perm string) error {
	s, ok := FromContext(ctx)
	if !ok {
		return ErrUnauthenticated
	}
	return Require(ctx, a.Checker, s, perm)
}

// RequireCluster checks perm, then loads cluster id in the caller's own
// tenant. A cluster of another tenant (or a malformed id) is repo.ErrNotFound.
func (a Authorizer) RequireCluster(ctx context.Context, id, perm string) (repo.Cluster, error) {
	if err := a.Require(ctx, perm); err != nil {
		return repo.Cluster{}, err
	}
	s, _ := FromContext(ctx)
	return a.Clusters.GetCluster(ctx, s.TenantID, id)
}
