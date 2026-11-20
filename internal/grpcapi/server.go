// Package grpcapi serves teleport.v1 for other platform services on the
// Freya SPIFFE mTLS channel (contracts/grpc.md). The framework's policy
// allow-list (deploy/policy.yaml) admits only inventory, asset and portal to
// teleport.v1.Access before any handler runs; the handler re-checks the
// verified peer's service name against the same list (defence in depth), so
// a policy mistake cannot widen access. The caller acts as authz.Module for
// the tenant named in the request and may only read (resources:read).
// Nothing here is proxied by the gateway; responses carry identifiers,
// names and reachability only. Adapted from dns-v4 internal/grpcapi.
package grpcapi

import (
	"context"
	"errors"
	"regexp"
	"slices"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra/v4/authn"

	inventoryv1 "github.com/go-tangra/go-tangra-inventory/sdk/v4/api/proto/inventory/v1"

	teleportv1 "github.com/go-tangra/go-tangra-teleport/v4/api/proto/teleport/v1"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/enroll"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/resources"
)

// AccessCallers are the services allowed to call teleport.v1.Access
// (contracts/grpc.md; the same list as deploy/policy.yaml).
var AccessCallers = []string{"inventory", "asset", "portal"}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// SourceCallers are the services allowed to call inventory.v1
// TeleportJoinSource here (spec 002: only inventory renders join material).
var SourceCallers = []string{"inventory"}

// Deps carries the services the teleport.v1 servers use.
type Deps struct {
	Resources *resources.Service // US3: Access
	Enroll    *enroll.Service    // spec 002: TeleportJoinSource
	Audit     audit.Recorder     // refused callers are audited (may be nil)
	// Callers overrides AccessCallers (nil: AccessCallers).
	Callers []string
}

// AccessServer implements teleport.v1.Access (access.go); without a wired
// resources service every method answers Unimplemented.
type AccessServer struct {
	teleportv1.UnimplementedAccessServer
	d Deps
}

// Register registers the teleport.v1 mesh servers on the gRPC server.
func Register(gs grpc.ServiceRegistrar, d Deps) {
	teleportv1.RegisterAccessServer(gs, &AccessServer{d: d})
	inventoryv1.RegisterTeleportJoinSourceServer(gs, &SourceServer{d: d})
}

// admit checks the verified peer BEFORE anything else (a refused peer learns
// nothing about tenants or hosts), then returns ctx carrying the module
// subject of the request's tenant.
func (s *AccessServer) admit(ctx context.Context, tenantID string) (context.Context, error) {
	callers := s.d.Callers
	if callers == nil {
		callers = AccessCallers
	}
	p, err := admitPeer(ctx, s.d.Audit, callers, "teleport.v1.Access", tenantID)
	if err != nil {
		return nil, err
	}
	return authz.WithSubjects(ctx, authz.Module(tenantID, p.ID.String())), nil
}

// admitPeer checks the verified peer against callers, then the tenant id.
func admitPeer(ctx context.Context, r audit.Recorder, callers []string, service, tenantID string) (authn.PeerIdentity, error) {
	p, ok := authn.FromContext(ctx)
	if !ok || p.ServiceName == "" || !slices.Contains(callers, p.ServiceName) {
		refused(ctx, r, p, service)
		return authn.PeerIdentity{}, status.Error(codes.PermissionDenied, "forbidden")
	}
	if !uuidRE.MatchString(tenantID) {
		return authn.PeerIdentity{}, status.Error(codes.InvalidArgument, "tenant_id must be a uuid")
	}
	return p, nil
}

// refused audits a refused peer under the platform tenant (the request's
// tenant is not trusted).
func refused(ctx context.Context, r audit.Recorder, p authn.PeerIdentity, service string) {
	if r == nil {
		return
	}
	e := audit.Event{TenantID: repo.NilTenant, Action: audit.AccessRefused, ActorKind: authz.ActorModule, ActorID: p.ServiceName,
		TargetKind: audit.TargetSystem, TargetName: service, Outcome: audit.OutcomeFailure, Reason: "forbidden"}
	if e.ActorID == "" {
		e.ActorID = "unknown"
	}
	audit.Emit(ctx, r, e)
}

// GRPCError maps a domain error to a status carrying only a stable reason.
func GRPCError(err error) error {
	if _, ok := status.FromError(err); ok && err != nil {
		return err
	}
	var fe *clusters.FieldError
	switch {
	case errors.As(err, &fe):
		return status.Error(codes.InvalidArgument, "invalid_"+fe.Field)
	case errors.Is(err, authz.ErrForbidden), errors.Is(err, authz.ErrUnauthenticated):
		return status.Error(codes.PermissionDenied, "forbidden")
	case errors.Is(err, repo.ErrNotFound):
		return status.Error(codes.NotFound, "not_found")
	}
	return status.Error(codes.Unavailable, "temporarily_unavailable")
}
