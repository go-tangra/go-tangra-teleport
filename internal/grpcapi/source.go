package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	inventoryv1 "github.com/go-tangra/go-tangra-inventory/sdk/v4/api/proto/inventory/v1"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/enroll"
)

// SourceServer implements inventory.v1.TeleportJoinSource (spec 002): it
// renders the join material of an enrollment when the host's agent fetches
// it. Only svc/inventory is admitted (deploy/policy.yaml and here); the
// render runs as a worker of the request's tenant. The response carries the
// single-use token and is never logged.
type SourceServer struct {
	inventoryv1.UnimplementedTeleportJoinSourceServer
	d Deps
}

// RenderTeleportJoin implements inventory.v1.TeleportJoinSource.
func (s *SourceServer) RenderTeleportJoin(ctx context.Context, req *inventoryv1.RenderTeleportJoinRequest) (*inventoryv1.TeleportJoinMaterial, error) {
	if _, err := admitPeer(ctx, s.d.Audit, SourceCallers, "inventory.v1.TeleportJoinSource", req.GetTenantId()); err != nil {
		return nil, err
	}
	if s.d.Enroll == nil {
		return nil, status.Error(codes.Unimplemented, "enrollment not wired")
	}
	if !uuidRE.MatchString(req.GetEnrollmentId()) || !uuidRE.MatchString(req.GetHostId()) {
		return nil, status.Error(codes.NotFound, "not_found")
	}
	ctx = authz.WithSubjects(ctx, authz.Worker(req.GetTenantId(), "enrollment-render"))
	m, err := s.d.Enroll.Render(ctx, enroll.RenderInput{EnrollmentID: req.GetEnrollmentId(), HostID: req.GetHostId(), ItemID: req.GetItemId()})
	if err != nil {
		return nil, GRPCError(err)
	}
	return &inventoryv1.TeleportJoinMaterial{ItemId: req.GetItemId(), Token: string(m.Token.Reveal()), ProxyAddr: m.ProxyAddr,
		CaPins: m.CAPins, TeleportVersion: m.TeleportVersion, Labels: m.Labels, TokenExpiresAt: m.TokenExpiresAt.Unix(),
		EnrollmentId: m.EnrollmentID}, nil
}
