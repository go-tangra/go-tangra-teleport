package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	teleportv1 "github.com/go-tangra/go-tangra-teleport/v4/api/proto/teleport/v1"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/resources"
)

func hostOf(h resources.HostAccess) *teleportv1.HostAccess {
	out := &teleportv1.HostAccess{ClusterId: h.ClusterID, ClusterName: h.ClusterName, ResourceName: h.ResourceName, Online: h.Online,
		WebUrl: h.WebURL, ResourceId: h.ResourceID, Kind: h.Kind}
	if !h.LastSeen.IsZero() {
		out.LastSeen = timestamppb.New(h.LastSeen)
	}
	return out
}

// LookupHost implements teleport.v1.Access.
func (s *AccessServer) LookupHost(ctx context.Context, req *teleportv1.LookupHostRequest) (*teleportv1.LookupHostResponse, error) {
	if s.d.Resources == nil {
		return nil, status.Error(codes.Unimplemented, "access not wired")
	}
	ctx, err := s.admit(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	hosts, err := s.d.Resources.LookupHost(ctx, req.GetHostname(), req.GetIp())
	if err != nil {
		return nil, GRPCError(err)
	}
	out := &teleportv1.LookupHostResponse{Hosts: make([]*teleportv1.HostAccess, 0, len(hosts))}
	for _, h := range hosts {
		out.Hosts = append(out.Hosts, hostOf(h))
	}
	return out, nil
}

// GetLinks implements teleport.v1.Access.
func (s *AccessServer) GetLinks(ctx context.Context, req *teleportv1.GetLinksRequest) (*teleportv1.GetLinksResponse, error) {
	if s.d.Resources == nil {
		return nil, status.Error(codes.Unimplemented, "access not wired")
	}
	ctx, err := s.admit(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	links, err := s.d.Resources.GetLinks(ctx, req.GetTargetModule(), req.GetTargetIds())
	if err != nil {
		return nil, GRPCError(err)
	}
	out := &teleportv1.GetLinksResponse{ByTargetId: make(map[string]*teleportv1.HostAccess, len(links))}
	for id, h := range links {
		out.ByTargetId[id] = hostOf(h)
	}
	return out, nil
}
