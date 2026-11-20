// Package teleportclient is a thin, typed Go client for the teleport.v1
// service-to-service gRPC API (contracts/grpc.md), for other Freya modules:
// inventory, asset and portal ask which Teleport-enrolled resources reach a
// host ("reachable through Teleport"). The caller supplies a connected
// SPIFFE-mTLS connection (for example from freya.App.Client(ctx,
// "teleport")); this package does not dial. Errors are typed sentinels; the
// server's status message is never surfaced. Adapted from dns-v4
// pkg/dnsclient; the same client ships in the sdk/ module.
package teleportclient

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	teleportv1 "github.com/go-tangra/go-tangra-teleport/v4/api/proto/teleport/v1"
)

// Service is the mesh name of the Teleport module.
const Service = "teleport"

// Link targets.
const (
	TargetInventory = "inventory"
	TargetAsset     = "asset"
)

// MaxTargets bounds one GetLinks call.
const MaxTargets = 500

// Typed errors (mapped from the gRPC status code only).
var (
	ErrPermissionDenied = errors.New("teleportclient: permission denied") // the caller identity is not allowed
	ErrInvalid          = errors.New("teleportclient: invalid request")   // malformed tenant, hostname, ip or ids
	ErrNotFound         = errors.New("teleportclient: not found")
	ErrUnavailable      = errors.New("teleportclient: teleport unavailable")
	ErrFailed           = errors.New("teleportclient: request failed")
)

// Host is one Teleport-enrolled resource that reaches a host.
type Host struct {
	ClusterID    string
	ClusterName  string
	ResourceID   string
	ResourceName string
	Kind         string // node | app | db | kube | desktop
	Online       bool
	LastSeen     time.Time // zero when never seen
	WebURL       string    // deep link to the proxy's web UI
}

// Client calls teleport.v1 over a caller-provided connection.
type Client struct {
	access teleportv1.AccessClient
}

// New builds a client from a connected (SPIFFE-mTLS) gRPC connection.
func New(conn grpc.ClientConnInterface) *Client {
	return &Client{access: teleportv1.NewAccessClient(conn)}
}

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	var sentinel error
	switch status.Code(err) {
	case codes.PermissionDenied, codes.Unauthenticated:
		sentinel = ErrPermissionDenied
	case codes.InvalidArgument:
		sentinel = ErrInvalid
	case codes.NotFound:
		sentinel = ErrNotFound
	case codes.Unavailable, codes.DeadlineExceeded:
		sentinel = ErrUnavailable
	default:
		sentinel = ErrFailed
	}
	return fmt.Errorf("%w (%s)", sentinel, status.Code(err))
}

func hostOf(h *teleportv1.HostAccess) Host {
	out := Host{ClusterID: h.GetClusterId(), ClusterName: h.GetClusterName(), ResourceID: h.GetResourceId(),
		ResourceName: h.GetResourceName(), Kind: h.GetKind(), Online: h.GetOnline(), WebURL: h.GetWebUrl()}
	if ts := h.GetLastSeen(); ts != nil {
		out.LastSeen = ts.AsTime()
	}
	return out
}

// LookupHost lists the tenant's resources reaching hostname (or ip: pass
// exactly one).
func (c *Client) LookupHost(ctx context.Context, tenantID, hostname, ip string) ([]Host, error) {
	res, err := c.access.LookupHost(ctx, &teleportv1.LookupHostRequest{TenantId: tenantID, Hostname: hostname, Ip: ip})
	if err != nil {
		return nil, mapErr(err)
	}
	out := make([]Host, 0, len(res.GetHosts()))
	for _, h := range res.GetHosts() {
		out = append(out, hostOf(h))
	}
	return out, nil
}

// GetLinks returns, for each of the caller's records (module inventory or
// asset; at most MaxTargets ids), the resource linked to it. Records without
// a link are absent from the map.
func (c *Client) GetLinks(ctx context.Context, tenantID, module string, ids []string) (map[string]Host, error) {
	if len(ids) > MaxTargets {
		return nil, fmt.Errorf("%w: at most %d ids", ErrInvalid, MaxTargets)
	}
	res, err := c.access.GetLinks(ctx, &teleportv1.GetLinksRequest{TenantId: tenantID, TargetModule: module, TargetIds: ids})
	if err != nil {
		return nil, mapErr(err)
	}
	out := make(map[string]Host, len(res.GetByTargetId()))
	for id, h := range res.GetByTargetId() {
		out[id] = hostOf(h)
	}
	return out, nil
}
