package teleportapi

import (
	"context"
	"time"

	"github.com/gravitational/teleport/api/client/proto"
	userspb "github.com/gravitational/teleport/api/gen/proto/go/teleport/users/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
)

// Probe kinds: the Teleport resource kinds the tangra-manager role grants
// (research D3). ProbeRead checks read access to one of them with the
// smallest possible request; write access is never probed.
const (
	ProbeUser                  = types.KindUser
	ProbeRole                  = types.KindRole
	ProbeLock                  = types.KindLock
	ProbeToken                 = types.KindToken
	ProbeNode                  = types.KindNode
	ProbeAppServer             = types.KindAppServer
	ProbeDBServer              = types.KindDatabaseServer
	ProbeKubeServer            = types.KindKubeServer
	ProbeWindowsDesktop        = types.KindWindowsDesktop
	ProbeEvent                 = types.KindEvent
	ProbeSession               = types.KindSession
	ProbeClusterAuthPreference = types.KindClusterAuthPreference
)

// ProbeKinds lists every probed kind in the D3 role order.
var ProbeKinds = []string{
	ProbeUser, ProbeRole, ProbeLock, ProbeToken,
	ProbeNode, ProbeAppServer, ProbeDBServer, ProbeKubeServer, ProbeWindowsDesktop,
	ProbeEvent, ProbeSession, ProbeClusterAuthPreference,
}

func probeKnown(kind string) bool {
	for _, k := range ProbeKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// ProbeRead implements Client: one minimal read of kind. A denial maps to
// ErrAccessDenied (through Limit).
func (r *real) ProbeRead(ctx context.Context, kind string) error {
	var err error
	switch kind {
	case ProbeUser:
		_, err = r.c.ListUsers(ctx, &userspb.ListUsersRequest{PageSize: 1})
	case ProbeRole:
		_, err = r.c.ListRoles(ctx, &proto.ListRolesRequest{Limit: 1})
	case ProbeLock:
		_, err = r.c.GetLocks(ctx, true)
	case ProbeToken:
		_, _, err = r.c.ListProvisionTokens(ctx, 1, "", nil, "")
	case ProbeNode, ProbeAppServer, ProbeDBServer, ProbeKubeServer, ProbeWindowsDesktop:
		_, err = r.c.ListResources(ctx, proto.ListResourcesRequest{ResourceType: kind, Limit: 1})
	case ProbeEvent:
		now := time.Now().UTC()
		_, _, err = r.c.SearchEvents(ctx, now.Add(-time.Minute), now, "default", nil, 1, types.EventOrderDescending, "", "")
	case ProbeSession:
		now := time.Now().UTC()
		_, _, err = r.c.SearchSessionEvents(ctx, now.Add(-time.Minute), now, 1, types.EventOrderDescending, "")
	case ProbeClusterAuthPreference:
		_, err = r.c.GetAuthPreference(ctx)
	default:
		err = trace.BadParameter("unknown probe kind")
	}
	return err
}

func (c *limited) ProbeRead(ctx context.Context, kind string) error {
	_, err := call(c, ctx, func(ctx context.Context) (struct{}, error) { return struct{}{}, c.inner.ProbeRead(ctx, kind) })
	return err
}

// ProbeRead implements Client: kinds in Denied answer an access denial.
func (f *Fake) ProbeRead(_ context.Context, kind string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("ProbeRead"); err != nil {
		return err
	}
	switch {
	case !probeKnown(kind):
		return trace.BadParameter("unknown probe kind")
	case f.Denied[kind]:
		return trace.AccessDenied("access denied to perform action %q on %q", "list", kind)
	}
	return nil
}
