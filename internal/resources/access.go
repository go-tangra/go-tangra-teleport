package resources

import (
	"context"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

// The read side of teleport.v1.Access (contracts/grpc.md): which enrolled
// resources reach a host, for inventory, asset and portal. Callers are mesh
// modules acting for one tenant (authz.Module); only resources:read is
// needed, and every read is scoped to the caller's tenant.

// Bounds of the Access API.
const (
	MaxLinkTargets = 500
	maxHostname    = 253
)

// HostAccess is one resource that reaches a host.
type HostAccess struct {
	ClusterID    string
	ClusterName  string
	ResourceID   string
	ResourceName string
	Kind         string
	Online       bool
	LastSeen     time.Time
	WebURL       string
}

// ValidHostname checks an RFC 1123 hostname (a trailing dot is allowed).
func ValidHostname(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > maxHostname {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// webURL deep-links a resource in the proxy's web UI.
func webURL(c repo.Cluster, name string) string {
	if c.ProxyAddr == "" || c.ClusterName == "" {
		return ""
	}
	u := url.URL{Scheme: "https", Host: strings.TrimSuffix(c.ProxyAddr, ":443"), Path: "/web/cluster/" + c.ClusterName + "/resources",
		RawQuery: url.Values{"search": {name}}.Encode()}
	return u.String()
}

func accessOf(c repo.Cluster, sn repo.ResourceSnapshot) HostAccess {
	name := c.ClusterName
	if name == "" {
		name = c.DisplayName
	}
	return HostAccess{ClusterID: c.ID, ClusterName: name, ResourceID: sn.ID, ResourceName: sn.TeleportName, Kind: sn.Kind,
		Online: sn.Online, LastSeen: sn.LastSeenAt, WebURL: webURL(c, sn.TeleportName)}
}

// tenantClusters indexes the caller's clusters.
func (s *Service) tenantClusters(ctx context.Context, tenantID string) (map[string]repo.Cluster, error) {
	cs, err := s.Repo.ListClusters(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]repo.Cluster, len(cs))
	for _, c := range cs {
		out[c.ID] = c
	}
	return out, nil
}

// LookupHost returns the tenant's resources whose hostname or address is
// the given one (exactly one of hostname and ip).
func (s *Service) LookupHost(ctx context.Context, hostname, ip string) ([]HostAccess, error) {
	if err := s.Clusters.Authz.Require(ctx, authz.ResourcesRead); err != nil {
		return nil, err
	}
	switch {
	case (hostname == "") == (ip == ""):
		return nil, &clusters.FieldError{Field: "hostname", Msg: "exactly one of hostname and ip is required"}
	case hostname != "" && !ValidHostname(hostname):
		return nil, &clusters.FieldError{Field: "hostname", Msg: "must be an RFC 1123 hostname"}
	}
	if ip != "" {
		a, err := netip.ParseAddr(ip)
		if err != nil || a.Zone() != "" {
			return nil, &clusters.FieldError{Field: "ip", Msg: "must be an IPv4 or IPv6 address"}
		}
		ip = a.Unmap().String()
	}
	subj, _ := authz.FromContext(ctx)
	cs, err := s.tenantClusters(ctx, subj.TenantID)
	if err != nil {
		return nil, err
	}
	snaps, err := s.Repo.FindSnapshots(ctx, subj.TenantID, strings.TrimSuffix(hostname, "."), ip)
	if err != nil {
		return nil, err
	}
	out := make([]HostAccess, 0, len(snaps))
	for _, sn := range snaps {
		if c, ok := cs[sn.ClusterID]; ok {
			out = append(out, accessOf(c, sn))
		}
	}
	return out, nil
}

// GetLinks returns, per record of one module, the resource linked to it
// (auto or confirmed links; an online resource first). Candidates are not
// links yet and are left out.
func (s *Service) GetLinks(ctx context.Context, module string, ids []string) (map[string]HostAccess, error) {
	if err := s.Clusters.Authz.Require(ctx, authz.ResourcesRead); err != nil {
		return nil, err
	}
	if len(ids) == 0 || len(ids) > MaxLinkTargets {
		return nil, &clusters.FieldError{Field: "target_ids", Msg: "must list 1 to 500 ids"}
	}
	for _, id := range ids {
		if err := validTarget(LinkInput{TargetModule: module, TargetID: id}); err != nil {
			return nil, err
		}
	}
	subj, _ := authz.FromContext(ctx)
	cs, err := s.tenantClusters(ctx, subj.TenantID)
	if err != nil {
		return nil, err
	}
	links, err := s.Repo.ListLinksByTarget(ctx, subj.TenantID, module, ids)
	if err != nil {
		return nil, err
	}
	out := map[string]HostAccess{}
	for _, l := range links {
		if l.Match == repo.MatchCandidate {
			continue
		}
		if have, ok := out[l.TargetID]; ok && have.Online {
			continue
		}
		sn, err := s.Repo.GetSnapshot(ctx, subj.TenantID, l.SnapshotID)
		if err != nil {
			continue
		}
		if c, ok := cs[sn.ClusterID]; ok {
			out[l.TargetID] = accessOf(c, sn)
		}
	}
	return out, nil
}
