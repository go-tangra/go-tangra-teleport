package access

import (
	"context"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

// Bounds of the access lifetime (R4), in minutes.
const (
	MinTTLMinutes = 15
	MaxTTLMinutes = 720
)

// SettingsView is a cluster's access settings as the API shows them.
type SettingsView struct {
	AccessTTLMinutes int        `json:"access_ttl_minutes"`
	UpdatedAt        *time.Time `json:"updated_at,omitempty"`
	UpdatedBy        string     `json:"updated_by,omitempty"`
}

func viewOf(s repo.AccessSettings) SettingsView {
	v := SettingsView{AccessTTLMinutes: s.AccessTTLMinutes, UpdatedBy: s.UpdatedBy}
	if v.AccessTTLMinutes == 0 {
		v.AccessTTLMinutes = repo.DefaultAccessTTLMinutes
	}
	if !s.UpdatedAt.IsZero() {
		t := s.UpdatedAt.UTC()
		v.UpdatedAt = &t
	}
	return v
}

// PutSettings sets a cluster's access lifetime (clusters:manage), audited
// as a cluster update.
func (s *Service) PutSettings(ctx context.Context, clusterID string, minutes int) (SettingsView, error) {
	c, err := s.Clusters.Authz.RequireCluster(ctx, clusterID, authz.ClustersManage)
	if err != nil {
		return SettingsView{}, err
	}
	details := map[string]any{"access_ttl_minutes": minutes}
	if minutes < MinTTLMinutes || minutes > MaxTTLMinutes {
		clusters.Audit(ctx, s.Audit, audit.ClusterUpdate, audit.TargetCluster, c.ID, c.DisplayName, ErrInvalid, details)
		return SettingsView{}, ErrInvalid
	}
	subj, _ := authz.FromContext(ctx)
	set := repo.AccessSettings{ClusterID: c.ID, TenantID: c.TenantID, AccessTTLMinutes: minutes, UpdatedAt: s.now(), UpdatedBy: subj.ActorID()}
	err = s.Repo.PutAccessSettings(ctx, set)
	clusters.Audit(ctx, s.Audit, audit.ClusterUpdate, audit.TargetCluster, c.ID, c.DisplayName, err, details)
	if err != nil {
		return SettingsView{}, err
	}
	s.nodes.forget(c.ID)
	return viewOf(set), nil
}
