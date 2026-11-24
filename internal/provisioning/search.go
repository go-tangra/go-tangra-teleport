package provisioning

import (
	"context"
	"errors"
	"unicode/utf8"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
)

// Member search bounds (GET /clusters/{id}/provisioning/members).
const (
	DefaultMemberSearch = 20
	MaxMemberSearch     = 50
	MaxMemberQuery      = 100 // characters, as auth accepts
)

// MemberCandidate is a tenant member as the "Provision user" picker shows
// it: no roles, groups or contact data beyond the sign-in login.
type MemberCandidate struct {
	UserID      string `json:"user_id"`
	DisplayName string `json:"display_name"`
	Login       string `json:"login"`
}

// MemberSearch is the search answer.
type MemberSearch struct {
	Items []MemberCandidate `json:"items"`
}

// SearchMembers finds active members of the cluster's tenant whose login or
// display name contains query (provisioning:manage, the same permission as
// provisioning one). limit is DefaultMemberSearch when 0, at most
// MaxMemberSearch. An auth failure is ErrMembershipUnavailable.
func (s *Service) SearchMembers(ctx context.Context, clusterID, query string, limit int) (MemberSearch, error) {
	c, err := s.Clusters.Authz.RequireCluster(ctx, clusterID, authz.ProvisioningManage)
	if err != nil {
		return MemberSearch{}, err
	}
	if !utf8.ValidString(query) || utf8.RuneCountInString(query) > MaxMemberQuery {
		return MemberSearch{}, &clusters.FieldError{Field: "q", Msg: "must be at most 100 characters"}
	}
	switch {
	case limit == 0:
		limit = DefaultMemberSearch
	case limit < 1 || limit > MaxMemberSearch:
		return MemberSearch{}, &clusters.FieldError{Field: "limit", Msg: "must be 1 to 50"}
	}
	ms, err := s.membership().Search(ctx, c.TenantID, query, limit)
	if err != nil {
		return MemberSearch{}, errors.Join(ErrMembershipUnavailable, err)
	}
	out := MemberSearch{Items: make([]MemberCandidate, 0, len(ms))}
	for _, m := range ms {
		if len(out.Items) == limit {
			break
		}
		out.Items = append(out.Items, MemberCandidate{UserID: m.UserID, DisplayName: m.DisplayName, Login: m.Login})
	}
	return out, nil
}
