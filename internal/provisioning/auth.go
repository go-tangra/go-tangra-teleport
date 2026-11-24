package provisioning

import (
	"context"
	"errors"
	"slices"
	"time"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"google.golang.org/grpc"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
)

// Auth Profiles.Members bounds (auth.proto ListMemberDetailsRequest).
const (
	authPageSize = 1000
	// maxAuthPages caps one listing (a million members): a cursor that never
	// ends is a broken peer, not a tenant.
	maxAuthPages = 1000
	// DefaultAuthTimeout bounds every auth call.
	DefaultAuthTimeout = 10 * time.Second
)

// ProfilesClient is the part of auth's Profiles service the membership uses.
type ProfilesClient interface {
	Members(ctx context.Context, in *authv1.ListMemberDetailsRequest, opts ...grpc.CallOption) (*authv1.ListMemberDetailsResponse, error)
}

// AuthMembership reads a tenant's members from auth Profiles.Members over
// the module's mTLS mesh connection. Auth derives the module from the
// caller's SPIFFE id, so Roles are this module's role slugs only; Login is
// the member's sign-in e-mail. Any failure is ErrMembershipUnavailable
// (wrapped): nothing is changed while auth cannot be asked. The auth policy
// must admit svc/teleport to Profiles/Members.
type AuthMembership struct {
	Client  ProfilesClient
	Timeout time.Duration // per call (DefaultAuthTimeout)
}

func (a AuthMembership) call(ctx context.Context, in *authv1.ListMemberDetailsRequest) (*authv1.ListMemberDetailsResponse, error) {
	if a.Client == nil {
		return nil, unavailable(errors.New("no auth client"))
	}
	d := a.Timeout
	if d <= 0 {
		d = DefaultAuthTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	res, err := a.Client.Members(ctx, in)
	if err != nil {
		return nil, unavailable(err)
	}
	return res, nil
}

func memberOf(d *authv1.MemberDetail) Member {
	return Member{UserID: d.GetUserId(), Login: d.GetLogin(), DisplayName: d.GetDisplayName(),
		Roles: slices.Clone(d.GetRoles()), Groups: slices.Clone(d.GetGroupIds())}
}

// Members implements Membership: every active member, page by page.
func (a AuthMembership) Members(ctx context.Context, tenantID string) ([]Member, error) {
	var out []Member
	cursor := ""
	for range maxAuthPages {
		res, err := a.call(ctx, &authv1.ListMemberDetailsRequest{TenantId: tenantID, Cursor: cursor, Limit: authPageSize})
		if err != nil {
			return nil, err
		}
		for _, d := range res.GetMembers() {
			out = append(out, memberOf(d))
		}
		next := res.GetNextCursor()
		if next == "" {
			return out, nil
		}
		if next == cursor {
			return nil, unavailable(errors.New("auth repeated the member cursor"))
		}
		cursor = next
	}
	return nil, unavailable(errors.New("auth member listing did not end"))
}

// Member implements Membership: the user_ids filter re-reads one member.
func (a AuthMembership) Member(ctx context.Context, tenantID, userID string) (Member, bool, error) {
	res, err := a.call(ctx, &authv1.ListMemberDetailsRequest{TenantId: tenantID, UserIds: []string{userID}, Limit: 1})
	if err != nil {
		return Member{}, false, err
	}
	for _, d := range res.GetMembers() {
		if d.GetUserId() == userID {
			return memberOf(d), true, nil
		}
	}
	return Member{}, false, nil
}

// Search implements Membership: the first limit members whose login or
// display name contains query (case-insensitive, auth-side).
func (a AuthMembership) Search(ctx context.Context, tenantID, query string, limit int) ([]Member, error) {
	if limit < 1 || limit > authPageSize {
		limit = authPageSize
	}
	res, err := a.call(ctx, &authv1.ListMemberDetailsRequest{TenantId: tenantID, Query: query, Limit: int32(limit)}) // #nosec G115 -- bounded above
	if err != nil {
		return nil, err
	}
	out := make([]Member, 0, len(res.GetMembers()))
	for _, d := range res.GetMembers() {
		out = append(out, memberOf(d))
	}
	return out, nil
}

// Addresses implements notify.Directory: the login (sign-in e-mail) of
// every id that is an active member, through the user_ids filter in chunks
// of authPageSize; ids that are no active member, or have no login, are
// absent. Any failure is ErrMembershipUnavailable (wrapped).
func (a AuthMembership) Addresses(ctx context.Context, tenantID string, userIDs []string) (map[string]string, error) {
	out := map[string]string{}
	for chunk := range slices.Chunk(userIDs, authPageSize) {
		res, err := a.call(ctx, &authv1.ListMemberDetailsRequest{TenantId: tenantID, UserIds: chunk, Limit: authPageSize})
		if err != nil {
			return nil, err
		}
		for _, d := range res.GetMembers() {
			if d.GetLogin() != "" && slices.Contains(chunk, d.GetUserId()) {
				out[d.GetUserId()] = d.GetLogin()
			}
		}
	}
	return out, nil
}

var (
	_ Membership       = AuthMembership{}
	_ notify.Directory = AuthMembership{}
)
