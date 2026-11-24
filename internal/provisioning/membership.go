package provisioning

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
)

// ErrMembershipUnavailable reports that the tenant's membership cannot be
// read from auth (dependency_unavailable). Nothing is changed while it is.
var ErrMembershipUnavailable = errors.New("provisioning: tangra membership unavailable")

// Member is one active tangra member of a tenant as auth reports it.
type Member struct {
	UserID      string
	Login       string   // the sign-in e-mail; the Teleport username is derived from it (Username)
	DisplayName string   // for pickers only; never part of the Teleport user
	Roles       []string // module role slugs held in this module
	Groups      []string // group ids
}

func cloneMember(m Member) Member {
	m.Roles, m.Groups = slices.Clone(m.Roles), slices.Clone(m.Groups)
	return m
}

// Membership reads a tenant's members from auth over mTLS (research D10;
// AuthMembership in production). Members lists them for a sync; Member
// re-reads one member before any lock or delete (SR-006), so a stale listing
// never de-provisions anyone; Search finds members for the "Provision user"
// picker. All answer ErrMembershipUnavailable (wrapped) when auth cannot be
// asked.
type Membership interface {
	Members(ctx context.Context, tenantID string) ([]Member, error)
	// Member returns the member and true, or false when the user is no
	// longer an active member of the tenant.
	Member(ctx context.Context, tenantID, userID string) (Member, bool, error)
	// Search returns at most limit members whose login or display name
	// contains query (case-insensitive; empty matches everyone), by id.
	Search(ctx context.Context, tenantID, query string, limit int) ([]Member, error)
}

// Unavailable is a membership that cannot reach auth (a nil
// Service.Membership): every read is ErrMembershipUnavailable, so
// provisioning reports dependency_unavailable and changes nothing.
type Unavailable struct{}

// Members implements Membership.
func (Unavailable) Members(context.Context, string) ([]Member, error) {
	return nil, ErrMembershipUnavailable
}

// Member implements Membership.
func (Unavailable) Member(context.Context, string, string) (Member, bool, error) {
	return Member{}, false, ErrMembershipUnavailable
}

// Search implements Membership.
func (Unavailable) Search(context.Context, string, string, int) ([]Member, error) {
	return nil, ErrMembershipUnavailable
}

// FakeMembership is an in-memory Membership for tests. Set replaces both the
// listing and the members auth confirms; SetListed replaces the listing
// only (a stale page or a forged hint), so re-verification can be tested.
type FakeMembership struct {
	mu        sync.Mutex
	listed    []Member
	current   map[string]Member
	err       error
	memberErr error
	queries   []string
}

// NewFakeMembership builds a fake with members.
func NewFakeMembership(members ...Member) *FakeMembership {
	f := &FakeMembership{}
	f.Set(members...)
	return f
}

// Set makes members the listing and the confirmed truth; errors are cleared.
func (f *FakeMembership) Set(members ...Member) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.current = map[string]Member{}
	for _, m := range members {
		f.current[m.UserID] = cloneMember(m)
	}
	f.listed = nil
	for _, m := range members {
		f.listed = append(f.listed, cloneMember(m))
	}
	f.err, f.memberErr = nil, nil
}

// SetListed replaces the listing only.
func (f *FakeMembership) SetListed(members ...Member) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listed = nil
	for _, m := range members {
		f.listed = append(f.listed, cloneMember(m))
	}
}

// SetErr fails every read with err (wrapped in ErrMembershipUnavailable).
func (f *FakeMembership) SetErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err, f.memberErr = err, err
}

// SetMemberErr fails the re-verification reads only.
func (f *FakeMembership) SetMemberErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.memberErr = err
}

func unavailable(err error) error {
	return errors.Join(ErrMembershipUnavailable, err)
}

// Members implements Membership.
func (f *FakeMembership) Members(context.Context, string) ([]Member, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, unavailable(f.err)
	}
	out := make([]Member, 0, len(f.listed))
	for _, m := range f.listed {
		out = append(out, cloneMember(m))
	}
	return out, nil
}

// Member implements Membership.
func (f *FakeMembership) Member(_ context.Context, _, userID string) (Member, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.memberErr != nil {
		return Member{}, false, unavailable(f.memberErr)
	}
	m, ok := f.current[userID]
	return cloneMember(m), ok, nil
}

// Search implements Membership over the listing and records the query.
func (f *FakeMembership) Search(_ context.Context, _, query string, limit int) ([]Member, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, query)
	if f.err != nil {
		return nil, unavailable(f.err)
	}
	q := strings.ToLower(query)
	out := []Member{}
	for _, m := range f.listed {
		if len(out) == limit {
			break
		}
		if strings.Contains(strings.ToLower(m.Login), q) || strings.Contains(strings.ToLower(m.DisplayName), q) {
			out = append(out, cloneMember(m))
		}
	}
	return out, nil
}

// Queries returns the search queries seen so far.
func (f *FakeMembership) Queries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.queries)
}

var (
	_ Membership = Unavailable{}
	_ Membership = (*FakeMembership)(nil)
)
