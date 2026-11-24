package provisioning_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/provisioning"
)

// fakeProfiles is auth's Profiles.Members over an in-memory member list: it
// pages by id like auth, honours the user_ids filter and the query, and
// records every request.
type fakeProfiles struct {
	mu       sync.Mutex
	members  []*authv1.MemberDetail // ordered by id
	err      error
	reqs     []*authv1.ListMemberDetailsRequest
	stuck    bool // answers the same cursor forever
	deadline bool // saw a context deadline
}

func (f *fakeProfiles) Members(ctx context.Context, in *authv1.ListMemberDetailsRequest, _ ...grpc.CallOption) (*authv1.ListMemberDetailsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, in)
	if _, ok := ctx.Deadline(); ok {
		f.deadline = true
	}
	if f.err != nil {
		return nil, f.err
	}
	limit := int(in.GetLimit())
	if limit == 0 {
		limit = 1000
	}
	var out []*authv1.MemberDetail
	for _, m := range f.members {
		if len(in.GetUserIds()) > 0 && !slices.Contains(in.GetUserIds(), m.GetUserId()) {
			continue
		}
		if in.GetCursor() != "" && m.GetUserId() <= in.GetCursor() {
			continue
		}
		out = append(out, m)
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[limit-1].GetUserId()
	}
	if f.stuck {
		next = "x"
	}
	return &authv1.ListMemberDetailsResponse{Members: out, NextCursor: next}, nil
}

func detail(i int) *authv1.MemberDetail {
	id := "018f3a2b-0000-7000-8000-" + strconv.FormatInt(int64(100000000000+i), 10)
	return &authv1.MemberDetail{UserId: id, Login: "user" + strconv.Itoa(i) + "@example.com", DisplayName: "User " + strconv.Itoa(i),
		Roles: []string{"operator"}, GroupIds: []string{"devs"}}
}

func TestAuthMembershipPagesThroughEveryMember(t *testing.T) {
	f := &fakeProfiles{}
	for i := range 2500 {
		f.members = append(f.members, detail(i))
	}
	m := provisioning.AuthMembership{Client: f}
	ms, err := m.Members(context.Background(), ct.TenantA)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2500 || len(f.reqs) != 3 {
		t.Fatalf("%d members in %d pages", len(ms), len(f.reqs))
	}
	for _, r := range f.reqs {
		if r.GetTenantId() != ct.TenantA || r.GetLimit() != 1000 || r.GetQuery() != "" || len(r.GetUserIds()) != 0 {
			t.Fatalf("request %v", r)
		}
	}
	if f.reqs[1].GetCursor() != f.members[999].GetUserId() {
		t.Fatalf("cursor %q", f.reqs[1].GetCursor())
	}
	got := ms[7]
	if got.UserID != f.members[7].GetUserId() || got.Login != "user7@example.com" || got.DisplayName != "User 7" ||
		!slices.Equal(got.Roles, []string{"operator"}) || !slices.Equal(got.Groups, []string{"devs"}) {
		t.Fatalf("member %+v", got)
	}
	if !f.deadline {
		t.Fatal("the auth call has no deadline")
	}
}

func TestAuthMembershipEmptyTenant(t *testing.T) {
	ms, err := provisioning.AuthMembership{Client: &fakeProfiles{}}.Members(context.Background(), ct.TenantA)
	if err != nil || len(ms) != 0 {
		t.Fatalf("%v %v", ms, err)
	}
}

func TestAuthMembershipMemberUsesTheFilter(t *testing.T) {
	f := &fakeProfiles{members: []*authv1.MemberDetail{detail(1), detail(2)}}
	m := provisioning.AuthMembership{Client: f}
	got, ok, err := m.Member(context.Background(), ct.TenantA, detail(2).GetUserId())
	if err != nil || !ok || got.Login != "user2@example.com" {
		t.Fatalf("%+v %v %v", got, ok, err)
	}
	if r := f.reqs[0]; !slices.Equal(r.GetUserIds(), []string{detail(2).GetUserId()}) || r.GetTenantId() != ct.TenantA {
		t.Fatalf("request %v", r)
	}
	if _, ok, err := m.Member(context.Background(), ct.TenantA, detail(9).GetUserId()); err != nil || ok {
		t.Fatalf("a non-member is reported: %v %v", ok, err)
	}
	// An answer for another id (never expected from auth) is not the member.
	f.members = []*authv1.MemberDetail{detail(1)}
	f.members[0].UserId = detail(3).GetUserId()
	if _, ok, _ := m.Member(context.Background(), ct.TenantA, detail(1).GetUserId()); ok {
		t.Fatal("a foreign answer was taken as the member")
	}
}

func TestAuthMembershipSearchPassesTheQuery(t *testing.T) {
	f := &fakeProfiles{members: []*authv1.MemberDetail{detail(1), detail(2), detail(3)}}
	m := provisioning.AuthMembership{Client: f}
	ms, err := m.Search(context.Background(), ct.TenantA, "alice", 2)
	if err != nil || len(ms) != 2 {
		t.Fatalf("%v %v", ms, err)
	}
	if r := f.reqs[0]; r.GetQuery() != "alice" || r.GetLimit() != 2 || r.GetTenantId() != ct.TenantA || r.GetCursor() != "" {
		t.Fatalf("request %v", r)
	}
	if len(f.reqs) != 1 {
		t.Fatal("search paged on")
	}
}

func TestAuthMembershipFailuresAreUnavailable(t *testing.T) {
	for _, err := range []error{status.Error(codes.Unavailable, "down"), status.Error(codes.PermissionDenied, "policy"), errors.New("boom")} {
		m := provisioning.AuthMembership{Client: &fakeProfiles{err: err}}
		if _, e := m.Members(context.Background(), ct.TenantA); !errors.Is(e, provisioning.ErrMembershipUnavailable) {
			t.Fatalf("members: %v", e)
		}
		if _, _, e := m.Member(context.Background(), ct.TenantA, detail(1).GetUserId()); !errors.Is(e, provisioning.ErrMembershipUnavailable) {
			t.Fatalf("member: %v", e)
		}
		if _, e := m.Search(context.Background(), ct.TenantA, "", 5); !errors.Is(e, provisioning.ErrMembershipUnavailable) {
			t.Fatalf("search: %v", e)
		}
	}
	if _, err := (provisioning.AuthMembership{}).Members(context.Background(), ct.TenantA); !errors.Is(err, provisioning.ErrMembershipUnavailable) {
		t.Fatalf("no client: %v", err)
	}
}

func TestAuthMembershipStopsOnACursorThatDoesNotMove(t *testing.T) {
	f := &fakeProfiles{members: []*authv1.MemberDetail{detail(1)}, stuck: true}
	m := provisioning.AuthMembership{Client: f, Timeout: time.Second}
	if _, err := m.Members(context.Background(), ct.TenantA); !errors.Is(err, provisioning.ErrMembershipUnavailable) {
		t.Fatalf("err %v", err)
	}
	if len(f.reqs) > 3 {
		t.Fatalf("%d requests", len(f.reqs))
	}
}
