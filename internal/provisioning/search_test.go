package provisioning_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/provisioning"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

func members(n int) []provisioning.Member {
	out := make([]provisioning.Member, 0, n)
	for i := range n {
		d := detail(i)
		out = append(out, provisioning.Member{UserID: d.GetUserId(), Login: d.GetLogin(), DisplayName: d.GetDisplayName(), Roles: d.GetRoles()})
	}
	return out
}

func TestSearchMembers(t *testing.T) {
	e := setup(t)
	all := append(members(60), provisioning.Member{UserID: bobID, Login: "bob@example.com", DisplayName: "Bob Smith"})
	e.auth.Set(all...)

	p, err := e.svc.SearchMembers(admin, e.id, "BOB", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Items) != 1 || p.Items[0] != (provisioning.MemberCandidate{UserID: bobID, DisplayName: "Bob Smith", Login: "bob@example.com"}) {
		t.Fatalf("items %+v", p.Items)
	}
	if q := e.auth.Queries(); !slices.Equal(q, []string{"BOB"}) {
		t.Fatalf("queries %v", q)
	}
	// Default 20, at most 50.
	if p, _ := e.svc.SearchMembers(admin, e.id, "", 0); len(p.Items) != provisioning.DefaultMemberSearch {
		t.Fatalf("default: %d", len(p.Items))
	}
	if p, _ := e.svc.SearchMembers(admin, e.id, "", provisioning.MaxMemberSearch); len(p.Items) != 50 {
		t.Fatalf("max: %d", len(p.Items))
	}
	for _, bad := range []struct {
		q     string
		limit int
		field string
	}{
		{"", 51, "limit"}, {"", -1, "limit"}, {strings.Repeat("a", 101), 0, "q"},
	} {
		_, err := e.svc.SearchMembers(admin, e.id, bad.q, bad.limit)
		var fe *clusters.FieldError
		if !errors.As(err, &fe) || fe.Field != bad.field {
			t.Fatalf("%q/%d: %v", bad.q, bad.limit, err)
		}
	}
	if _, err := e.svc.SearchMembers(admin, e.id, strings.Repeat("é", 100), 0); err != nil {
		t.Fatalf("100 characters: %v", err)
	}
}

func TestSearchMembersPermissionsAndScope(t *testing.T) {
	e := setup(t)
	e.auth.Set(bob)
	if _, err := e.svc.SearchMembers(operator, e.id, "", 0); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("operator: %v", err)
	}
	if _, err := e.svc.SearchMembers(viewer, e.id, "", 0); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer: %v", err)
	}
	other := e.Register(t, ct.TenantB, "theirs")
	if _, err := e.svc.SearchMembers(admin, other.ID, "", 0); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("cross-tenant: %v", err)
	}
	if len(e.auth.Queries()) != 0 {
		t.Fatal("auth was asked without permission")
	}
	e.auth.SetErr(errors.New("auth down"))
	if _, err := e.svc.SearchMembers(admin, e.id, "", 0); !errors.Is(err, provisioning.ErrMembershipUnavailable) {
		t.Fatalf("auth down: %v", err)
	}
	e.svc.Membership = nil
	if _, err := e.svc.SearchMembers(admin, e.id, "", 0); !errors.Is(err, provisioning.ErrMembershipUnavailable) {
		t.Fatalf("no membership: %v", err)
	}
}
