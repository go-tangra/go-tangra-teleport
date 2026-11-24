package provisioning_test

import (
	"context"
	"errors"
	"testing"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/provisioning"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

// resolving wires the provisioning service like the app does: the invite is
// addressed to the tangra user id, and the notifier resolves it to the
// member's sign-in e-mail through the membership (auth Profiles.Members).
func resolving(t *testing.T) *env {
	t.Helper()
	e := setup(t)
	e.svc.Notify = notify.NewResolver(e.Notify, e.auth, nil)
	return e
}

// flaky is a directory that fails while down (auth stopping between the
// member listing and the invite).
type flaky struct {
	notify.Directory
	down bool
}

func (f *flaky) Addresses(ctx context.Context, tenantID string, ids []string) (map[string]string, error) {
	if f.down {
		return nil, provisioning.ErrMembershipUnavailable
	}
	return f.Directory.Addresses(ctx, tenantID, ids)
}

func TestInviteGoesToTheMembersEmail(t *testing.T) {
	e := resolving(t)
	e.auth.Set(provisioning.Member{UserID: bobID, Login: "bob.smith@example.com", Roles: []string{"operator"}})
	if s := e.sync(t); s != (provisioning.Summary{Created: 1}) {
		t.Fatalf("summary %+v", s)
	}
	inv := e.Notify.OfTemplate(notify.TemplateInvite)
	if len(inv) != 1 || inv[0].To != "bob.smith@example.com" || inv[0].Vars["invite_url"] == "" {
		t.Fatalf("invite %+v", inv)
	}
}

// Auth down when the invite is addressed: the user is rolled back and kept
// in error (dependency_unavailable), and the next sync sends the invite.
func TestInviteWhileAuthIsDownRetriesAtTheNextSync(t *testing.T) {
	e := setup(t)
	dir := &flaky{Directory: e.auth, down: true}
	e.svc.Notify = notify.NewResolver(e.Notify, dir, nil)
	e.auth.Set(provisioning.Member{UserID: bobID, Login: "bob.smith@example.com", Roles: []string{"operator"}})
	if _, err := e.svc.Provision(admin, e.id, provisioning.ProvisionInput{TangraUserID: bobID}); !errors.Is(err, notify.ErrUnavailable) {
		t.Fatalf("provision: %v", err)
	}
	if _, ok := e.user("bob.smith"); ok {
		t.Fatal("user kept without an invite")
	}
	if r, _ := e.row(t, bobID); r.State != repo.UserError {
		t.Fatalf("row %+v", r)
	}
	dir.down = false
	if s := e.sync(t); s != (provisioning.Summary{Created: 1}) {
		t.Fatalf("retry %+v", s)
	}
	if r, _ := e.row(t, bobID); r.State != repo.UserActive || len(e.Notify.OfTemplate(notify.TemplateInvite)) != 1 {
		t.Fatalf("row %+v", r)
	}
}

// A member whose login is no e-mail address cannot be invited: nothing is
// sent and the user stays in error.
func TestInviteWithoutAnAddressIsNotDelivered(t *testing.T) {
	e := resolving(t)
	e.auth.Set(bob) // login "Bob.Smith"
	if s := e.sync(t); s != (provisioning.Summary{Errors: 1}) {
		t.Fatalf("summary %+v", s)
	}
	if r, _ := e.row(t, bobID); r.State != repo.UserError || len(e.Notify.Sent()) != 0 {
		t.Fatalf("row %+v sent %d", r, len(e.Notify.Sent()))
	}
}
