package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/provisioning"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
)

// Spec 006: provisioning reads the membership from auth Profiles.Members
// over the module's mesh connection unless a test overrides it.
func TestMembershipWiring(t *testing.T) {
	a, err := Build(context.Background(), testConfig(), options(secrets.NewFake(), nil))
	if err != nil {
		t.Fatal(err)
	}
	m, ok := a.Provisioning.Membership.(provisioning.AuthMembership)
	a.Close()
	if !ok || m.Client == nil {
		t.Fatalf("membership %T", a.Provisioning.Membership)
	}
	o := options(secrets.NewFake(), nil)
	fake := provisioning.NewFakeMembership()
	o.Membership = fake
	b, err := Build(context.Background(), testConfig(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.Provisioning.Membership != fake {
		t.Fatalf("override ignored: %T", b.Provisioning.Membership)
	}
}

// Every notifier of the module resolves recipient user ids to e-mail
// addresses: the same (resolving) sender reaches provisioning, clusters and
// the alert engine; with auth down a send is ErrUnavailable.
func TestNotifierResolvesRecipients(t *testing.T) {
	o := options(secrets.NewFake(), nil)
	o.Notify = notify.NewFake()
	a, err := Build(context.Background(), testConfig(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, ok := a.Notify.(*notify.Resolver); !ok || a.Provisioning.Notify != a.Notify || a.Clusters.Notify != a.Notify || a.AlertEngine.Notify != a.Notify {
		t.Fatalf("notifier %T", a.Notify)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = a.Notify.Send(ctx, notify.Message{TenantID: "11111111-1111-7111-8111-111111111111", Template: notify.TemplateAlert, To: "u1"})
	if !errors.Is(err, notify.ErrUnavailable) {
		t.Fatalf("auth down: %v", err)
	}
}
