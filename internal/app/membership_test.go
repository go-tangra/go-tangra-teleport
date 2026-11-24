package app

import (
	"context"
	"testing"

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
