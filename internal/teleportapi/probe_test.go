package teleportapi

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi/identitytest"
)

// An access denial keeps the teleport_rejected reason (HTTP mapping is
// unchanged) but is distinguishable, so the permission probe can tell a
// missing grant from any other refusal.
func TestAccessDeniedIsDistinguishable(t *testing.T) {
	err := MapError(trace.AccessDenied("access denied to perform action %q on %q", "list", "token"))
	if !errors.Is(err, ErrAccessDenied) || !errors.Is(err, ErrRejected) || Reason(err) != "teleport_rejected" {
		t.Fatalf("access denied mapped to %v (%q)", err, Reason(err))
	}
	for _, other := range []error{trace.BadParameter("bad"), status.Error(codes.PermissionDenied, "x"), trace.NotFound("x")} {
		if errors.Is(MapError(other), ErrAccessDenied) {
			t.Errorf("%v is not an access denial", other)
		}
	}
}

// ProbeRead goes through the limiter (mapped errors) and the fake answers
// denials for the kinds it is told to.
func TestProbeReadThroughLimitAndFake(t *testing.T) {
	f := NewFake()
	f.Denied = map[string]bool{ProbeToken: true}
	c := Limit(f, Limits{})
	for _, k := range ProbeKinds {
		err := c.ProbeRead(ctx, k)
		if (k == ProbeToken) != errors.Is(err, ErrAccessDenied) {
			t.Errorf("probe %s: %v", k, err)
		}
	}
	if f.Calls("ProbeRead") != len(ProbeKinds) {
		t.Fatalf("calls %d", f.Calls("ProbeRead"))
	}
	if err := c.ProbeRead(ctx, "secret"); !errors.Is(err, ErrRejected) || errors.Is(err, ErrAccessDenied) {
		t.Fatalf("unknown kind: %v", err)
	}
	// D3 role kinds, in a stable order.
	want := []string{"user", "role", "lock", "token", "node", "app_server", "db_server", "kube_server", "windows_desktop", "event", "session", "cluster_auth_preference"}
	if !slices.Equal(ProbeKinds, want) {
		t.Fatalf("probe kinds %v", ProbeKinds)
	}
}

// SetErr fails every call until cleared (an outage), FailNext still wins once.
func TestFakeSetErr(t *testing.T) {
	f := NewFake()
	f.SetErr(trace.ConnectionProblem(nil, "down"))
	for range 3 {
		if _, err := f.Ping(ctx); err == nil {
			t.Fatal("outage not applied")
		}
	}
	if err := f.ProbeRead(ctx, ProbeUser); err == nil {
		t.Fatal("outage not applied to probes")
	}
	f.SetErr(nil)
	if _, err := f.Ping(ctx); err != nil {
		t.Fatal(err)
	}
}

// ParseIdentityAt reports the issue time and uses the given clock.
func TestParseIdentityAt(t *testing.T) {
	exp := time.Now().Add(48 * time.Hour).Truncate(time.Second).UTC()
	raw := testIdentity(t, "prod.example.com", exp)
	id, err := ParseIdentityAt(secrets.NewSecret([]byte(raw)), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if id.IssuedAt.IsZero() || !id.IssuedAt.Before(id.ExpiresAt) {
		t.Fatalf("issued %v expires %v", id.IssuedAt, id.ExpiresAt)
	}
	if _, err := ParseIdentityAt(secrets.NewSecret([]byte(raw)), exp.Add(time.Second)); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("expired at the given clock: %v", err)
	}
}

// An impersonated identity (tctl auth sign) names its impersonator in the
// TLS subject and in the SSH certificate; a sign-in identity has none
// (spec 005 R2).
func TestParseIdentityImpersonator(t *testing.T) {
	signIn := identitytest.New(t, identitytest.Options{User: "tangra-access"})
	id, err := ParseIdentity(secrets.NewSecret([]byte(signIn)))
	if err != nil || id.Impersonator != "" || id.Subject != "tangra-access" {
		t.Fatalf("sign-in identity %+v %v", id, err)
	}
	signed := identitytest.New(t, identitytest.Options{Impersonator: "abc.prod.example.com"})
	if id, err = ParseIdentity(secrets.NewSecret([]byte(signed))); err != nil || id.Impersonator != "abc.prod.example.com" {
		t.Fatalf("tctl identity %+v %v", id, err)
	}
	sshOnly := identitytest.New(t, identitytest.Options{Impersonator: "abc.prod.example.com", ImpersonatorSSHOnly: true})
	if id, err = ParseIdentity(secrets.NewSecret([]byte(sshOnly))); err != nil || id.Impersonator != "abc.prod.example.com" {
		t.Fatalf("ssh-only impersonator %+v %v", id, err)
	}
}
