package teleportapi

import (
	"errors"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/types"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
)

func TestConversions(t *testing.T) {
	u, _ := types.NewUser("alice")
	u.SetRoles([]string{"access"})
	u.SetLogins([]string{"ubuntu"})
	u.SetStaticLabels(map[string]string{"tangra.io/managed": "true"})
	got := userOf(u)
	if got.Name != "alice" || got.Roles[0] != "access" || got.Logins[0] != "ubuntu" || got.Labels["tangra.io/managed"] != "true" {
		t.Fatalf("user %+v", got)
	}
	r, _ := types.NewRole("editor", types.RoleSpecV6{})
	if ro := roleOf(r); ro.Name != "editor" || ro.Preset {
		t.Fatalf("role %+v", ro)
	}
	r.SetOrigin(types.OriginDefaults)
	if !roleOf(r).Preset {
		t.Fatal("preset")
	}
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	for target, want := range map[types.LockTarget][2]string{
		{User: "bob"}:     {"user", "bob"},
		{Role: "access"}:  {"role", "access"},
		{ServerID: "n-1"}: {"server_id", "n-1"},
	} {
		l, err := types.NewLock("l", types.LockSpecV2{Target: target, Message: "m", Expires: &exp, CreatedBy: "tangra"})
		if err != nil {
			t.Fatal(err)
		}
		lo := lockOf(l)
		if lo.TargetKind != want[0] || lo.Target != want[1] || lo.Message != "m" || !lo.ExpiresAt.Equal(exp) || lo.CreatedBy != "tangra" {
			t.Fatalf("lock %+v", lo)
		}
	}
}

func TestDialRefusesBeforeConnecting(t *testing.T) {
	g, _ := netguard.New(netguard.Policy{})
	if _, err := Dial(ctx, DialParams{ProxyAddr: "teleport.example.com:443"}); !errors.Is(err, ErrBlockedTarget) {
		t.Fatalf("no guard %v", err)
	}
	if _, err := Dial(ctx, DialParams{ProxyAddr: "teleport.example.com:443", Guard: g, Identity: secrets.NewSecret([]byte("x"))}); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("bad identity %v", err)
	}
	id := secrets.NewSecret([]byte(testIdentity(t, "prod", time.Now().Add(time.Hour))))
	for _, addr := range []string{"127.0.0.1:443", "169.254.169.254:443", "10.0.0.1:443", "8.8.8.8:22"} {
		if _, err := Dial(ctx, DialParams{ProxyAddr: addr, Guard: g, Identity: id}); !errors.Is(err, ErrBlockedTarget) {
			t.Errorf("Dial(%s) = %v", addr, err)
		}
	}
}
