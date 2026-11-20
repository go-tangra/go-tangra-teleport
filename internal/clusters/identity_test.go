package clusters_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi/identitytest"
)

func TestParseIdentity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	raw := identitytest.New(t, identitytest.Options{Cluster: "prod.example.com", User: "tangra-mgmt",
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(720 * time.Hour)})
	id, err := clusters.ParseIdentity([]byte(raw), now)
	if err != nil {
		t.Fatal(err)
	}
	if id.ClusterName != "prod.example.com" || id.Username != "tangra-mgmt" ||
		!id.IssuedAt.Equal(now.Add(-time.Hour)) || !id.ExpiresAt.Equal(now.Add(720*time.Hour)) {
		t.Fatalf("identity %+v", id)
	}
	if id.Lifetime() != 721*time.Hour {
		t.Fatalf("lifetime %v", id.Lifetime())
	}
}

func TestParseIdentityRefusals(t *testing.T) {
	now := time.Now().UTC()
	valid := identitytest.New(t, identitytest.Options{})
	expired := identitytest.New(t, identitytest.Options{NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-time.Hour)})
	for _, c := range []struct {
		name string
		raw  []byte
		want error
	}{
		{"empty", nil, clusters.ErrInvalid},
		{"blank", []byte("   \n"), clusters.ErrInvalid},
		{"over 64 KiB", []byte(valid + strings.Repeat("#", clusters.MaxIdentityBytes)), clusters.ErrInvalid},
		{"malformed", []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), teleportapi.ErrCredentialInvalid},
		{"garbage", []byte("not an identity file"), teleportapi.ErrCredentialInvalid},
		{"truncated", []byte(valid[:len(valid)/2]), teleportapi.ErrCredentialInvalid},
		{"expired", []byte(expired), teleportapi.ErrCredentialInvalid},
	} {
		_, err := clusters.ParseIdentity(c.raw, now)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
			continue
		}
		// The error never quotes the file.
		for _, f := range identitytest.Fragments(string(c.raw)) {
			if strings.Contains(err.Error(), f) {
				t.Errorf("%s: error quotes the input: %v", c.name, err)
			}
		}
	}
	// Exactly the cap is accepted as a size; the file then parses or not on its own.
	var fe *clusters.FieldError
	_, err := clusters.ParseIdentity(make([]byte, clusters.MaxIdentityBytes+1), now)
	if !errors.As(err, &fe) || fe.Field != "credential" {
		t.Fatalf("size refusal names no field: %v", err)
	}
	if clusters.MaxIdentityBytes != 64<<10 {
		t.Fatalf("cap %d", clusters.MaxIdentityBytes)
	}
}
