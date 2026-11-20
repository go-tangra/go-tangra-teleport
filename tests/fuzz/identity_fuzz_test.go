package fuzz

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi/identitytest"
)

// FuzzParseIdentity: an uploaded identity file is tenant input. Whatever the
// bytes, the parser never panics, refuses with a field error (size, empty)
// or credential_invalid only, never quotes the input in its error, and on
// success returns a bounded username, a cluster and an expiry after now.
func FuzzParseIdentity(f *testing.F) {
	valid := identitytest.New(f, identitytest.Options{})
	for _, s := range []string{valid, valid[:len(valid)/2], "", " ", "not an identity",
		"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
		"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", strings.Repeat("A", 70000), "\x00\xff"} {
		f.Add([]byte(s))
	}
	now := time.Now()
	f.Fuzz(func(t *testing.T, raw []byte) {
		id, err := clusters.ParseIdentity(raw, now)
		if err != nil {
			if !errors.Is(err, clusters.ErrInvalid) && !errors.Is(err, teleportapi.ErrCredentialInvalid) {
				t.Fatalf("unexpected error class: %v", err)
			}
			if len(raw) >= 16 && strings.Contains(err.Error(), string(raw)) {
				t.Fatalf("error quotes the input: %v", err)
			}
			if id != (clusters.Identity{}) {
				t.Fatalf("refusal returned values: %+v", id)
			}
			return
		}
		if len(raw) > clusters.MaxIdentityBytes || id.Username == "" || len(id.Username) > 256 || id.ClusterName == "" ||
			!id.ExpiresAt.After(now) {
			t.Fatalf("accepted an out-of-bounds identity: %+v", id)
		}
	})
}
