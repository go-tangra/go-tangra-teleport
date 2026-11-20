package clusters

import (
	"bytes"
	"errors"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// MaxIdentityBytes caps an uploaded identity file (plan Constraints).
const MaxIdentityBytes = 64 << 10

// maxUsername bounds the management username (cluster.credential_identity).
const maxUsername = 256

// Identity is the public metadata of a management identity file.
type Identity struct {
	ClusterName string    // the issuing cluster (user CA)
	Username    string    // the Teleport user the module signs in as (FR-013 self-lockout guard)
	IssuedAt    time.Time // certificate NotBefore
	ExpiresAt   time.Time // certificate NotAfter
}

// Lifetime is the certificate validity period.
func (i Identity) Lifetime() time.Duration { return i.ExpiresAt.Sub(i.IssuedAt) }

// ParseIdentity checks an uploaded identity file at now: the size cap and
// emptiness are field errors (validation_failed), anything that does not
// parse as an identity, lacks a user or has expired is
// teleportapi.ErrCredentialInvalid. Errors never quote the input.
func ParseIdentity(raw []byte, now time.Time) (Identity, error) {
	if len(raw) > MaxIdentityBytes {
		return Identity{}, &FieldError{Field: "credential", Msg: "identity file is larger than 64 KiB"}
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return Identity{}, &FieldError{Field: "credential", Msg: "identity file is empty"}
	}
	id, err := teleportapi.ParseIdentityAt(secrets.NewSecret(raw), now)
	if err != nil {
		if errors.Is(err, teleportapi.ErrCredentialInvalid) {
			return Identity{}, err
		}
		return Identity{}, teleportapi.ErrCredentialInvalid
	}
	if id.Subject == "" || len(id.Subject) > maxUsername || id.ClusterName == "" {
		return Identity{}, teleportapi.ErrCredentialInvalid
	}
	return Identity{ClusterName: id.ClusterName, Username: id.Subject, IssuedAt: id.IssuedAt, ExpiresAt: id.ExpiresAt}, nil
}
