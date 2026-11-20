package teleportapi

import (
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/gravitational/teleport/api/identityfile"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
)

// Identity is the public metadata of an identity file (no key material).
type Identity struct {
	ClusterName string    // the issuing user CA (the TLS cert issuer)
	Subject     string    // the Teleport user the identity signs in as
	IssuedAt    time.Time // TLS certificate NotBefore (lifetime for expiry thresholds)
	ExpiresAt   time.Time // TLS certificate NotAfter
}

// ParseIdentity reads an identity file. Any parse failure, a missing TLS
// certificate or an expired one is ErrCredentialInvalid; the error never
// quotes the file.
func ParseIdentity(s secrets.Secret) (Identity, error) { return ParseIdentityAt(s, time.Now()) }

// ParseIdentityAt is ParseIdentity with the expiry judged at now.
func ParseIdentityAt(s secrets.Secret, now time.Time) (Identity, error) {
	id, err := identityfile.FromString(string(s.Reveal()))
	if err != nil || len(id.PrivateKey) == 0 || len(id.Certs.TLS) == 0 {
		return Identity{}, ErrCredentialInvalid
	}
	block, _ := pem.Decode(id.Certs.TLS)
	if block == nil {
		return Identity{}, ErrCredentialInvalid
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Identity{}, ErrCredentialInvalid
	}
	if !now.Before(cert.NotAfter) {
		return Identity{}, &mapped{base: ErrCredentialInvalid, detail: "identity expired"}
	}
	return Identity{ClusterName: cert.Issuer.CommonName, Subject: cert.Subject.CommonName,
		IssuedAt: cert.NotBefore.UTC(), ExpiresAt: cert.NotAfter.UTC()}, nil
}
