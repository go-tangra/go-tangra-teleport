package teleportapi

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"time"

	"github.com/gravitational/teleport/api/identityfile"
	"golang.org/x/crypto/ssh"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
)

// Identity is the public metadata of an identity file (no key material).
type Identity struct {
	ClusterName string    // the issuing user CA (the TLS cert issuer)
	Subject     string    // the Teleport user the identity signs in as
	IssuedAt    time.Time // TLS certificate NotBefore (lifetime for expiry thresholds)
	ExpiresAt   time.Time // TLS certificate NotAfter
	// Impersonator is who issued the certificates on the subject's behalf
	// (every tctl auth sign identity has one); empty for a sign-in
	// identity (spec 005 R2). Teleport never lets an impersonated
	// certificate impersonate anyone else.
	Impersonator string
}

// impersonatorOID is the TLS subject attribute Teleport writes the
// impersonator into (its tlsca package, ImpersonatorASN1ExtensionOID).
var impersonatorOID = asn1.ObjectIdentifier{1, 3, 9999, 2, 7}

// sshImpersonator is the SSH certificate extension of the impersonator.
const sshImpersonator = "impersonator"

// impersonator reads the impersonator from the TLS subject, then from the
// SSH certificate.
func impersonator(cert *x509.Certificate, sshCert []byte) string {
	for _, n := range cert.Subject.Names {
		if n.Type.Equal(impersonatorOID) {
			if v, ok := n.Value.(string); ok && v != "" {
				return v
			}
		}
	}
	if len(sshCert) == 0 {
		return ""
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(sshCert)
	if err != nil {
		return ""
	}
	if c, ok := pub.(*ssh.Certificate); ok {
		return c.Permissions.Extensions[sshImpersonator]
	}
	return ""
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
		IssuedAt: cert.NotBefore.UTC(), ExpiresAt: cert.NotAfter.UTC(), Impersonator: impersonator(cert, id.Certs.SSH)}, nil
}
