package access

import (
	"bytes"
	"context"
	"time"

	"github.com/gravitational/teleport/api/identityfile"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// Identity is a downloaded Teleport identity file (R11): the key, the SSH
// and TLS certificates and the cluster's host CA, for `tsh -i`. File is
// wiped by the caller once written; it is never stored or logged.
type Identity struct {
	User    string
	Cluster string // the Teleport cluster name
	Proxy   string
	Expires time.Time
	File    secrets.Secret
}

// Download issues an identity file for the caller's own managed user
// (access:download, MFA). minutes > 0 shortens the cluster's lifetime.
// Every outcome is audited (teleport.access.issued).
func (s *Service) Download(ctx context.Context, clusterID string, minutes int) (Identity, error) {
	details := map[string]any{"kind": KindDownload}
	g, err := s.Resolve(ctx, clusterID, authz.AccessDownload, true)
	if err != nil {
		s.Record(ctx, audit.AccessIssued, g, err, details)
		return Identity{}, err
	}
	ttl, err := TTL(g.Settings, minutes)
	if err != nil {
		s.Record(ctx, audit.AccessIssued, g, err, details)
		return Identity{}, err
	}
	details["ttl_minutes"] = int(ttl / time.Minute)
	certs, err := s.Issue(ctx, g, ttl)
	if err != nil {
		s.Record(ctx, audit.AccessIssued, g, err, details)
		return Identity{}, err
	}
	defer certs.Drop()
	file, err := EncodeIdentity(certs)
	if err != nil {
		s.Record(ctx, audit.AccessIssued, g, err, details)
		return Identity{}, err
	}
	details["expires_at"] = certs.Expires.UTC().Format(time.RFC3339)
	s.Record(ctx, audit.AccessIssued, g, nil, details)
	return Identity{User: certs.User, Cluster: certs.Cluster, Proxy: g.Cluster.ProxyAddr, Expires: certs.Expires, File: file}, nil
}

// EncodeIdentity is the identity file of certs: the private key, the SSH
// and TLS certificates, the TLS host CA and the SSH host CA as known_hosts
// @cert-authority lines for the cluster.
func EncodeIdentity(c *teleportapi.UserCerts) (secrets.Secret, error) {
	key := c.KeyPEM()
	defer key.Wipe()
	id := &identityfile.IdentityFile{PrivateKey: key.Reveal(), Certs: identityfile.Certs{SSH: c.SSHCert, TLS: c.TLSCert}}
	for _, ca := range c.TLSCAs {
		id.CACerts.TLS = append(id.CACerts.TLS, bytes.Clone(ca))
	}
	for _, k := range c.SSHCAs {
		line := "@cert-authority " + c.Cluster + ",*." + c.Cluster + " " + string(bytes.TrimSpace(k)) + " type=host\n"
		id.CACerts.SSH = append(id.CACerts.SSH, []byte(line))
	}
	b, err := identityfile.Encode(id)
	clear(id.PrivateKey)
	if err != nil {
		return secrets.Secret{}, err
	}
	out := secrets.NewSecret(b)
	clear(b)
	return out, nil
}
