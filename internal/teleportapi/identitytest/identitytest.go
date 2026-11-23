// Package identitytest builds Teleport identity files for tests: a throwaway
// user CA signs the TLS and SSH certificates of one user, in the format
// `tctl auth sign --format=file` writes. Imported by tests only.
package identitytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/identityfile"
	"golang.org/x/crypto/ssh"
)

// Options shape the identity. Zero values: cluster "prod.example.com", user
// "tangra-mgmt", valid from an hour ago for 30 days.
type Options struct {
	Cluster   string
	User      string
	NotBefore time.Time
	NotAfter  time.Time
	// Impersonator makes an impersonated identity, as tctl auth sign
	// writes (the TLS subject attribute 1.3.9999.2.7 and the SSH extension
	// "impersonator"); empty is a sign-in identity.
	Impersonator string
	// ImpersonatorSSHOnly names the impersonator in the SSH certificate only.
	ImpersonatorSSHOnly bool
}

// impersonatorOID is Teleport's TLS subject attribute of the impersonator.
var impersonatorOID = asn1.ObjectIdentifier{1, 3, 9999, 2, 7}

// New returns the identity file text.
func New(t testing.TB, o Options) string {
	t.Helper()
	if o.Cluster == "" {
		o.Cluster = "prod.example.com"
	}
	if o.User == "" {
		o.User = "tangra-mgmt"
	}
	if o.NotBefore.IsZero() {
		o.NotBefore = time.Now().Add(-time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = o.NotBefore.Add(30 * 24 * time.Hour)
	}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: o.Cluster, Organization: []string{o.Cluster}},
		NotBefore: o.NotBefore.Add(-time.Hour), NotAfter: o.NotAfter.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	must(err)
	caCert, err := x509.ParseCertificate(caDER)
	must(err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	subject := pkix.Name{CommonName: o.User}
	if o.Impersonator != "" && !o.ImpersonatorSSHOnly {
		subject.ExtraNames = []pkix.AttributeTypeAndValue{{Type: impersonatorOID, Value: o.Impersonator}}
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: subject,
		NotBefore: o.NotBefore, NotAfter: o.NotAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	must(err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	must(err)
	caSigner, err := ssh.NewSignerFromKey(caKey)
	must(err)
	sshPub, err := ssh.NewPublicKey(&key.PublicKey)
	must(err)
	sshCert := &ssh.Certificate{Key: sshPub, CertType: ssh.UserCert, KeyId: o.User, ValidPrincipals: []string{o.User},
		ValidAfter: uint64(o.NotBefore.Unix()), ValidBefore: uint64(o.NotAfter.Unix())} // #nosec G115 -- test times are after 1970
	if o.Impersonator != "" {
		sshCert.Permissions.Extensions = map[string]string{"impersonator": o.Impersonator}
	}
	must(sshCert.SignCert(rand.Reader, caSigner))
	id := &identityfile.IdentityFile{
		PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		Certs: identityfile.Certs{TLS: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
			SSH: ssh.MarshalAuthorizedKey(sshCert)},
		CACerts: identityfile.CACerts{TLS: [][]byte{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}},
	}
	b, err := identityfile.Encode(id)
	must(err)
	return string(b)
}

// Fragments returns distinctive pieces of an identity file (the PEM armour
// and a slice of every base64 body) that must never appear in a response,
// log line, event or audit row.
func Fragments(raw string) []string {
	out := []string{"PRIVATE KEY", "BEGIN CERTIFICATE"}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= 48 && !strings.HasPrefix(line, "-----") {
			out = append(out, line[len(line)/2:len(line)/2+24])
		}
	}
	return out
}
