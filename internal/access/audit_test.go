package access_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/identityfile"
	"golang.org/x/crypto/ssh"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/access"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

func rowsOf(e *env, a audit.Action) []repo.AuditRow {
	e.Audit.Flush(context.Background())
	var out []repo.AuditRow
	for _, r := range e.Repo.Audit() {
		if r.Action == string(a) {
			out = append(out, r)
		}
	}
	return out
}

// T010 / R12: every download and refusal is audited, naming the Teleport
// user and never a key or certificate (FR-016, SC-005).
func TestDownloadAudit(t *testing.T) {
	e := newEnv(t)
	id, err := e.svc.Download(mfa(ct.TenantA, alice), e.cluster, 60)
	if err != nil {
		t.Fatal(err)
	}
	defer id.File.Wipe()
	if _, err := e.svc.Download(pwdOnly(ct.TenantA, alice), e.cluster, 0); err == nil {
		t.Fatal("no mfa")
	}
	if _, err := e.svc.Download(mfa(ct.TenantA, carol), e.cluster, 0); err == nil {
		t.Fatal("carol")
	}
	e2 := newEnv(t)
	e2.managed(t, carol, "tangra-carol", labels(ct.TenantA, alice))
	if _, err := e2.svc.Download(mfa(ct.TenantA, carol), e2.cluster, 0); err == nil {
		t.Fatal("label mismatch")
	}
	if _, err := e.svc.Download(mfa(ct.TenantB, alice), e.cluster, 0); err == nil {
		t.Fatal("other tenant")
	}

	rows := rowsOf(e, audit.AccessIssued)
	if len(rows) != 4 {
		t.Fatalf("rows %+v", rows)
	}
	ok := rows[0]
	if ok.Outcome != audit.OutcomeSuccess || ok.TargetKind != audit.TargetManagedUser || ok.TargetName != "tangra-alice" ||
		ok.ClusterID != e.cluster || ok.ActorID != alice || ok.Detail["kind"] != "download" || ok.Detail["ttl_minutes"] != 60 ||
		ok.Detail["expires_at"] == nil || ok.Detail["teleport_user"] != "tangra-alice" {
		t.Fatalf("success row %+v", ok)
	}
	for i, want := range []string{"mfa_required", "not_provisioned", "not_found"} {
		r := rows[i+1]
		if r.Outcome != audit.OutcomeFailure || r.Reason != want {
			t.Errorf("row %d: %+v", i+1, r)
		}
	}
	if r := rows[3]; r.TenantID != ct.TenantB || r.ClusterID != "" {
		t.Errorf("another tenant's cluster id recorded: %+v", r)
	}
	if r := rowsOf(e2, audit.AccessIssued); len(r) != 1 || r[0].Reason != "label_mismatch" || r[0].TargetName != "tangra-carol" {
		t.Fatalf("label mismatch row %+v", r)
	}

	// No secret of any issuance appears in audit rows or logs.
	all, _ := json.Marshal(e.Repo.Audit())
	logs := e.logs.Bytes()
	secrets := e.Teleport.IssuedSecrets()
	if len(secrets) == 0 {
		t.Fatal("no secrets recorded by the fake")
	}
	for _, sec := range secrets {
		for _, frag := range fragments(sec) {
			if bytes.Contains(all, frag) || bytes.Contains(logs, frag) {
				t.Fatalf("issued material leaked: %.40q", frag)
			}
		}
	}
	if bytes.Contains(logs, []byte("BEGIN")) || bytes.Contains(all, []byte("BEGIN")) {
		t.Fatal("PEM in logs or audit")
	}
}

// fragments are recognisable pieces of a secret (raw, base64, a PEM body line).
func fragments(sec []byte) [][]byte {
	out := [][]byte{}
	if len(sec) >= 24 {
		out = append(out, sec[:24])
		out = append(out, []byte(base64.StdEncoding.EncodeToString(sec)[:24]))
	}
	if b, _ := pem.Decode(sec); b != nil && len(b.Bytes) >= 24 {
		out = append(out, []byte(base64.StdEncoding.EncodeToString(b.Bytes)[8:40]))
	}
	return out
}

// T011 / R11: the downloaded identity file holds the key, both
// certificates for the managed user, and the cluster's host CA.
func TestIdentityFile(t *testing.T) {
	e := newEnv(t)
	id, err := e.svc.Download(mfa(ct.TenantA, alice), e.cluster, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer id.File.Wipe()
	f, err := identityfile.FromString(string(id.File.Reveal()))
	if err != nil {
		t.Fatal(err)
	}
	if id.User != "tangra-alice" || id.Proxy != ct.ProxyAddr || id.Cluster != ct.ClusterName {
		t.Fatalf("identity %+v", id)
	}
	if b, _ := pem.Decode(f.PrivateKey); b == nil {
		t.Fatal("no private key")
	}
	b, _ := pem.Decode(f.Certs.TLS)
	if b == nil {
		t.Fatal("no TLS certificate")
	}
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil || leaf.Subject.CommonName != "tangra-alice" || !leaf.NotAfter.Equal(id.Expires.Truncate(time.Second)) && leaf.NotAfter.Sub(id.Expires).Abs() > time.Second {
		t.Fatalf("TLS leaf %v %v (expires %v)", leaf.Subject, err, id.Expires)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(f.Certs.SSH)
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := pub.(*ssh.Certificate); !ok || c.KeyId != "tangra-alice" {
		t.Fatalf("ssh cert %v", pub)
	}
	tlsCA, sshCA := e.Teleport.HostCA()
	if len(f.CACerts.TLS) != 1 || !bytes.Equal(f.CACerts.TLS[0], tlsCA) {
		t.Fatal("TLS host CA missing")
	}
	want := "@cert-authority " + ct.ClusterName + ",*." + ct.ClusterName + " " + strings.TrimSpace(string(sshCA)) + " type=host"
	if len(f.CACerts.SSH) != 1 || strings.TrimSpace(string(f.CACerts.SSH[0])) != want {
		t.Fatalf("known_hosts %q want %q", f.CACerts.SSH, want)
	}
	_ = access.KindDownload
}

func TestNodesAsTheUser(t *testing.T) {
	e := newEnv(t)
	e.Teleport.Resources = append(e.Teleport.Resources, e.Teleport.Resources[len(e.Teleport.Resources)-1])
	e.Teleport.Resources[len(e.Teleport.Resources)-1].Name, e.Teleport.Resources[len(e.Teleport.Resources)-1].Hostname = "node-2", "db-1"
	e.Teleport.NodeAccess = map[string][]string{"tangra-alice": {"node-1"}, "tangra-bob": {"node-1", "node-2"}}
	n, err := e.svc.Nodes(mfa(ct.TenantA, alice), e.cluster)
	if err != nil || len(n) != 1 || n[0].Name != "node-1" || strings.Join(n[0].Logins, ",") != "deploy" {
		t.Fatalf("alice %+v %v", n, err)
	}
	n, err = e.svc.Nodes(mfa(ct.TenantA, bob), e.cluster)
	if err != nil || len(n) != 2 || n[0].Hostname != "db-1" {
		t.Fatalf("bob %+v %v", n, err)
	}
	// Cached for a minute: no second issuance.
	before := len(e.Teleport.IssuedCerts())
	if _, err := e.svc.Nodes(mfa(ct.TenantA, alice), e.cluster); err != nil || len(e.Teleport.IssuedCerts()) != before {
		t.Fatalf("not cached: %v", err)
	}
	e.Advance(61 * time.Second)
	if _, err := e.svc.Nodes(mfa(ct.TenantA, alice), e.cluster); err != nil || len(e.Teleport.IssuedCerts()) != before+1 {
		t.Fatalf("cache not expired: %v", err)
	}
	if got := e.Teleport.IssuedCerts(); got[0].TTL != 5*time.Minute {
		t.Fatalf("listing ttl %v", got[0].TTL)
	}
	// Listing is not an audited issuance.
	if r := rowsOf(e, audit.AccessIssued); len(r) != 0 {
		t.Fatalf("rows %+v", r)
	}
	if _, err := e.svc.Nodes(pwdOnly(ct.TenantA, alice), e.cluster); err == nil {
		t.Fatal("nodes without mfa")
	}
}
