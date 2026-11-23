package teleportapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
)

// stubAccess answers GenerateUserCerts by signing the request's public
// keys (as user certUser, so a test can make Teleport "answer" for someone
// else) and records the request.
type stubAccess struct {
	req      proto.UserCertsRequest
	certUser string
	err      error
	caKey    *ecdsa.PrivateKey
	caCert   *x509.Certificate
	caPEM    []byte
	sshCA    ssh.Signer
	mfa      bool
}

func newStubAccess(t *testing.T) *stubAccess {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "prod.example.com"}, IsCA: true,
		BasicConstraintsValid: true, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour * 24), KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	signer, _ := ssh.NewSignerFromKey(k)
	return &stubAccess{caKey: k, caCert: cert, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), sshCA: signer}
}

func (s *stubAccess) GenerateUserCerts(_ context.Context, req proto.UserCertsRequest) (*proto.Certs, error) {
	s.req = req
	if s.err != nil {
		return nil, s.err
	}
	user := req.Username
	if s.certUser != "" {
		user = s.certUser
	}
	block, _ := pem.Decode(req.TLSPublicKey)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: user}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: req.Expires, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, s.caCert, pub, s.caKey)
	if err != nil {
		return nil, err
	}
	spub, _, _, _, err := ssh.ParseAuthorizedKey(req.SSHPublicKey)
	if err != nil {
		return nil, err
	}
	sc := &ssh.Certificate{Key: spub, CertType: ssh.UserCert, KeyId: user,
		ValidPrincipals: []string{"deploy", "-teleport-nologin-1234", "root", "-teleport-internal-join", "deploy"},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(req.Expires.Add(-time.Minute).Unix())} // #nosec G115
	if err := sc.SignCert(rand.Reader, s.sshCA); err != nil {
		return nil, err
	}
	return &proto.Certs{SSH: ssh.MarshalAuthorizedKey(sc), TLS: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		TLSCACerts: [][]byte{s.caPEM}, SSHCACerts: [][]byte{ssh.MarshalAuthorizedKey(s.sshCA.PublicKey())}}, nil
}

func (s *stubAccess) GetAuthPreference(context.Context) (types.AuthPreference, error) {
	mfa := types.RequireMFAType_OFF
	if s.mfa {
		mfa = types.RequireMFAType_SESSION
	}
	return types.NewAuthPreference(types.AuthPreferenceSpecV2{RequireMFAType: mfa})
}

func TestRealIssueUserCerts(t *testing.T) {
	st := newStubAccess(t)
	r := &real{a: st, t: dialTarget{cluster: "prod.example.com"}}
	before := time.Now()
	c, err := r.IssueUserCerts(context.Background(), "tangra-alice", 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// The request names the user, carries only public keys of a key pair
	// generated in memory, and asks for the lifetime.
	if st.req.Username != "tangra-alice" || st.req.RouteToCluster != "prod.example.com" || st.req.Usage != proto.UserCertsRequest_All {
		t.Fatalf("request %+v", st.req)
	}
	if bytes.Contains(st.req.SSHPublicKey, []byte("PRIVATE")) || bytes.Contains(st.req.TLSPublicKey, []byte("PRIVATE")) {
		t.Fatal("a private key was sent")
	}
	if d := st.req.Expires.Sub(before); d < 2*time.Hour-time.Minute || d > 2*time.Hour+time.Minute {
		t.Fatalf("expires in %v", d)
	}
	if c.User != "tangra-alice" || c.Cluster != "prod.example.com" || c.Dropped() {
		t.Fatalf("certs %v", c)
	}
	// Logins are the principals without Teleport's internal ones, once each.
	if strings.Join(c.Logins, ",") != "deploy,root" {
		t.Fatalf("logins %v", c.Logins)
	}
	// The expiry is the earlier of the two certificates (SSH here).
	if d := st.req.Expires.Add(-time.Minute).Sub(c.Expires); d < -time.Second || d > time.Second {
		t.Fatalf("expiry %v vs %v", c.Expires, st.req.Expires)
	}
	if len(c.TLSCAs) != 1 || len(c.SSHCAs) != 1 {
		t.Fatal("host CA missing")
	}
	// The key matches the certificates.
	if _, err := c.tlsConfig(); err != nil {
		t.Fatalf("tls config: %v", err)
	}
	if _, err := c.signer(); err != nil {
		t.Fatal(err)
	}
	c.Drop()
	if !c.Dropped() || c.SSHCert != nil || c.TLSCert != nil || !c.KeyPEM().IsZero() {
		t.Fatal("drop kept material")
	}
	if _, err := c.signer(); err == nil {
		t.Fatal("a dropped key still signs")
	}

	// Certificates for anyone but the requested user are refused.
	st.certUser = "admin"
	if _, err := r.IssueUserCerts(context.Background(), "tangra-alice", time.Hour); err == nil {
		t.Fatal("certificates for another user accepted")
	}
	st.certUser = ""
	for _, bad := range []struct {
		user string
		ttl  time.Duration
	}{{"", time.Hour}, {"u", 0}, {"u", MaxAccessTTL + time.Second}} {
		if _, err := r.IssueUserCerts(context.Background(), bad.user, bad.ttl); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}

	// An impersonation denial stays an access denial through Limit.
	st.err = trace.AccessDenied("user tangra-mgmt is not allowed to impersonate admin")
	l := Limit(r, Limits{})
	_, err = l.IssueUserCerts(context.Background(), "admin", time.Hour)
	if !errors.Is(err, ErrAccessDenied) || !errors.Is(err, ErrRejected) {
		t.Fatalf("denial = %v", err)
	}

	st.mfa = true
	if on, err := l.SessionMFARequired(context.Background()); err != nil || !on {
		t.Fatalf("session mfa = %v %v", on, err)
	}
}

// UserCerts never print their key or certificates.
func TestUserCertsRedacted(t *testing.T) {
	st := newStubAccess(t)
	r := &real{a: st, t: dialTarget{cluster: "prod.example.com"}}
	c, err := r.IssueUserCerts(context.Background(), "tangra-alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key := c.KeyPEM().Reveal()
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("x", "certs", c)
	js, _ := json.Marshal(c)
	js2, _ := json.Marshal(*c)
	outs := []string{fmt.Sprint(c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprintf("%v", *c), fmt.Sprintf("%+v", *c),
		fmt.Sprintf("%#v", *c), fmt.Sprintf("%s", c), fmt.Sprintf("%x", *c), fmt.Sprintf("%d", *c), logs.String(), string(js), string(js2)}
	for _, out := range outs {
		if out != `"teleportapi.UserCerts{user:tangra-alice}"` && !strings.Contains(out, "teleportapi.UserCerts{user:tangra-alice}") {
			t.Errorf("unexpected rendering %q", out)
		}
		if strings.Contains(out, "PRIVATE") || strings.Contains(out, "CERTIFICATE") || strings.Contains(out, "ecdsa") || strings.Contains(out, "[") {
			t.Fatalf("material in %q", out)
		}
		_ = key
	}
}

// hostCert signs a host certificate for principals with ca.
func hostCert(t *testing.T, ca ssh.Signer, principals ...string) ssh.PublicKey {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := ssh.NewPublicKey(&k.PublicKey)
	c := &ssh.Certificate{Key: pub, CertType: ssh.HostCert, ValidPrincipals: principals, ValidBefore: ssh.CertTimeInfinity}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestHostKeyCallbackChecksTheClusterHostCA(t *testing.T) {
	st, other := newStubAccess(t), newStubAccess(t)
	cb, err := HostKeyCallback([][]byte{ssh.MarshalAuthorizedKey(st.sshCA.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
	if err := cb("node-1:0", addr, hostCert(t, st.sshCA, "node-1", "node-1.prod.example.com")); err != nil {
		t.Fatalf("cluster host cert refused: %v", err)
	}
	if err := cb("node-1:0", addr, hostCert(t, other.sshCA, "node-1")); err == nil {
		t.Fatal("host cert of another CA accepted")
	}
	if err := cb("node-1:0", addr, hostCert(t, st.sshCA, "node-2")); err == nil {
		t.Fatal("host cert for another host accepted")
	}
	plain, _ := ssh.NewPublicKey(&st.caKey.PublicKey)
	if err := cb("node-1:0", addr, plain); err == nil {
		t.Fatal("a plain host key accepted")
	}
	if _, err := HostKeyCallback(nil); err == nil {
		t.Fatal("no CA accepted")
	}
	if _, err := HostKeyCallback([][]byte{[]byte("junk")}); err == nil {
		t.Fatal("junk CA accepted")
	}
}

func TestOpenShellNeedsTheGuard(t *testing.T) {
	r := &real{t: dialTarget{proxyAddr: "teleport.example.com:443", cluster: "prod.example.com"}}
	if _, err := r.OpenShell(context.Background(), &UserCerts{}, ShellRequest{Node: "n", Login: "l", Cols: 80, Rows: 24}); !errors.Is(err, ErrBlockedTarget) {
		t.Fatalf("no guard: %v", err)
	}
	if _, err := r.ListNodesAs(context.Background(), &UserCerts{}); !errors.Is(err, ErrBlockedTarget) {
		t.Fatalf("no guard: %v", err)
	}
}

func TestFakeImpersonation(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	f.Info.ClusterName = "prod.example.com"
	f.Users = []User{{Name: "admin", Roles: []string{"editor"}},
		{Name: "tangra-alice", Logins: []string{"deploy"}, Labels: map[string]string{fakeManagedLabel: "true"}}}
	f.Resources = []Resource{{Kind: KindNode, Name: "n1", Hostname: "web-1"}, {Kind: KindNode, Name: "n2"}}
	l := Limit(f, Limits{})
	if _, err := l.IssueUserCerts(ctx, "admin", time.Hour); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("local admin impersonated: %v", err)
	}
	f.MaxCertTTL = 30 * time.Minute
	c, err := l.IssueUserCerts(ctx, "tangra-alice", time.Hour)
	if err != nil || c.User != "tangra-alice" || strings.Join(c.Logins, ",") != "deploy" {
		t.Fatalf("certs %v %v", c, err)
	}
	if d := time.Until(c.Expires); d > 31*time.Minute {
		t.Fatalf("not capped: %v", d)
	}
	if got := f.IssuedCerts(); len(got) != 1 || got[0].TTL != 30*time.Minute {
		t.Fatalf("issued %+v", got)
	}
	f.NodeAccess = map[string][]string{"tangra-alice": {"n1"}}
	nodes, err := l.ListNodesAs(ctx, c)
	if err != nil || len(nodes) != 1 || nodes[0].Name != "n1" {
		t.Fatalf("nodes %+v %v", nodes, err)
	}
	if _, err := l.OpenShell(ctx, c, ShellRequest{Node: "n1", Login: "root", Cols: 80, Rows: 24}); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("login not granted: %v", err)
	}
	if _, err := l.OpenShell(ctx, c, ShellRequest{Node: "n2", Login: "deploy", Cols: 80, Rows: 24}); err == nil {
		t.Fatal("invisible node reached")
	}
	sh, err := l.OpenShell(ctx, c, ShellRequest{Node: "n1", Login: "deploy", Cols: 80, Rows: 24})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Write([]byte("id\r")); err != nil {
		t.Fatal(err)
	}
	_ = sh.Resize(100, 30)
	buf := make([]byte, 256)
	var got strings.Builder
	for !strings.Contains(got.String(), "id\r") {
		n, err := sh.Output().Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got.Write(buf[:n])
	}
	if !strings.HasPrefix(got.String(), "fake shell deploy@n1") {
		t.Fatalf("output %q", got.String())
	}
	fs := f.Shells()[0]
	if fs.User != "tangra-alice" || string(fs.Input()) != "id\r" || len(fs.Sizes()) != 2 {
		t.Fatalf("shell %+v %q %v", fs, fs.Input(), fs.Sizes())
	}
	fs.Exit(errors.New("connection lost"))
	<-sh.Done()
	if sh.Err() == nil {
		t.Fatal("exit error lost")
	}
	if _, err := io.ReadAll(sh.Output()); err != nil {
		t.Fatal(err)
	}
	// Locked or dropped: nothing more.
	f.Locks = []Lock{{Name: "l", TargetKind: "user", Target: "tangra-alice"}}
	if _, err := l.IssueUserCerts(ctx, "tangra-alice", time.Hour); err == nil {
		t.Fatal("locked user impersonated")
	}
	f.Locks = nil
	c.Drop()
	if _, err := l.ListNodesAs(ctx, c); err == nil {
		t.Fatal("dropped certificates used")
	}
	f.ImpersonationDenied = true
	if _, err := l.IssueUserCerts(ctx, "tangra-alice", time.Hour); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("outdated role: %v", err)
	}
}
