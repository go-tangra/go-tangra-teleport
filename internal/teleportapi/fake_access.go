package teleportapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"slices"
	"sync"
	"time"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
)

// The Fake's brokered-access surface (spec 004). IssueUserCerts behaves like
// the documented tangra-manager role: only users labelled
// tangra.io/managed=true can be impersonated (ImpersonationDenied refuses
// every user, as a role without the impersonate rule would), never a locked
// user; MaxCertTTL caps the lifetime as Teleport may. Certificates are
// signed by a fake host/user CA and carry the user's logins. OpenShell
// returns a FakeShell that echoes its input; it refuses a login the
// certificates do not carry and a node the user cannot see (NodeAccess).

// fakeManagedLabel is users.LabelManaged (not imported: users imports this
// package).
const fakeManagedLabel = "tangra.io/managed"

// FakeIssue records one IssueUserCerts call.
type FakeIssue struct {
	User   string
	TTL    time.Duration
	Access bool // issued through AccessIssuer (the access identity)
}

type fakeHostCA struct {
	key    *ecdsa.PrivateKey
	cert   *x509.Certificate
	pem    []byte
	signer ssh.Signer
}

type fakeAccess struct {
	ca      *fakeHostCA
	issues  []FakeIssue
	secrets [][]byte // every key PEM and certificate handed out
	shells  []*FakeShell
}

// IssuedCerts lists every IssueUserCerts call that succeeded.
func (f *Fake) IssuedCerts() []FakeIssue {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.access.issues)
}

// IssuedSecrets returns every private key (PEM) and certificate the fake
// handed out, so leak tests can look for them in every output channel.
func (f *Fake) IssuedSecrets() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.access.secrets))
	for i, s := range f.access.secrets {
		out[i] = slices.Clone(s)
	}
	return out
}

// Shells lists every shell the fake opened, oldest first.
func (f *Fake) Shells() []*FakeShell {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.access.shells)
}

// HostCA returns the fake cluster's host CA: the TLS certificate (PEM) and
// the SSH CA key (authorized_keys line).
func (f *Fake) HostCA() (tlsPEM, sshKey []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ca := f.caLocked()
	return slices.Clone(ca.pem), ssh.MarshalAuthorizedKey(ca.signer.PublicKey())
}

func (f *Fake) caLocked() *fakeHostCA {
	if f.access.ca != nil {
		return f.access.ca
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	name := f.Info.ClusterName
	if name == "" {
		name = "fake.example.com"
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name, Organization: []string{name}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, _ := x509.ParseCertificate(der)
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		panic(err)
	}
	f.access.ca = &fakeHostCA{key: key, cert: cert, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), signer: signer}
	return f.access.ca
}

func (f *Fake) lockedLocked(user string) bool {
	return slices.ContainsFunc(f.Locks, func(l Lock) bool { return l.TargetKind == "user" && l.Target == user })
}

// IssueUserCerts implements Client.
func (f *Fake) IssueUserCerts(_ context.Context, user string, ttl time.Duration) (*UserCerts, error) {
	return f.issue(user, ttl, false)
}

// AccessIssuer is the same cluster seen through an access identity (spec
// 005): the same users, CAs and nodes, but IssueUserCerts obeys
// AccessImpersonationDenied (not ImpersonationDenied), its issues are
// marked Access, and Close leaves the Fake open.
func (f *Fake) AccessIssuer() Client { return fakeAccessIssuer{f} }

type fakeAccessIssuer struct{ *Fake }

func (a fakeAccessIssuer) IssueUserCerts(_ context.Context, user string, ttl time.Duration) (*UserCerts, error) {
	return a.issue(user, ttl, true)
}

func (fakeAccessIssuer) Close() error { return nil }

func (f *Fake) issue(user string, ttl time.Duration, viaAccess bool) (*UserCerts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("IssueUserCerts"); err != nil {
		return nil, err
	}
	if user == "" || ttl <= 0 || ttl > MaxAccessTTL {
		return nil, trace.BadParameter("bad certificate request")
	}
	denied := f.ImpersonationDenied
	if viaAccess {
		denied = f.AccessImpersonationDenied
	}
	i := f.userIndex(user)
	if denied || i < 0 || f.Users[i].Labels[fakeManagedLabel] != "true" {
		return nil, trace.AccessDenied("user %q is not allowed to impersonate %q", "tangra-mgmt", user)
	}
	if f.lockedLocked(user) {
		return nil, trace.AccessDenied("this user is locked")
	}
	if f.MaxCertTTL > 0 && ttl > f.MaxCertTTL {
		ttl = f.MaxCertTTL
	}
	u := f.Users[i]
	ca := f.caLocked()
	now := time.Now().UTC().Truncate(time.Second)
	exp := now.Add(ttl)
	key, keyPEM, err := newKey()
	if err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: user},
		NotBefore: now.Add(-time.Minute), NotAfter: exp, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sc := &ssh.Certificate{Key: pub, CertType: ssh.UserCert, KeyId: user,
		ValidPrincipals: append(slices.Clone(u.Logins), "-teleport-internal-join"),
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()), ValidBefore: uint64(exp.Unix())} // #nosec G115 -- current times
	if err := sc.SignCert(rand.Reader, ca.signer); err != nil {
		return nil, err
	}
	sshLine := ssh.MarshalAuthorizedKey(sc)
	tlsPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.access.issues = append(f.access.issues, FakeIssue{User: user, TTL: ttl, Access: viaAccess})
	f.access.secrets = append(f.access.secrets, slices.Clone(keyPEM), slices.Clone(sshLine), slices.Clone(tlsPEM))
	name := f.Info.ClusterName
	return certsOf(&proto.Certs{SSH: sshLine, TLS: tlsPEM, TLSCACerts: [][]byte{ca.pem},
		SSHCACerts: [][]byte{ssh.MarshalAuthorizedKey(ca.signer.PublicKey())}}, user, name, keyPEM)
}

// SessionMFARequired implements Client (ClusterSessionMFA).
func (f *Fake) SessionMFARequired(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("SessionMFARequired"); err != nil {
		return false, err
	}
	return f.ClusterSessionMFA, nil
}

// checkCerts refuses dropped, expired or foreign certificates. Callers hold mu.
func (f *Fake) checkCerts(c *UserCerts) error {
	if c == nil || c.Dropped() {
		return trace.AccessDenied("no certificates")
	}
	if !time.Now().Before(c.Expires) {
		return trace.AccessDenied("certificate expired")
	}
	if f.userIndex(c.User) < 0 || f.lockedLocked(c.User) {
		return trace.AccessDenied("access denied")
	}
	return nil
}

func (f *Fake) visible(user, node string) bool {
	nodes, ok := f.NodeAccess[user]
	return f.NodeAccess == nil || (ok && slices.Contains(nodes, node))
}

// ListNodesAs implements Client: the nodes NodeAccess lets the user see
// (every node when NodeAccess is nil).
func (f *Fake) ListNodesAs(_ context.Context, certs *UserCerts) ([]Resource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("ListNodesAs"); err != nil {
		return nil, err
	}
	if err := f.checkCerts(certs); err != nil {
		return nil, err
	}
	var out []Resource
	for _, r := range f.Resources {
		if r.Kind == KindNode && f.visible(certs.User, r.Name) {
			out = append(out, r)
		}
	}
	return out, nil
}

// OpenShell implements Client.
func (f *Fake) OpenShell(ctx context.Context, certs *UserCerts, req ShellRequest) (Shell, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("OpenShell"); err != nil {
		return nil, err
	}
	if err := f.checkCerts(certs); err != nil {
		return nil, err
	}
	known := slices.ContainsFunc(f.Resources, func(r Resource) bool { return r.Kind == KindNode && r.Name == req.Node })
	if !known || !f.visible(certs.User, req.Node) {
		return nil, trace.ConnectionProblem(nil, "failed connecting to host")
	}
	if !slices.Contains(certs.Logins, req.Login) {
		return nil, trace.AccessDenied("the node refused the login")
	}
	sh := newFakeShell(certs.User, req)
	f.access.shells = append(f.access.shells, sh)
	go func() {
		select {
		case <-ctx.Done():
			_ = sh.Close()
		case <-sh.done:
		}
	}()
	sh.Print("fake shell " + req.Login + "@" + req.Node + "\r\n")
	return sh, nil
}

// FakeShell is the Fake's interactive session: input is recorded and
// echoed; Print writes output; Exit ends it.
type FakeShell struct {
	User, Node, Login string

	pr   *io.PipeReader
	pw   *io.PipeWriter
	out  chan []byte
	done chan struct{}

	mu      sync.Mutex
	input   []byte
	sizes   [][2]int
	err     error
	once    sync.Once
	closed  bool
	stopped chan struct{}
}

func newFakeShell(user string, req ShellRequest) *FakeShell {
	pr, pw := io.Pipe()
	s := &FakeShell{User: user, Node: req.Node, Login: req.Login, pr: pr, pw: pw, out: make(chan []byte, 1024),
		done: make(chan struct{}), stopped: make(chan struct{}), sizes: [][2]int{{req.Cols, req.Rows}}}
	go func() {
		defer close(s.stopped)
		for {
			select {
			case b := <-s.out:
				if _, err := pw.Write(b); err != nil {
					return
				}
			case <-s.done:
				for {
					select {
					case b := <-s.out:
						_, _ = pw.Write(b)
					default:
						_ = pw.Close()
						return
					}
				}
			}
		}
	}()
	return s
}

// Output implements Shell.
func (s *FakeShell) Output() io.Reader { return s.pr }

// Write implements Shell: the input is recorded and echoed.
func (s *FakeShell) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	s.input = append(s.input, p...)
	s.mu.Unlock()
	s.Print(string(p))
	return len(p), nil
}

// Print writes output (dropped once the shell ended).
func (s *FakeShell) Print(out string) {
	select {
	case <-s.done:
	case s.out <- []byte(out):
	}
}

// Resize implements Shell.
func (s *FakeShell) Resize(cols, rows int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sizes = append(s.sizes, [2]int{cols, rows})
	return nil
}

// Done implements Shell.
func (s *FakeShell) Done() <-chan struct{} { return s.done }

// Err implements Shell.
func (s *FakeShell) Err() error {
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Exit ends the session with err (nil: the shell exited).
func (s *FakeShell) Exit(err error) {
	s.once.Do(func() {
		s.mu.Lock()
		s.err, s.closed = err, true
		s.mu.Unlock()
		close(s.done)
	})
}

// Close implements Shell.
func (s *FakeShell) Close() error {
	s.Exit(nil)
	return nil
}

// Closed reports whether the session ended.
func (s *FakeShell) Closed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// Input returns everything written to the shell.
func (s *FakeShell) Input() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.input)
}

// Sizes returns the terminal sizes, the initial one first.
func (s *FakeShell) Sizes() [][2]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.sizes)
}
