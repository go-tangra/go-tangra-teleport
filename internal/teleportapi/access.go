package teleportapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	tclient "github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/client/proxy"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
)

// Brokered access (spec 004). The management identity asks Teleport for
// short-lived certificates as a managed user (impersonation, research R1):
// the key pair is generated here, in memory, and only its public halves go
// to Teleport. UserCerts never reach a log, an error, an event or an audit
// row; Drop wipes the private key when the request or terminal ends.
//
// The certificates are used to list nodes as the user (Teleport RBAC
// decides, R10), to open an SSH session through the cluster proxy (R5:
// DialHost over the SSRF-pinned dialler, the node's host certificate
// checked against the cluster's host CA), and to build a tsh identity file
// (R11, internal/access).

// Teleport-internal SSH principals that are never a login.
const internalPrincipalPrefix = "-teleport"

// MaxAccessTTL bounds a request for user certificates (FR-003: 12 hours).
const MaxAccessTTL = 12 * time.Hour

// UserCerts are short-lived certificates of one Teleport user and their
// private key. Every formatting path redacts them.
type UserCerts struct {
	User    string    // the Teleport user the certificates are for
	Cluster string    // the issuing cluster
	Expires time.Time // the earlier of the SSH and TLS certificate expiries
	Logins  []string  // SSH principals the user may log in as
	SSHCert []byte    // authorized_keys line
	TLSCert []byte    // PEM
	// TLSCAs (PEM) and SSHCAs (authorized_keys lines) are the cluster's
	// host CA (read with GetClusterCACert and GetCertAuthorities: the CAs
	// GenerateUserCerts returns are the user CA).
	TLSCAs [][]byte
	SSHCAs [][]byte

	key secrets.Secret // PKCS#8 PEM
}

// NewUserCerts assembles certificates with their private key (PKCS#8 PEM;
// tests and the Fake).
func NewUserCerts(c UserCerts, keyPEM []byte) *UserCerts {
	c.key = secrets.NewSecret(keyPEM)
	return &c
}

// KeyPEM returns the private key (PKCS#8 PEM) as a secret.
func (c *UserCerts) KeyPEM() secrets.Secret {
	if c == nil {
		return secrets.Secret{}
	}
	return secrets.NewSecret(c.key.Reveal())
}

// Dropped reports whether the private key is gone.
func (c *UserCerts) Dropped() bool { return c == nil || c.key.IsZero() }

// Drop wipes the private key and forgets the certificates.
func (c *UserCerts) Drop() {
	if c == nil {
		return
	}
	c.key.Wipe()
	c.SSHCert, c.TLSCert = nil, nil
}

// String implements fmt.Stringer without any certificate or key (value
// receiver: a UserCerts value prints the same).
func (c UserCerts) String() string { return "teleportapi.UserCerts{user:" + c.User + "}" }

// GoString implements fmt.GoStringer (%#v).
func (c UserCerts) GoString() string { return c.String() }

// Format implements fmt.Formatter: every verb prints String.
func (c UserCerts) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// LogValue implements slog.LogValuer.
func (c UserCerts) LogValue() slog.Value { return slog.StringValue(c.String()) }

// MarshalJSON implements json.Marshaler: never the certificates.
func (c UserCerts) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }

// signer parses the private key.
func (c *UserCerts) signer() (crypto.Signer, error) {
	raw := c.key.Reveal()
	defer clear(raw)
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, trace.BadParameter("no private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	clear(block.Bytes)
	if err != nil {
		return nil, trace.BadParameter("bad private key")
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, trace.BadParameter("bad private key")
	}
	return s, nil
}

// tlsConfig is the client TLS configuration of the certificates: the user's
// certificate, the cluster's host CA as the only roots, and the SNI the
// proxy answers with its Teleport host certificate.
func (c *UserCerts) tlsConfig() (*tls.Config, error) {
	key := c.key.Reveal()
	defer clear(key)
	pair, err := tls.X509KeyPair(c.TLSCert, key)
	if err != nil {
		return nil, trace.BadParameter("bad user certificate")
	}
	pool := x509.NewCertPool()
	for _, ca := range c.TLSCAs {
		if !pool.AppendCertsFromPEM(ca) {
			return nil, trace.BadParameter("bad host CA")
		}
	}
	if len(c.TLSCAs) == 0 {
		return nil, trace.BadParameter("no host CA")
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, RootCAs: pool, MinVersion: tls.VersionTLS12,
		ServerName: apiutils.EncodeClusterName(c.Cluster)}, nil
}

// HostKeyCallback accepts only a host certificate signed by one of the
// cluster's host CAs (SSHCAs) and naming the host dialled; plain host keys
// are refused.
func HostKeyCallback(sshCAs [][]byte) (ssh.HostKeyCallback, error) {
	var cas []ssh.PublicKey
	for _, line := range sshCAs {
		k, _, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			return nil, trace.BadParameter("bad host CA key")
		}
		cas = append(cas, k)
	}
	if len(cas) == 0 {
		return nil, trace.BadParameter("no host CA")
	}
	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			for _, ca := range cas {
				if bytes.Equal(ca.Marshal(), auth.Marshal()) {
					return true
				}
			}
			return false
		},
		HostKeyFallback: func(string, net.Addr, ssh.PublicKey) error {
			return trace.AccessDenied("the node did not present a host certificate of the cluster")
		},
	}
	return checker.CheckHostKey, nil
}

// certsOf turns Teleport's answer into UserCerts, checking that the
// certificates are for user: a certificate for anyone else is refused.
func certsOf(res *proto.Certs, user, cluster string, keyPEM []byte) (*UserCerts, error) {
	if res == nil || len(res.SSH) == 0 || len(res.TLS) == 0 {
		return nil, trace.BadParameter("teleport returned no certificates")
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(res.SSH)
	if err != nil {
		return nil, trace.BadParameter("bad SSH certificate")
	}
	sc, ok := pub.(*ssh.Certificate)
	if !ok || sc.CertType != ssh.UserCert || sc.KeyId != user {
		return nil, trace.BadParameter("the SSH certificate is not for the requested user")
	}
	block, _ := pem.Decode(res.TLS)
	if block == nil {
		return nil, trace.BadParameter("bad TLS certificate")
	}
	tc, err := x509.ParseCertificate(block.Bytes)
	if err != nil || tc.Subject.CommonName != user {
		return nil, trace.BadParameter("the TLS certificate is not for the requested user")
	}
	exp := tc.NotAfter.UTC()
	if sc.ValidBefore != ssh.CertTimeInfinity {
		if s := time.Unix(int64(sc.ValidBefore), 0).UTC(); s.Before(exp) { // #nosec G115 -- a certificate time
			exp = s
		}
	}
	var logins []string
	for _, p := range sc.ValidPrincipals {
		if p != "" && !strings.HasPrefix(p, internalPrincipalPrefix) && !slices.Contains(logins, p) {
			logins = append(logins, p)
		}
	}
	return NewUserCerts(UserCerts{User: user, Cluster: cluster, Expires: exp, Logins: logins, SSHCert: res.SSH, TLSCert: res.TLS,
		TLSCAs: res.TLSCACerts, SSHCAs: res.SSHCACerts}, keyPEM), nil
}

// newKey generates the user's key pair: ECDSA P-256, in memory.
func newKey() (*ecdsa.PrivateKey, []byte, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	clear(der)
	return k, keyPEM, nil
}

// ShellRequest names an interactive SSH session.
type ShellRequest struct {
	Node  string // node name (the host id)
	Login string
	Cols  int
	Rows  int
}

// Shell is an interactive SSH session with a terminal. Output carries
// stdout and stderr; it reaches EOF when the session ends. Done is closed
// when the session ended; Err then tells why (nil for a clean exit).
type Shell interface {
	Output() io.Reader
	Write(p []byte) (int, error)
	Resize(cols, rows int) error
	Done() <-chan struct{}
	Err() error
	Close() error
}

// ---- real

// accessAPI is what brokered access uses of *tclient.Client (a test seam).
type accessAPI interface {
	GenerateUserCerts(ctx context.Context, req proto.UserCertsRequest) (*proto.Certs, error)
	GetAuthPreference(ctx context.Context) (types.AuthPreference, error)
	GetClusterCACert(ctx context.Context) (*proto.GetClusterCACertResponse, error)
	GetCertAuthorities(ctx context.Context, caType types.CertAuthType, loadKeys bool) ([]types.CertAuthority, error)
}

var _ accessAPI = (*tclient.Client)(nil)

// dialTarget is how the real client reaches the cluster's proxy as a user.
type dialTarget struct {
	proxyAddr string
	cluster   string
	guard     *netguard.Guard
	limits    Limits
}

// IssueUserCerts implements Client: certificates for user as the
// management identity (impersonation), valid for ttl at most.
func (r *real) IssueUserCerts(ctx context.Context, user string, ttl time.Duration) (*UserCerts, error) {
	if user == "" || ttl <= 0 || ttl > MaxAccessTTL {
		return nil, trace.BadParameter("bad certificate request")
	}
	k, keyPEM, err := newKey()
	if err != nil {
		return nil, err
	}
	defer clear(keyPEM)
	sshPub, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	res, err := r.a.GenerateUserCerts(ctx, proto.UserCertsRequest{
		SSHPublicKey:   ssh.MarshalAuthorizedKey(sshPub),
		TLSPublicKey:   pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
		Username:       user,
		Expires:        time.Now().Add(ttl).UTC(),
		RouteToCluster: r.t.cluster,
		Format:         constants.CertificateFormatStandard,
		Usage:          proto.UserCertsRequest_All,
	})
	if err != nil {
		return nil, err
	}
	c, err := certsOf(res, user, r.t.cluster, keyPEM)
	if err != nil {
		return nil, err
	}
	// The CAs Teleport returns with user certificates are the user CA; the
	// proxy and the nodes are verified against the host CA.
	if c.TLSCAs, c.SSHCAs, err = r.hostCA(ctx); err != nil {
		c.Drop()
		return nil, err
	}
	return c, nil
}

// hostCA reads the cluster's host CA: its TLS certificates (PEM) and its
// trusted SSH keys (authorized_keys lines). No secrets are loaded.
func (r *real) hostCA(ctx context.Context) (tlsCAs, sshCAs [][]byte, err error) {
	resp, err := r.a.GetClusterCACert(ctx)
	if err != nil {
		return nil, nil, err
	}
	for rest := resp.TLSCA; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		tlsCAs = append(tlsCAs, pem.EncodeToMemory(b))
	}
	cas, err := r.a.GetCertAuthorities(ctx, types.HostCA, false)
	if err != nil {
		return nil, nil, err
	}
	for _, ca := range cas {
		if ca.GetClusterName() != r.t.cluster {
			continue
		}
		for _, kp := range ca.GetTrustedSSHKeyPairs() {
			sshCAs = append(sshCAs, kp.PublicKey)
		}
	}
	if len(tlsCAs) == 0 || len(sshCAs) == 0 {
		return nil, nil, trace.NotFound("the cluster's host CA is not readable")
	}
	return tlsCAs, sshCAs, nil
}

// SessionMFARequired implements Client: the cluster's auth preference
// requires per-session MFA.
func (r *real) SessionMFARequired(ctx context.Context) (bool, error) {
	p, err := r.a.GetAuthPreference(ctx)
	if err != nil {
		return false, err
	}
	return p.GetRequireMFAType().IsSessionMFARequired(), nil
}

// pinnedDialer reaches the registered proxy address only, whatever address
// teleport/api asks for (research D12).
func (t dialTarget) pinnedDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	pinned := t.guard.Dialer(t.proxyAddr)
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return pinned(ctx, network, t.proxyAddr)
	}
}

func (t dialTarget) check(ctx context.Context) error {
	if t.guard == nil {
		return ErrBlockedTarget
	}
	if _, err := t.guard.Resolve(ctx, t.proxyAddr); err != nil {
		return ErrBlockedTarget
	}
	return nil
}

// maxNodes bounds a node listing.
const maxNodes = 1000

// ListNodesAs implements Client: the SSH nodes Teleport lets the
// certificates' user see.
func (r *real) ListNodesAs(ctx context.Context, certs *UserCerts) ([]Resource, error) {
	if err := r.t.check(ctx); err != nil {
		return nil, err
	}
	cfg, err := certs.tlsConfig()
	if err != nil {
		return nil, err
	}
	cfg.ServerName = ""
	dial := r.t.pinnedDialer()
	c, err := tclient.New(ctx, tclient.Config{
		Dialer:                     tclient.ContextDialerFunc(dial),
		Credentials:                []tclient.Credentials{tclient.LoadTLS(cfg)},
		ALPNSNIAuthDialClusterName: certs.Cluster,
		DialTimeout:                r.t.limits.withDefaults().CallTimeout,
		DialOpts:                   DialOptions(r.t.limits),
	})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	var out []Resource
	next := ""
	for len(out) < maxNodes {
		res, err := c.ListResources(ctx, proto.ListResourcesRequest{ResourceType: types.KindNode, Limit: 200, StartKey: next})
		if err != nil {
			return nil, err
		}
		for _, rs := range res.Resources {
			out = append(out, resourceOf(rs))
		}
		if res.NextKey == "" {
			break
		}
		next = res.NextKey
	}
	if len(out) > maxNodes {
		out = out[:maxNodes]
	}
	return out, nil
}

// shellTimeout bounds dialling the proxy and the node and the SSH
// handshake of a new shell.
const shellTimeout = 20 * time.Second

// OpenShell implements Client: an interactive session to req.Node as
// req.Login through the cluster proxy, authenticated as the certificates'
// user. ctx bounds the whole session (cancel it to end the session).
func (r *real) OpenShell(ctx context.Context, certs *UserCerts, req ShellRequest) (Shell, error) {
	if err := r.t.check(ctx); err != nil {
		return nil, err
	}
	cfg, err := certs.tlsConfig()
	if err != nil {
		return nil, err
	}
	signer, err := certs.signer()
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(certs.SSHCert)
	if err != nil {
		return nil, trace.BadParameter("bad SSH certificate")
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, trace.BadParameter("bad SSH certificate")
	}
	algSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, trace.BadParameter("bad private key")
	}
	certSigner, err := ssh.NewCertSigner(cert, algSigner)
	if err != nil {
		return nil, trace.BadParameter("bad SSH certificate")
	}
	hostKey, err := HostKeyCallback(certs.SSHCAs)
	if err != nil {
		return nil, err
	}

	sctx, cancel := context.WithCancel(ctx)
	ok = false
	defer func() {
		if !ok {
			cancel()
		}
	}()
	// Bound the set-up: the proxy stream lives on sctx, so a timer closes
	// it if dialling or the handshake hangs.
	setup := time.AfterFunc(shellTimeout, cancel)
	defer setup.Stop()

	dial := r.t.pinnedDialer()
	pc, err := proxy.NewClient(sctx, proxy.ClientConfig{
		ProxyAddress:      r.t.proxyAddr,
		TLSRoutingEnabled: true,
		TLSConfigFunc:     func(string) (*tls.Config, error) { return cfg.Clone(), nil },
		DialTimeout:       shellTimeout,
		DialOpts: []grpc.DialOption{grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return dial(ctx, "tcp", addr)
		})},
	})
	if err != nil {
		return nil, err
	}
	target := net.JoinHostPort(req.Node, "0")
	conn, _, err := pc.DialHost(sctx, target, certs.Cluster, nil)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	cc, chans, reqs, err := ssh.NewClientConn(conn, target, &ssh.ClientConfig{
		User: req.Login, Auth: []ssh.AuthMethod{ssh.PublicKeys(certSigner)}, HostKeyCallback: hostKey, Timeout: shellTimeout,
	})
	if err != nil {
		_ = conn.Close()
		_ = pc.Close()
		return nil, mapSSHError(err)
	}
	client := ssh.NewClient(cc, chans, reqs)
	sh, err := startShell(client, req)
	if err != nil {
		_ = client.Close()
		_ = pc.Close()
		return nil, mapSSHError(err)
	}
	sh.onClose = func() { cancel(); _ = pc.Close() }
	go func() {
		select {
		case <-sctx.Done():
			_ = sh.Close()
		case <-sh.done:
		}
	}()
	ok = true
	return sh, nil
}

// mapSSHError maps an SSH refusal (no matching login, host key refused) to
// an access denial; everything else is the connection's.
func mapSSHError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unable to authenticate"), strings.Contains(msg, "host certificate"),
		strings.Contains(msg, "access denied"), strings.Contains(msg, "not allowed"):
		return trace.AccessDenied("the node refused the login")
	}
	return trace.ConnectionProblem(err, "ssh session failed")
}

// sshShell is a Shell over an SSH session.
type sshShell struct {
	client  *ssh.Client
	sess    *ssh.Session
	stdin   io.WriteCloser
	out     *io.PipeReader
	done    chan struct{}
	err     error
	once    sync.Once
	onClose func()
}

func startShell(client *ssh.Client, req ShellRequest) (*sshShell, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty("xterm-256color", req.Rows, req.Cols, modes); err != nil {
		_ = sess.Close()
		return nil, err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	pr, pw := io.Pipe()
	sess.Stdout, sess.Stderr = pw, pw
	if err := sess.Shell(); err != nil {
		_ = sess.Close()
		return nil, err
	}
	sh := &sshShell{client: client, sess: sess, stdin: stdin, out: pr, done: make(chan struct{})}
	go func() {
		err := sess.Wait()
		var exit *ssh.ExitError
		var missing *ssh.ExitMissingError
		if errors.As(err, &exit) || errors.As(err, &missing) {
			err = nil // the shell ended on its own; its status is the user's business
		}
		sh.err = err
		_ = pw.Close()
		close(sh.done)
	}()
	return sh, nil
}

func (s *sshShell) Output() io.Reader           { return s.out }
func (s *sshShell) Write(p []byte) (int, error) { return s.stdin.Write(p) }
func (s *sshShell) Done() <-chan struct{}       { return s.done }
func (s *sshShell) Resize(cols, rows int) error { return s.sess.WindowChange(rows, cols) }
func (s *sshShell) Err() error                  { <-s.done; return s.err }
func (s *sshShell) Close() error {
	s.once.Do(func() {
		_ = s.sess.Close()
		_ = s.client.Close()
		if s.onClose != nil {
			s.onClose()
		}
	})
	return nil
}

// ---- limited

// IssueUserCerts is bounded like any call (timeout, cluster slot).
func (c *limited) IssueUserCerts(ctx context.Context, user string, ttl time.Duration) (*UserCerts, error) {
	return call(c, ctx, func(ctx context.Context) (*UserCerts, error) { return c.inner.IssueUserCerts(ctx, user, ttl) })
}

// SessionMFARequired is bounded like any call.
func (c *limited) SessionMFARequired(ctx context.Context) (bool, error) {
	return call(c, ctx, c.inner.SessionMFARequired)
}

// ListNodesAs is bounded like any call.
func (c *limited) ListNodesAs(ctx context.Context, certs *UserCerts) ([]Resource, error) {
	return call(c, ctx, func(ctx context.Context) ([]Resource, error) { return c.inner.ListNodesAs(ctx, certs) })
}

// OpenShell takes neither the call timeout nor a cluster slot: the session
// is long-lived and bounded by the terminal hub (internal/terminal); the
// set-up is bounded by shellTimeout. Errors are mapped.
func (c *limited) OpenShell(ctx context.Context, certs *UserCerts, req ShellRequest) (Shell, error) {
	sh, err := c.inner.OpenShell(ctx, certs, req)
	if err != nil {
		return nil, MapError(err)
	}
	return sh, nil
}
