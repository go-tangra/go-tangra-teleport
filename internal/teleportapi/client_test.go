package teleportapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	testpb "google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/gravitational/teleport/api/identityfile"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
)

var ctx = context.Background()

func TestDefaults(t *testing.T) {
	l := Limits{}.withDefaults()
	if l.CallTimeout != 10*time.Second || l.MaxMessageBytes != 4<<20 || l.MaxConcurrent != 4 {
		t.Fatalf("defaults %+v", l)
	}
}

func TestMapError(t *testing.T) {
	cases := []struct {
		in   error
		want error
	}{
		{trace.NotFound("user %q not found", "bob"), ErrNotFound},
		{trace.CompareFailed("revision mismatch"), ErrConflict},
		{trace.AlreadyExists("user exists"), ErrConflict},
		{trace.AccessDenied("access denied to perform action %q on %q", "create", "user"), ErrRejected},
		{trace.BadParameter("bad role spec"), ErrRejected},
		{trace.LimitExceeded("too large"), ErrRejected},
		{status.Error(codes.ResourceExhausted, "grpc: received message larger than max"), ErrRejected},
		{trace.ConnectionProblem(errors.New("dial"), "connection refused"), ErrUnreachable},
		{context.DeadlineExceeded, ErrUnreachable},
		{status.Error(codes.DeadlineExceeded, "deadline"), ErrUnreachable},
		{status.Error(codes.Unavailable, "unavailable"), ErrUnreachable},
		{status.Error(codes.Unauthenticated, "bad cert"), ErrCredentialInvalid},
		{fmt.Errorf("tls: %w", x509.CertificateInvalidError{Reason: x509.Expired}), ErrCredentialInvalid},
		{errors.New("remote error: tls: expired certificate"), ErrCredentialInvalid},
		{errors.New("something odd"), ErrRejected},
	}
	for _, c := range cases {
		got := MapError(c.in)
		if !errors.Is(got, c.want) {
			t.Errorf("MapError(%v) = %v, want %v", c.in, got, c.want)
		}
		if Reason(got) == "" {
			t.Errorf("no reason for %v", got)
		}
	}
	if MapError(nil) != nil {
		t.Fatal("nil")
	}
	// Already-mapped errors pass through unchanged.
	m := MapError(trace.NotFound("x"))
	if MapError(m) != m {
		t.Fatal("double mapping")
	}
	for err, reason := range map[error]string{ErrNotFound: "not_found", ErrConflict: "conflict", ErrRejected: "teleport_rejected",
		ErrUnreachable: "cluster_unreachable", ErrCredentialInvalid: "credential_invalid", ErrBlockedTarget: "blocked_target"} {
		if Reason(err) != reason {
			t.Errorf("Reason(%v) = %q", err, Reason(err))
		}
	}
	if Reason(errors.New("plain")) != "" {
		t.Fatal("reason of an unmapped error")
	}
	// Messages are bounded and never carry multi-line traces.
	long := MapError(trace.BadParameter("%s\n%s", strings.Repeat("x", 600), "goroutine 1 [running]"))
	if len(long.Error()) > 300 || strings.Contains(long.Error(), "\n") || strings.Contains(long.Error(), "goroutine") {
		t.Fatalf("message not sanitized: %q", long.Error())
	}
}

// blockingClient blocks every call until its context ends, counting the
// calls in flight.
type blockingClient struct {
	Fake
	inFlight, peak atomic.Int32
	release        chan struct{}
}

func (b *blockingClient) Ping(ctx context.Context) (Info, error) {
	n := b.inFlight.Add(1)
	defer b.inFlight.Add(-1)
	for {
		p := b.peak.Load()
		if n <= p || b.peak.CompareAndSwap(p, n) {
			break
		}
	}
	select {
	case <-ctx.Done():
		return Info{}, ctx.Err()
	case <-b.release:
		return Info{ClusterName: "c"}, nil
	}
}

func TestLimitedTimeout(t *testing.T) {
	b := &blockingClient{release: make(chan struct{})}
	c := Limit(b, Limits{CallTimeout: 50 * time.Millisecond})
	start := time.Now()
	_, err := c.Ping(ctx)
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("timeout err %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("timeout took %v", d)
	}
}

func TestLimitedSemaphore(t *testing.T) {
	b := &blockingClient{release: make(chan struct{})}
	c := Limit(b, Limits{CallTimeout: 5 * time.Second, MaxConcurrent: 4})
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = c.Ping(ctx) }()
	}
	deadline := time.Now().Add(2 * time.Second)
	for b.inFlight.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	if p := b.peak.Load(); p != 4 {
		t.Fatalf("peak concurrency %d, want 4", p)
	}
	close(b.release)
	wg.Wait()
	// A caller whose context ends while queued gets unreachable, not a hang.
	b2 := &blockingClient{release: make(chan struct{})}
	c2 := Limit(b2, Limits{CallTimeout: 5 * time.Second, MaxConcurrent: 1})
	go func() { _, _ = c2.Ping(ctx) }()
	for b2.inFlight.Load() < 1 {
		time.Sleep(time.Millisecond)
	}
	qctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := c2.Ping(qctx); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("queued caller %v", err)
	}
	close(b2.release)
}

func TestLimitedForwardsEveryMethod(t *testing.T) {
	f := NewFake()
	f.Info = Info{ClusterName: "prod", ServerVersion: "18.1.0", Edition: EditionCommunity}
	f.Users = []User{{Name: "alice", Roles: []string{"access"}}}
	f.Roles = []Role{{Name: "access", Preset: true}}
	f.Locks = []Lock{{Name: "l1", TargetKind: "user", Target: "bob"}}
	f.Resources = []Resource{{Kind: KindNode, Name: "n1", Hostname: "web-1"}}
	c := Limit(f, Limits{})
	if i, err := c.Ping(ctx); err != nil || i.ClusterName != "prod" {
		t.Fatal(i, err)
	}
	if p, err := c.ListUsers(ctx, ListOptions{}); err != nil || len(p.Items) != 1 {
		t.Fatal(p, err)
	}
	if u, err := c.GetUser(ctx, "alice"); err != nil || u.Name != "alice" {
		t.Fatal(u, err)
	}
	if _, err := c.GetUser(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if p, err := c.ListRoles(ctx, ListOptions{}); err != nil || len(p.Items) != 1 {
		t.Fatal(p, err)
	}
	if r, err := c.GetRole(ctx, "access"); err != nil || !r.Preset {
		t.Fatal(r, err)
	}
	if _, err := c.GetRole(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if l, err := c.ListLocks(ctx); err != nil || len(l) != 1 {
		t.Fatal(l, err)
	}
	if p, err := c.ListResources(ctx, KindNode, ListOptions{}); err != nil || len(p.Items) != 1 {
		t.Fatal(p, err)
	}
	if err := c.Close(); err != nil || !f.Closed() {
		t.Fatal("close")
	}
	// Errors from the inner client are mapped.
	f.FailNext("ListUsers", trace.AccessDenied("denied"))
	if _, err := c.ListUsers(ctx, ListOptions{}); !errors.Is(err, ErrRejected) {
		t.Fatal(err)
	}
}

func TestFakePagingAndScripting(t *testing.T) {
	f := NewFake()
	for i := range 5 {
		f.Users = append(f.Users, User{Name: fmt.Sprintf("u%d", i)})
	}
	p, _ := f.ListUsers(ctx, ListOptions{Limit: 2})
	if len(p.Items) != 2 || p.Next == "" {
		t.Fatalf("page 1 %+v", p)
	}
	p2, _ := f.ListUsers(ctx, ListOptions{Limit: 2, Next: p.Next})
	p3, _ := f.ListUsers(ctx, ListOptions{Limit: 2, Next: p2.Next})
	if p2.Items[0].Name != "u2" || len(p3.Items) != 1 || p3.Next != "" {
		t.Fatalf("pages %+v %+v", p2, p3)
	}
	if _, err := f.ListUsers(ctx, ListOptions{Next: "garbage"}); !errors.Is(MapError(err), ErrRejected) {
		t.Fatal("bad cursor")
	}
	for _, m := range []string{"Ping", "ListUsers", "GetUser", "ListRoles", "GetRole", "ListLocks", "ListResources"} {
		f.FailNext(m, trace.ConnectionProblem(nil, "down"))
	}
	if _, err := f.Ping(ctx); err == nil {
		t.Fatal("Ping")
	}
	if _, err := f.ListUsers(ctx, ListOptions{}); err == nil {
		t.Fatal("ListUsers")
	}
	if _, err := f.GetUser(ctx, "u1"); err == nil {
		t.Fatal("GetUser")
	}
	if _, err := f.ListRoles(ctx, ListOptions{}); err == nil {
		t.Fatal("ListRoles")
	}
	if _, err := f.GetRole(ctx, "x"); err == nil {
		t.Fatal("GetRole")
	}
	if _, err := f.ListLocks(ctx); err == nil {
		t.Fatal("ListLocks")
	}
	if _, err := f.ListResources(ctx, KindNode, ListOptions{}); err == nil {
		t.Fatal("ListResources")
	}
	if f.Calls("Ping") != 1 {
		t.Fatalf("calls %d", f.Calls("Ping"))
	}
	// Resources filter by kind.
	f.Resources = []Resource{{Kind: KindNode, Name: "n"}, {Kind: KindApp, Name: "a"}}
	if p, _ := f.ListResources(ctx, KindApp, ListOptions{}); len(p.Items) != 1 || p.Items[0].Name != "a" {
		t.Fatal("kind filter")
	}
}

// echoServer is the grpc interop TestService returning payloads of the
// requested size.
type echoServer struct {
	testpb.UnimplementedTestServiceServer
}

func (echoServer) UnaryCall(_ context.Context, in *testpb.SimpleRequest) (*testpb.SimpleResponse, error) {
	return &testpb.SimpleResponse{Payload: &testpb.Payload{Body: make([]byte, in.GetResponseSize())}}, nil
}

func TestDialOptionsCapResponseSize(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.MaxSendMsgSize(16 << 20))
	testpb.RegisterTestServiceServer(srv, echoServer{})
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	opts := append(DialOptions(Limits{}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }))
	cc, err := grpc.NewClient("passthrough:///bufnet", opts...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	c := testpb.NewTestServiceClient(cc)
	if _, err := c.UnaryCall(ctx, &testpb.SimpleRequest{ResponseSize: 3 << 20}); err != nil {
		t.Fatalf("3 MiB refused: %v", err)
	}
	_, err = c.UnaryCall(ctx, &testpb.SimpleRequest{ResponseSize: 5 << 20})
	if status.Code(err) != codes.ResourceExhausted || !errors.Is(MapError(err), ErrRejected) {
		t.Fatalf("5 MiB response admitted: %v", err)
	}
}

// testIdentity builds an identity file whose TLS cert is issued by a CA named
// cluster and expires at exp.
func testIdentity(t *testing.T, cluster string, exp time.Time) string {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cluster, Organization: []string{cluster}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: exp.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "tangra-mgmt"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: exp, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	// identityfile.FromString requires the SSH user certificate tctl writes.
	caSigner, _ := ssh.NewSignerFromKey(caKey)
	sshPub, _ := ssh.NewPublicKey(&key.PublicKey)
	sshCert := &ssh.Certificate{Key: sshPub, CertType: ssh.UserCert, KeyId: "tangra-mgmt", ValidPrincipals: []string{"tangra-mgmt"},
		ValidAfter: uint64(time.Now().Add(-time.Hour).Unix()), ValidBefore: uint64(exp.Unix())}
	if err := sshCert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	id := &identityfile.IdentityFile{
		PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		Certs: identityfile.Certs{TLS: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
			SSH: ssh.MarshalAuthorizedKey(sshCert)},
		CACerts: identityfile.CACerts{TLS: [][]byte{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}},
	}
	b, err := identityfile.Encode(id)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseIdentity(t *testing.T) {
	exp := time.Now().Add(72 * time.Hour).Truncate(time.Second).UTC()
	raw := testIdentity(t, "prod.example.com", exp)
	id, err := ParseIdentity(secrets.NewSecret([]byte(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if id.ClusterName != "prod.example.com" || !id.ExpiresAt.Equal(exp) || id.Subject != "tangra-mgmt" {
		t.Fatalf("identity %+v", id)
	}
	for _, bad := range []string{"", "not an identity file", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"} {
		_, err := ParseIdentity(secrets.NewSecret([]byte(bad)))
		if !errors.Is(err, ErrCredentialInvalid) || strings.Contains(err.Error(), "PRIVATE") {
			t.Errorf("ParseIdentity(%.20q) = %v", bad, err)
		}
	}
	// Expired identities are refused.
	old := testIdentity(t, "prod.example.com", time.Now().Add(-time.Minute))
	if _, err := ParseIdentity(secrets.NewSecret([]byte(old))); !errors.Is(err, ErrCredentialInvalid) {
		t.Fatalf("expired %v", err)
	}
}

func TestPageSizeClamps(t *testing.T) {
	for in, want := range map[int]int32{-1: 0, 0: 0, 200: 200, math.MaxInt32 + 1: math.MaxInt32} {
		if got := pageSize(in); got != want {
			t.Errorf("pageSize(%d) = %d, want %d", in, got, want)
		}
	}
}
