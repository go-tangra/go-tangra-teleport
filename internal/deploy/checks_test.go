package deploy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/deploy"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

// resolver answers names from a map (a name absent from it does not resolve).
type resolver map[string][]netip.Addr

func (r resolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

var public = []netip.Addr{netip.MustParseAddr("93.184.216.34")}

// tlsServer serves TLS with a certificate for names, signed by its own CA,
// valid until notAfter. Every dial is routed to it.
type tlsServer struct {
	roots *x509.CertPool
	ln    net.Listener
	wg    sync.WaitGroup
}

func newTLSServer(t *testing.T, names []string, notAfter time.Time) *tlsServer {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: notAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	s := &tlsServer{roots: x509.NewCertPool(), ln: ln}
	s.roots.AddCert(caCert)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); s.wg.Wait() })
	return s
}

func prober(t *testing.T, r resolver, srv *tlsServer, p netguard.Policy) *deploy.Prober {
	t.Helper()
	var dials []string
	var mu sync.Mutex
	g, err := netguard.New(p, netguard.WithResolver(r), netguard.WithDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dials = append(dials, addr)
		mu.Unlock()
		if srv == nil {
			return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError("refused")}
		}
		var d net.Dialer
		return d.DialContext(ctx, network, srv.ln.Addr().String())
	}))
	if err != nil {
		t.Fatal(err)
	}
	pr := &deploy.Prober{Guard: g, Now: time.Now}
	if srv != nil {
		pr.Roots = srv.roots
	}
	return pr
}

func byName(cs []repo.DraftCheck) map[string]repo.DraftCheck {
	out := map[string]repo.DraftCheck{}
	for _, c := range cs {
		out[c.Name] = c
	}
	return out
}

func TestChecksPass(t *testing.T) {
	srv := newTLSServer(t, []string{"tp.example.test", "*.tp.example.test"}, time.Now().Add(30*24*time.Hour))
	p := prober(t, resolver{"tp.example.test": public, deploy.WildcardProbe + ".tp.example.test": public}, srv, netguard.Policy{})
	cs := p.Run(context.Background(), "tp.example.test")
	if len(cs) != 3 || cs[0].Name != deploy.CheckDNSApex || cs[1].Name != deploy.CheckDNSWildcard || cs[2].Name != deploy.CheckTLS443 {
		t.Fatalf("checks %+v", cs)
	}
	for _, c := range cs {
		if !c.OK || c.CheckedAt.IsZero() || c.Detail == "" {
			t.Errorf("%s: %+v", c.Name, c)
		}
	}
	if !strings.Contains(byName(cs)[deploy.CheckTLS443].Detail, "valid until") {
		t.Fatalf("tls detail %q", byName(cs)[deploy.CheckTLS443].Detail)
	}
}

func TestChecksFail(t *testing.T) {
	// No DNS at all: both DNS checks fail and TLS cannot be tried.
	p := prober(t, resolver{}, nil, netguard.Policy{})
	for _, c := range p.Run(context.Background(), "tp.example.test") {
		if c.OK {
			t.Errorf("%s passed without DNS", c.Name)
		}
	}
	// The apex resolves, the wildcard does not; nothing answers on 443.
	p = prober(t, resolver{"tp.example.test": public}, nil, netguard.Policy{})
	cs := byName(p.Run(context.Background(), "tp.example.test"))
	if !cs[deploy.CheckDNSApex].OK || cs[deploy.CheckDNSWildcard].OK || cs[deploy.CheckTLS443].OK ||
		!strings.Contains(cs[deploy.CheckTLS443].Detail, "no connection") {
		t.Fatalf("checks %+v", cs)
	}
}

func TestTLSWithAnInvalidCertificate(t *testing.T) {
	r := resolver{"tp.example.test": public, deploy.WildcardProbe + ".tp.example.test": public}
	for name, c := range map[string]struct {
		names    []string
		notAfter time.Time
		trusted  bool
		detail   string
	}{
		"wrong name": {[]string{"other.example.test"}, time.Now().Add(time.Hour), true, "not valid for tp.example.test"},
		"expired":    {[]string{"tp.example.test"}, time.Now().Add(-time.Minute), true, "expired"},
		"untrusted":  {[]string{"tp.example.test"}, time.Now().Add(time.Hour), false, "not trusted"},
	} {
		srv := newTLSServer(t, c.names, c.notAfter)
		p := prober(t, r, srv, netguard.Policy{})
		if !c.trusted {
			p.Roots = x509.NewCertPool()
		}
		got := byName(p.Run(context.Background(), "tp.example.test"))[deploy.CheckTLS443]
		if got.OK || !strings.Contains(got.Detail, c.detail) {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

// SR-003: probes go only through netguard, so private, loopback, link-local
// and metadata targets are refused (and never dialled) unless allowed.
func TestPrivateTargetsRefused(t *testing.T) {
	srv := newTLSServer(t, []string{"tp.example.test", "*.tp.example.test"}, time.Now().Add(time.Hour))
	for _, addr := range []string{"10.0.0.5", "127.0.0.1", "169.254.169.254", "192.168.1.1", "::1"} {
		a := []netip.Addr{netip.MustParseAddr(addr)}
		p := prober(t, resolver{"tp.example.test": a, deploy.WildcardProbe + ".tp.example.test": a}, srv, netguard.Policy{})
		for _, c := range p.Run(context.Background(), "tp.example.test") {
			if c.OK || !strings.Contains(c.Detail, "refused") {
				t.Errorf("%s %s: %+v", addr, c.Name, c)
			}
			if strings.Contains(c.Detail, addr) {
				t.Errorf("%s: the detail names the address", c.Name)
			}
		}
	}
	// An explicitly allowed private network is probed.
	a := []netip.Addr{netip.MustParseAddr("10.0.0.5")}
	p := prober(t, resolver{"tp.example.test": a, deploy.WildcardProbe + ".tp.example.test": a}, srv,
		netguard.Policy{AllowedPrivate: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	for _, c := range p.Run(context.Background(), "tp.example.test") {
		if !c.OK {
			t.Errorf("allowed private %s: %+v", c.Name, c)
		}
	}
	// An invalid domain is refused before any lookup.
	if cs := prober(t, resolver{}, nil, netguard.Policy{}).Run(context.Background(), "bad domain"); cs[0].OK || cs[2].OK {
		t.Fatalf("invalid domain %+v", cs)
	}
}

func TestRateLimit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := &deploy.Limiter{Every: 10 * time.Second, Now: func() time.Time { return now }}
	if !l.Allow("d1") || l.Allow("d1") {
		t.Fatal("second call within 10 s allowed")
	}
	if !l.Allow("d2") {
		t.Fatal("drafts share a budget")
	}
	now = now.Add(9 * time.Second)
	if l.Allow("d1") {
		t.Fatal("allowed after 9 s")
	}
	now = now.Add(time.Second)
	if !l.Allow("d1") {
		t.Fatal("refused after 10 s")
	}
	// Old entries are forgotten.
	now = now.Add(time.Hour)
	if !l.Allow("d2") || l.Len() != 1 {
		t.Fatalf("entries %d", l.Len())
	}
	var zero deploy.Limiter
	if !zero.Allow("x") || zero.Allow("x") {
		t.Fatal("zero limiter: 1 call per 10 s by default")
	}
}
