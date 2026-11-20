package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeResolver answers from a script: each call pops the next answer (the
// last one repeats), so a test can make a name rebind between lookups.
type fakeResolver struct {
	mu      sync.Mutex
	answers [][]netip.Addr
	err     error
	calls   int
	hosts   []string
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.hosts = append(f.hosts, host)
	if f.err != nil {
		return nil, f.err
	}
	i := f.calls - 1
	if i >= len(f.answers) {
		i = len(f.answers) - 1
	}
	return f.answers[i], nil
}

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, v := range s {
		out[i] = netip.MustParseAddr(v)
	}
	return out
}

// recordingDial records every address dialled and hands back one end of a pipe.
type recordingDial struct {
	mu    sync.Mutex
	addrs []string
	err   error
	block bool
}

func (d *recordingDial) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	block, err := d.block, d.err
	d.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	c, s := net.Pipe()
	_ = s.Close()
	return c, nil
}

func guard(t *testing.T, p Policy, r Resolver, d *recordingDial) *Guard {
	t.Helper()
	g, err := New(p, WithResolver(r), WithDialer(d.dial))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestDefaults(t *testing.T) {
	g, err := New(Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if g.policy.Timeout != 5*time.Second || DefaultTimeout != 5*time.Second {
		t.Fatalf("timeout = %v", g.policy.Timeout)
	}
	if len(g.policy.AllowedPorts) != 2 || g.policy.AllowedPorts[0] != 443 || g.policy.AllowedPorts[1] != 3080 {
		t.Fatalf("ports = %v", g.policy.AllowedPorts)
	}
	if g.resolver == nil || g.dial == nil {
		t.Fatal("default resolver/dialer not set")
	}
	if _, err := New(Policy{AllowedPrivate: []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}}); err == nil {
		t.Fatal("a public prefix was accepted as private")
	}
	if _, err := New(Policy{AllowedPrivate: []netip.Prefix{{}}}); err == nil {
		t.Fatal("an invalid prefix was accepted")
	}
}

func TestCheckClassification(t *testing.T) {
	g, err := New(Policy{})
	if err != nil {
		t.Fatal(err)
	}
	blocked := []string{
		"127.0.0.1", "127.1.2.3", "::1", // loopback
		"169.254.0.1", "169.254.169.254", "fe80::1", // link-local + metadata
		"fd00:ec2::254",                                // AWS IPv6 metadata
		"224.0.0.1", "239.1.2.3", "ff02::1", "ff05::2", // multicast
		"0.0.0.0", "::", // unspecified
		"0.1.2.3", "255.255.255.255", "240.0.0.1", // this-network, broadcast, reserved
		"10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1", "fd12:3456::1", "fc00::1", // private / ULA
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", // IPv4-mapped
		"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", // NAT64 of loopback / metadata
		"2001:db8::1", "192.0.2.1", "198.51.100.1", "203.0.113.1", // documentation
		"198.18.0.1", // benchmarking
	}
	for _, s := range blocked {
		if err := g.Check(netip.MustParseAddr(s)); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: err = %v, want ErrBlocked", s, err)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808"}
	for _, s := range allowed {
		if err := g.Check(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	if err := g.Check(netip.Addr{}); !errors.Is(err, ErrBlocked) {
		t.Error("invalid address accepted")
	}
}

func TestPrivateOptOut(t *testing.T) {
	g, err := New(Policy{AllowedPrivate: []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"10.1.2.3", "::ffff:10.9.9.9", "fd12::1"} {
		if err := g.Check(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s refused despite opt-out: %v", s, err)
		}
	}
	// Outside the opted-in prefixes, and the metadata address inside the ULA
	// opt-out, stay blocked; so do loopback and link-local.
	for _, s := range []string{"192.168.1.1", "172.16.0.1", "fd00:ec2::254", "127.0.0.1", "169.254.169.254", "fc00::1"} {
		if err := g.Check(netip.MustParseAddr(s)); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: err = %v, want ErrBlocked", s, err)
		}
	}
}

func TestParseHostPort(t *testing.T) {
	ok := map[string]struct {
		host string
		port uint16
	}{
		"teleport.example.com":      {"teleport.example.com", 443},
		"Teleport.Example.COM:3080": {"teleport.example.com", 3080},
		"teleport.example.com.":     {"teleport.example.com", 443},
		"8.8.8.8":                   {"8.8.8.8", 443},
		"8.8.8.8:443":               {"8.8.8.8", 443},
		"[2606:4700::1]:443":        {"2606:4700::1", 443},
		"[2606:4700::1]":            {"2606:4700::1", 443},
		"a-b.c-d.example:65535":     {"a-b.c-d.example", 65535},
		"xn--bcher-kva.example:443": {"xn--bcher-kva.example", 443},
	}
	for in, want := range ok {
		h, p, err := ParseHostPort(in, 443)
		if err != nil || h != want.host || p != want.port {
			t.Errorf("%q = %q %d %v, want %q %d", in, h, p, err, want.host, want.port)
		}
	}
	bad := []string{"", " ", "host:", "host:0", "host:65536", "host:-1", "host:abc", "http://host", "host/path",
		"user@host", "host:443:1", "[::1", "2606:4700::1", "-bad.example", "bad-.example", "bad..example",
		"ho st", "host\x00", "host?x=1", "host#f", strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 127) + "com",
		"[2606:4700::1%eth0]:443", ":443", "*.example.com", strings.Repeat("a", 301), "[2606:4700::1]x",
		"[2606:4700::1]:", "host:0443", "[1.2.3.4]:443"}
	if _, _, err := ParseHostPort("host", 0); !errors.Is(err, ErrInvalidAddress) {
		t.Errorf("no port and no default: %v", err)
	}
	for _, in := range bad {
		if _, _, err := ParseHostPort(in, 443); !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("%q: err = %v, want ErrInvalidAddress", in, err)
		}
	}
}

func TestResolveChecksEveryAddress(t *testing.T) {
	r := &fakeResolver{answers: [][]netip.Addr{addrs("8.8.8.8", "10.0.0.1")}}
	g := guard(t, Policy{}, r, &recordingDial{})
	if _, err := g.Resolve(context.Background(), "teleport.example.com"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("a mixed answer was accepted: %v", err)
	}
	r = &fakeResolver{answers: [][]netip.Addr{addrs("8.8.8.8", "1.1.1.1")}}
	g = guard(t, Policy{}, r, &recordingDial{})
	tg, err := g.Resolve(context.Background(), "teleport.example.com:3080")
	if err != nil {
		t.Fatal(err)
	}
	if tg.Host != "teleport.example.com" || tg.Port != 3080 || tg.IP != netip.MustParseAddr("8.8.8.8") || tg.String() != "8.8.8.8:3080" {
		t.Fatalf("target = %+v", tg)
	}
	// IP literals skip DNS.
	r = &fakeResolver{answers: [][]netip.Addr{addrs("8.8.8.8")}}
	g = guard(t, Policy{}, r, &recordingDial{})
	if _, err := g.Resolve(context.Background(), "127.0.0.1"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("loopback literal accepted: %v", err)
	}
	if tg, err := g.Resolve(context.Background(), "1.1.1.1"); err != nil || tg.IP.String() != "1.1.1.1" || r.calls != 0 {
		t.Fatalf("literal = %+v %v (lookups %d)", tg, err, r.calls)
	}
}

func TestResolveRefuses(t *testing.T) {
	ctx := context.Background()
	g := guard(t, Policy{}, &fakeResolver{answers: [][]netip.Addr{addrs("8.8.8.8")}}, &recordingDial{})
	if _, err := g.Resolve(ctx, "teleport.example.com:22"); !errors.Is(err, ErrPort) {
		t.Errorf("port outside the allow-list: %v", err)
	}
	if _, err := g.Resolve(ctx, "bad host"); !errors.Is(err, ErrInvalidAddress) {
		t.Errorf("bad host: %v", err)
	}
	g = guard(t, Policy{}, &fakeResolver{err: errors.New("nxdomain")}, &recordingDial{})
	if _, err := g.Resolve(ctx, "teleport.example.com"); !errors.Is(err, ErrResolve) {
		t.Errorf("resolver failure: %v", err)
	}
	g = guard(t, Policy{}, &fakeResolver{answers: [][]netip.Addr{nil}}, &recordingDial{})
	if _, err := g.Resolve(ctx, "teleport.example.com"); !errors.Is(err, ErrResolve) {
		t.Errorf("empty answer: %v", err)
	}
	g = guard(t, Policy{AllowedPorts: []uint16{8443}}, &fakeResolver{answers: [][]netip.Addr{addrs("8.8.8.8")}}, &recordingDial{})
	if _, err := g.Resolve(ctx, "teleport.example.com"); !errors.Is(err, ErrPort) {
		t.Errorf("default port 443 not in a custom allow-list: %v", err)
	}
	if _, err := g.Resolve(ctx, "teleport.example.com:8443"); err != nil {
		t.Errorf("custom port refused: %v", err)
	}
}

// TestDNSRebinding: the first lookup answers a public address, a later one a
// private address. The dial uses the pinned, checked IP — never the name — so
// the rebinding cannot redirect the connection; and a new dial re-resolves
// and is refused.
func TestDNSRebinding(t *testing.T) {
	r := &fakeResolver{answers: [][]netip.Addr{addrs("8.8.8.8"), addrs("127.0.0.1")}}
	d := &recordingDial{}
	g := guard(t, Policy{}, r, d)
	conn, err := g.DialContext(context.Background(), "tcp", "teleport.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if len(d.addrs) != 1 || d.addrs[0] != "8.8.8.8:443" {
		t.Fatalf("dialled %v, want the pinned 8.8.8.8:443", d.addrs)
	}
	if _, err := g.DialContext(context.Background(), "tcp", "teleport.example.com:443"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("rebound name dialled: %v", err)
	}
	if len(d.addrs) != 1 {
		t.Fatalf("a blocked target was dialled: %v", d.addrs)
	}
	if r.calls != 2 {
		t.Fatalf("lookups = %d, want one per dial", r.calls)
	}
}

func TestDialerForFixedTarget(t *testing.T) {
	r := &fakeResolver{answers: [][]netip.Addr{addrs("1.1.1.1")}}
	d := &recordingDial{}
	g := guard(t, Policy{}, r, d)
	dial := g.Dialer("teleport.example.com:3080")
	// The address passed by the caller (teleport client) is ignored: only the
	// registered proxy address is ever dialled.
	conn, err := dial(context.Background(), "tcp", "169.254.169.254:80")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if len(d.addrs) != 1 || d.addrs[0] != "1.1.1.1:3080" {
		t.Fatalf("dialled %v", d.addrs)
	}
	if r.hosts[0] != "teleport.example.com" {
		t.Fatalf("resolved %v", r.hosts)
	}
}

func TestDialTimeoutAndErrors(t *testing.T) {
	r := &fakeResolver{answers: [][]netip.Addr{addrs("8.8.8.8")}}
	d := &recordingDial{block: true}
	g := guard(t, Policy{Timeout: 50 * time.Millisecond}, r, d)
	start := time.Now()
	_, err := g.DialContext(context.Background(), "tcp", "teleport.example.com")
	if !errors.Is(err, ErrDial) {
		t.Fatalf("err = %v, want ErrDial", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("timeout not applied: %v", el)
	}
	d = &recordingDial{err: errors.New("connection refused")}
	g = guard(t, Policy{}, r, d)
	if _, err := g.DialContext(context.Background(), "tcp", "teleport.example.com"); !errors.Is(err, ErrDial) {
		t.Fatalf("err = %v", err)
	}
	if _, err := g.DialContext(context.Background(), "udp", "teleport.example.com"); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("non-tcp network: %v", err)
	}
	if _, err := g.DialContext(context.Background(), "tcp", "nope:22"); !errors.Is(err, ErrPort) {
		t.Fatalf("port: %v", err)
	}
}

func TestErrorsNeverCarryTheName(t *testing.T) {
	r := &fakeResolver{answers: [][]netip.Addr{addrs("10.0.0.7")}}
	g := guard(t, Policy{}, r, &recordingDial{})
	_, err := g.Resolve(context.Background(), "internal-secret-host.example")
	if err == nil || strings.Contains(err.Error(), "10.0.0.7") || strings.Contains(err.Error(), "internal-secret-host") {
		t.Fatalf("error leaks the target: %v", err)
	}
}

func TestDefaultResolverAndDialer(t *testing.T) {
	g, err := New(Policy{AllowedPorts: []uint16{1}})
	if err != nil {
		t.Fatal(err)
	}
	// "localhost" resolves to loopback through the system resolver and is refused.
	if _, err := g.Resolve(context.Background(), "localhost:1"); !errors.Is(err, ErrBlocked) && !errors.Is(err, ErrResolve) {
		t.Fatalf("localhost: %v", err)
	}
}
