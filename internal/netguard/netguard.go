// Package netguard is the SSRF guard for every outbound connection to a
// tenant-supplied address: Teleport cluster proxies and deployment-wizard
// probes (research D12, SR-003). It parses host[:port] strictly, resolves the
// host, checks EVERY resolved address and dials the first checked IP itself,
// so a name that rebinds between the check and the dial cannot redirect the
// connection (each dial resolves and checks again).
//
// Always refused: loopback, link-local (including 169.254.169.254), the
// fd00:ec2::254 metadata address, multicast, unspecified, "this network",
// broadcast, reserved, documentation and benchmarking ranges, and NAT64 or
// IPv4-mapped forms of any of them. RFC 1918, CGNAT and ULA addresses are
// refused unless a Policy.AllowedPrivate prefix covers them (the config's
// teleport.allowed_private_networks, an explicit and logged opt-out). Ports
// are limited to an allow-list (default 443, 3080); dials time out after 5 s.
//
// Errors name the refusal class only, never the host or the resolved address.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Errors (wrapped; match with errors.Is).
var (
	ErrInvalidAddress = errors.New("netguard: invalid address")
	ErrBlocked        = errors.New("netguard: blocked target")
	ErrPort           = errors.New("netguard: port not allowed")
	ErrResolve        = errors.New("netguard: name does not resolve")
	ErrDial           = errors.New("netguard: connection failed")
)

// DefaultTimeout bounds one resolve + dial.
const DefaultTimeout = 5 * time.Second

// DefaultPorts is the port allow-list when Policy.AllowedPorts is empty.
var DefaultPorts = []uint16{443, 3080}

// Policy is what the guard admits.
type Policy struct {
	// AllowedPrivate opens RFC 1918 / CGNAT / ULA prefixes (each must lie
	// inside one of those ranges).
	AllowedPrivate []netip.Prefix
	AllowedPorts   []uint16
	Timeout        time.Duration
}

// Resolver resolves a host name (net.Resolver satisfies it).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DialFunc dials a network address.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Option configures a Guard.
type Option func(*Guard)

// WithResolver replaces the system resolver (tests).
func WithResolver(r Resolver) Option { return func(g *Guard) { g.resolver = r } }

// WithDialer replaces the TCP dialer (tests).
func WithDialer(d DialFunc) Option { return func(g *Guard) { g.dial = d } }

// Guard checks and dials targets.
type Guard struct {
	policy   Policy
	resolver Resolver
	dial     DialFunc
}

// Target is a checked destination: the canonical host and the pinned IP.
type Target struct {
	Host string
	Port uint16
	IP   netip.Addr
}

// String is the pinned ip:port.
func (t Target) String() string { return netip.AddrPortFrom(t.IP, t.Port).String() }

var (
	privateRanges = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("fc00::/7"),
	}
	// blockedRanges are refused whatever the policy says.
	blockedRanges = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("fd00:ec2::254/128"),
	}
	nat64 = netip.MustParsePrefix("64:ff9b::/96")
)

// New builds a guard; the defaults are the system resolver, a plain TCP
// dialer, DefaultPorts and DefaultTimeout.
func New(p Policy, opts ...Option) (*Guard, error) {
	for _, pr := range p.AllowedPrivate {
		if !pr.IsValid() || !insidePrivate(pr) {
			return nil, fmt.Errorf("%w: allowed private prefix outside RFC 1918, CGNAT or ULA", ErrInvalidAddress)
		}
	}
	if len(p.AllowedPorts) == 0 {
		p.AllowedPorts = append([]uint16(nil), DefaultPorts...)
	}
	if p.Timeout <= 0 {
		p.Timeout = DefaultTimeout
	}
	g := &Guard{policy: p, resolver: net.DefaultResolver}
	d := &net.Dialer{}
	g.dial = d.DialContext
	for _, o := range opts {
		o(g)
	}
	return g, nil
}

func insidePrivate(p netip.Prefix) bool {
	for _, r := range privateRanges {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// Check classifies one address.
func (g *Guard) Check(a netip.Addr) error {
	if !a.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrBlocked)
	}
	a = a.Unmap().WithZone("")
	if a.Is6() && nat64.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	switch {
	case a.IsLoopback():
		return fmt.Errorf("%w: loopback", ErrBlocked)
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast():
		return fmt.Errorf("%w: link-local", ErrBlocked)
	case a.IsMulticast(), a.IsInterfaceLocalMulticast():
		return fmt.Errorf("%w: multicast", ErrBlocked)
	case a.IsUnspecified():
		return fmt.Errorf("%w: unspecified", ErrBlocked)
	case a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return fmt.Errorf("%w: broadcast", ErrBlocked)
	}
	for _, r := range blockedRanges {
		if r.Contains(a) {
			return fmt.Errorf("%w: reserved range", ErrBlocked)
		}
	}
	for _, r := range privateRanges {
		if !r.Contains(a) {
			continue
		}
		for _, allowed := range g.policy.AllowedPrivate {
			if allowed.Contains(a) {
				return nil
			}
		}
		return fmt.Errorf("%w: private network", ErrBlocked)
	}
	return nil
}

func (g *Guard) portAllowed(p uint16) bool {
	for _, a := range g.policy.AllowedPorts {
		if a == p {
			return true
		}
	}
	return false
}

// ParseHostPort parses host[:port] strictly: a DNS name (letters, digits,
// hyphens; labels ≤ 63, name ≤ 253, a trailing dot dropped, lower-cased), an
// IPv4 literal, or a bracketed IPv6 literal without a zone. The port is
// 1..65535 and defaults to defaultPort. No scheme, user info, path or query.
func ParseHostPort(s string, defaultPort uint16) (string, uint16, error) {
	bad := func() (string, uint16, error) { return "", 0, ErrInvalidAddress }
	if s == "" || len(s) > 300 {
		return bad()
	}
	host, portStr := s, ""
	switch {
	case strings.HasPrefix(s, "["):
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return bad()
		}
		host = s[1:end]
		rest := s[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return bad()
			}
			portStr = rest[1:]
			if portStr == "" {
				return bad()
			}
		}
		a, err := netip.ParseAddr(host)
		if err != nil || !a.Is6() || a.Zone() != "" {
			return bad()
		}
		host = a.String()
	default:
		if i := strings.LastIndexByte(s, ':'); i >= 0 {
			host, portStr = s[:i], s[i+1:]
			if portStr == "" || strings.ContainsRune(host, ':') {
				return bad()
			}
		}
		// Without brackets a literal has no colon left, so it is IPv4.
		if a, err := netip.ParseAddr(host); err == nil {
			host = a.String()
		} else {
			host = strings.ToLower(strings.TrimSuffix(host, "."))
			if !validName(host) {
				return bad()
			}
		}
	}
	port := defaultPort
	if portStr != "" {
		n, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != portStr {
			return bad()
		}
		port = uint16(n)
	}
	if port == 0 {
		return bad()
	}
	return host, port, nil
}

func validName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Resolve parses hostport, checks the port, resolves the host and checks
// every address. The first address is pinned.
func (g *Guard) Resolve(ctx context.Context, hostport string) (Target, error) {
	host, port, err := ParseHostPort(hostport, 443)
	if err != nil {
		return Target{}, err
	}
	if !g.portAllowed(port) {
		return Target{}, ErrPort
	}
	var ips []netip.Addr
	if a, perr := netip.ParseAddr(host); perr == nil {
		ips = []netip.Addr{a}
	} else {
		ctx, cancel := context.WithTimeout(ctx, g.policy.Timeout)
		defer cancel()
		ips, err = g.resolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return Target{}, ErrResolve
		}
	}
	for _, ip := range ips {
		if err := g.Check(ip); err != nil {
			return Target{}, err
		}
	}
	return Target{Host: host, Port: port, IP: ips[0].Unmap().WithZone("")}, nil
}

// DialContext resolves and checks hostport, then dials the pinned IP over TCP
// within the policy timeout.
func (g *Guard) DialContext(ctx context.Context, network, hostport string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, ErrInvalidAddress
	}
	t, err := g.Resolve(ctx, hostport)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, g.policy.Timeout)
	defer cancel()
	conn, err := g.dial(ctx, "tcp", t.String())
	if err != nil {
		return nil, ErrDial
	}
	return conn, nil
}

// Dialer returns a dial function bound to one registered target: the address
// its caller passes (the Teleport client's own idea of where to go) is
// ignored, so only hostport is ever reached, checked again on every dial.
func (g *Guard) Dialer(hostport string) DialFunc {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return g.DialContext(ctx, network, hostport)
	}
}
