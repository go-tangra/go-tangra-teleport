package deploy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

// Prerequisite check names (data-model deployment_draft.checks).
const (
	CheckDNSApex     = "dns_apex"
	CheckDNSWildcard = "dns_wildcard"
	CheckTLS443      = "tls_443"
)

// WildcardProbe is the label resolved under the domain to test its wildcard
// record (any name under a wildcard resolves).
const WildcardProbe = "tangra-wildcard-check"

// DefaultCheckEvery is the per-draft check budget: one run per 10 s.
const DefaultCheckEvery = 10 * time.Second

// Prober runs the prerequisite checks, only through Guard (netguard: every
// resolved address is checked and the dial is pinned, so private, loopback,
// link-local and metadata targets are refused unless the deployment allows
// a private range). Roots verifies the certificate (nil: the system pool).
// Details name the outcome class, never a resolved address.
type Prober struct {
	Guard *netguard.Guard
	Roots *x509.CertPool
	Now   func() time.Time
}

func (p *Prober) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}

// refusal explains a netguard error without the target's address.
func refusal(err error) string {
	switch {
	case errors.Is(err, netguard.ErrBlocked):
		return "refused: the name resolves to a loopback, link-local, metadata or private address"
	case errors.Is(err, netguard.ErrResolve):
		return "the name does not resolve"
	case errors.Is(err, netguard.ErrInvalidAddress):
		return "refused: not a valid domain"
	case errors.Is(err, netguard.ErrPort):
		return "refused: port 443 is not allowed by this deployment"
	case errors.Is(err, netguard.ErrDial):
		return "no connection on port 443"
	}
	return "the check failed"
}

func (p *Prober) resolve(ctx context.Context, name, check, ok string) repo.DraftCheck {
	c := repo.DraftCheck{Name: check, CheckedAt: p.now()}
	if _, err := p.Guard.Resolve(ctx, name+":443"); err != nil {
		c.Detail = refusal(err)
		return c
	}
	c.OK, c.Detail = true, ok
	return c
}

// tlsDetail explains a failed certificate verification.
func tlsDetail(err error, domain string) string {
	var host x509.HostnameError
	var inv x509.CertificateInvalidError
	var unk x509.UnknownAuthorityError
	switch {
	case errors.As(err, &host):
		return "the certificate is not valid for " + domain
	case errors.As(err, &inv) && inv.Reason == x509.Expired:
		return "the certificate has expired or is not yet valid"
	case errors.As(err, &unk):
		return "the certificate is not trusted (unknown or self-signed issuer)"
	case errors.As(err, &inv):
		return "the certificate is invalid"
	}
	return "port 443 answered without a working TLS handshake"
}

func (p *Prober) tls443(ctx context.Context, domain string) repo.DraftCheck {
	c := repo.DraftCheck{Name: CheckTLS443, CheckedAt: p.now()}
	conn, err := p.Guard.DialContext(ctx, "tcp", domain+":443")
	if err != nil {
		c.Detail = refusal(err)
		return c
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(ctx, netguard.DefaultTimeout)
	defer cancel()
	tc := tls.Client(conn, &tls.Config{ServerName: domain, RootCAs: p.Roots, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(ctx); err != nil {
		c.Detail = tlsDetail(err, domain)
		return c
	}
	leaf := tc.ConnectionState().PeerCertificates[0]
	c.OK, c.Detail = true, "port 443 answers with a valid certificate (valid until "+leaf.NotAfter.UTC().Format(time.RFC3339)+")"
	return c
}

// Run checks that domain and its wildcard resolve to admitted addresses and
// that port 443 answers with a certificate valid for domain, in that order.
func (p *Prober) Run(ctx context.Context, domain string) []repo.DraftCheck {
	return []repo.DraftCheck{
		p.resolve(ctx, domain, CheckDNSApex, "the domain resolves"),
		p.resolve(ctx, WildcardProbe+"."+domain, CheckDNSWildcard, "names under the domain resolve (wildcard record)"),
		p.tls443(ctx, domain),
	}
}

// Limiter allows one call per Every (DefaultCheckEvery) per key.
type Limiter struct {
	Every time.Duration
	Now   func() time.Time

	mu   sync.Mutex
	last map[string]time.Time
}

// Allow reports whether key may run now, and if so records the run.
func (l *Limiter) Allow(key string) bool {
	every := l.Every
	if every <= 0 {
		every = DefaultCheckEvery
	}
	now := time.Now()
	if l.Now != nil {
		now = l.Now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == nil {
		l.last = map[string]time.Time{}
	}
	for k, t := range l.last {
		if now.Sub(t) >= every {
			delete(l.last, k)
		}
	}
	if _, busy := l.last[key]; busy {
		return false
	}
	l.last[key] = now
	return true
}

// Len is the number of keys inside their window.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.last)
}
