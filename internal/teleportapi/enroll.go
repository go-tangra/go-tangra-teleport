package teleportapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"slices"
	"time"

	tclient "github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/trace"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
)

// The calls of US3 (research D7, D9): join tokens, and the change watcher
// that keeps resource snapshots current.

// Join-token system roles (research D9), one per resource type.
const (
	RoleNode    = string(types.RoleNode)
	RoleApp     = string(types.RoleApp)
	RoleDB      = string(types.RoleDatabase)
	RoleKube    = string(types.RoleKube)
	RoleDesktop = string(types.RoleWindowsDesktop)
)

// JoinRoles lists the system roles a join token may carry.
var JoinRoles = []string{RoleNode, RoleApp, RoleDB, RoleKube, RoleDesktop}

// JoinTokenSpec is a join token to create (token join method only; the
// delegated methods are out of v1 scope).
type JoinTokenSpec struct {
	Roles   []string // JoinRoles
	Expires time.Time
}

// IssuedToken is a created join token. The name is the secret a joining
// agent presents, so it stays a secrets.Secret until the one response that
// returns it (SR-002); only TokenHash(Name) is kept.
type IssuedToken struct {
	Name    secrets.Secret
	Expires time.Time
}

// tokenBytes is the random part of a token name (64 hex characters).
const tokenBytes = 32

// newTokenName draws a fresh token name.
func newTokenName() string {
	b := make([]byte, tokenBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never fails on supported platforms
	return hex.EncodeToString(b)
}

// TokenHash is the SHA-256 of a token name: what the module stores to find
// the token again for revocation (data-model join_token.token_hash).
func TokenHash(name secrets.Secret) []byte {
	sum := sha256.Sum256(name.Reveal())
	return sum[:]
}

func hashMatches(name string, hash []byte) bool {
	sum := sha256.Sum256([]byte(name))
	return subtle.ConstantTimeCompare(sum[:], hash) == 1
}

// opaque maps err without keeping Teleport's message: token errors may quote
// the token name, which must not reach a log, an audit row or a response.
func opaque(err error) error {
	if err == nil {
		return nil
	}
	if Reason(err) != "" {
		if m, ok := err.(*mapped); ok {
			return &mapped{base: m.base, denied: m.denied}
		}
		return err
	}
	base := classify(err)
	return &mapped{base: base, denied: base == ErrRejected && trace.IsAccessDenied(err)}
}

// Watch event operations.
const (
	OpInit   = "init"   // the watch is established; the caller resynchronises
	OpPut    = "put"    // a resource was created or updated (heartbeat)
	OpDelete = "delete" // a resource was deleted (for servers: heartbeat expired)
)

// WatchKinds are the kinds the cluster watcher follows (research D7).
var WatchKinds = []string{KindNode, KindApp, KindDB, KindKube, KindDesktop, types.KindLock, types.KindUser, types.KindRole}

// ServerKinds are the heartbeat-backed resource kinds among WatchKinds.
var ServerKinds = []string{KindNode, KindApp, KindDB, KindKube, KindDesktop}

// WatchEvent is one change on a watched cluster. Resource is set for puts
// of a server kind; deletes carry the kind and name only.
type WatchEvent struct {
	Op       string
	Kind     string
	Name     string
	Resource Resource
}

// Watcher is an open watch. Events is closed when the watch ends; Error then
// says why (a mapped error, nil after Close).
type Watcher interface {
	Events() <-chan WatchEvent
	Done() <-chan struct{}
	Error() error
	Close() error
}

// resourceOf converts any enrolled resource.
func resourceOf(r types.Resource) Resource {
	out := Resource{Kind: r.GetKind(), Name: r.GetName()}
	if l, ok := r.(interface{ GetAllLabels() map[string]string }); ok {
		out.Labels = l.GetAllLabels()
	}
	if h, ok := r.(interface{ GetHostname() string }); ok {
		out.Hostname = h.GetHostname()
	}
	if a, ok := r.(interface{ GetAddr() string }); ok {
		out.Addr = a.GetAddr()
	}
	if v, ok := r.(interface{ GetTeleportVersion() string }); ok {
		out.Version = v.GetTeleportVersion()
	}
	return out
}

// ---- real

// enrollAPI is the part of *tclient.Client the US3 and US4 calls use.
type enrollAPI interface {
	CreateToken(ctx context.Context, token types.ProvisionToken) error
	ListProvisionTokens(ctx context.Context, pageSize int, pageToken string, anyRoles types.SystemRoles, botName string) ([]types.ProvisionToken, string, error)
	DeleteToken(ctx context.Context, name string) error
	GetClusterCACert(ctx context.Context) (*proto.GetClusterCACertResponse, error)
	NewWatcher(ctx context.Context, watch types.Watch) (types.Watcher, error)
	SearchEvents(ctx context.Context, fromUTC, toUTC time.Time, namespace string, eventTypes []string, limit int, order types.EventOrder, startKey string, search string) ([]apievents.AuditEvent, string, error)
	SearchSessionEvents(ctx context.Context, fromUTC time.Time, toUTC time.Time, limit int, order types.EventOrder, startKey string) ([]apievents.AuditEvent, string, error)
}

var _ enrollAPI = (*tclient.Client)(nil)

func (r *real) CreateJoinToken(ctx context.Context, s JoinTokenSpec) (IssuedToken, error) {
	if len(s.Roles) == 0 {
		return IssuedToken{}, trace.BadParameter("a join token needs a role")
	}
	roles := make(types.SystemRoles, 0, len(s.Roles))
	for _, ro := range s.Roles {
		roles = append(roles, types.SystemRole(ro))
	}
	name := newTokenName()
	tok, err := types.NewProvisionTokenFromSpec(name, s.Expires.UTC(), types.ProvisionTokenSpecV2{Roles: roles, JoinMethod: types.JoinMethodToken})
	if err != nil {
		return IssuedToken{}, opaque(err)
	}
	if err := r.e.CreateToken(ctx, tok); err != nil {
		return IssuedToken{}, opaque(err)
	}
	return IssuedToken{Name: secrets.NewSecret([]byte(name)), Expires: s.Expires.UTC()}, nil
}

// MaxCAPins bounds the pins a cluster may report (CA rotation keeps two).
const MaxCAPins = 4

// CAPinsOf computes the pins of the PEM certificates in pemCerts: the
// SHA-256 of each certificate's SubjectPublicKeyInfo, as `tctl status`
// prints and `teleport start --ca-pin` expects.
func CAPinsOf(pemCerts []byte) ([]string, error) {
	var pins []string
	for rest := pemCerts; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, trace.BadParameter("cluster CA certificate does not parse")
		}
		sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		pin := "sha256:" + hex.EncodeToString(sum[:])
		if !slices.Contains(pins, pin) {
			pins = append(pins, pin)
		}
	}
	if len(pins) == 0 || len(pins) > MaxCAPins {
		return nil, trace.BadParameter("cluster reported %d CA certificates", len(pins))
	}
	return pins, nil
}

func (r *real) CAPins(ctx context.Context) ([]string, error) {
	resp, err := r.e.GetClusterCACert(ctx)
	if err != nil {
		return nil, opaque(err)
	}
	return CAPinsOf(resp.TLSCA)
}

// maxTokenPages bounds the search for a token to revoke.
const maxTokenPages = 20

func (r *real) DeleteJoinToken(ctx context.Context, hash []byte) error {
	next := ""
	for range maxTokenPages {
		toks, nx, err := r.e.ListProvisionTokens(ctx, 500, next, nil, "")
		if err != nil {
			return opaque(err)
		}
		for _, t := range toks {
			if hashMatches(t.GetName(), hash) {
				return opaque(r.e.DeleteToken(ctx, t.GetName()))
			}
		}
		if nx == "" {
			break
		}
		next = nx
	}
	return trace.NotFound("join token not found")
}

func (r *real) Watch(ctx context.Context, kinds []string) (Watcher, error) {
	wk := make([]types.WatchKind, 0, len(kinds))
	for _, k := range kinds {
		wk = append(wk, types.WatchKind{Kind: k})
	}
	w, err := r.e.NewWatcher(ctx, types.Watch{Name: "tangra-teleport", Kinds: wk, AllowPartialSuccess: true})
	if err != nil {
		return nil, err
	}
	return adaptWatcher(w), nil
}

// realWatcher translates a teleport/api watcher.
type realWatcher struct {
	w   types.Watcher
	out chan WatchEvent
}

func adaptWatcher(w types.Watcher) *realWatcher {
	rw := &realWatcher{w: w, out: make(chan WatchEvent, 64)}
	go rw.pump()
	return rw
}

func (rw *realWatcher) pump() {
	defer close(rw.out)
	for {
		select {
		case <-rw.w.Done():
			return
		case ev, ok := <-rw.w.Events():
			if !ok {
				return
			}
			we, keep := translate(ev)
			if !keep {
				continue
			}
			select {
			case rw.out <- we:
			case <-rw.w.Done():
				return
			}
		}
	}
}

// translate converts one teleport/api event (false: not of interest).
func translate(ev types.Event) (WatchEvent, bool) {
	switch ev.Type {
	case types.OpInit:
		return WatchEvent{Op: OpInit}, true
	case types.OpPut, types.OpDelete:
		if ev.Resource == nil {
			return WatchEvent{}, false
		}
		we := WatchEvent{Op: OpPut, Kind: ev.Resource.GetKind(), Name: ev.Resource.GetName()}
		if ev.Type == types.OpDelete {
			we.Op = OpDelete
		} else {
			we.Resource = resourceOf(ev.Resource)
		}
		return we, true
	}
	return WatchEvent{}, false
}

func (rw *realWatcher) Events() <-chan WatchEvent { return rw.out }
func (rw *realWatcher) Done() <-chan struct{}     { return rw.w.Done() }
func (rw *realWatcher) Error() error              { return rw.w.Error() }
func (rw *realWatcher) Close() error              { return rw.w.Close() }

// ---- limited

func (c *limited) CreateJoinToken(ctx context.Context, s JoinTokenSpec) (IssuedToken, error) {
	v, err := call(c, ctx, func(ctx context.Context) (IssuedToken, error) { return c.inner.CreateJoinToken(ctx, s) })
	return v, opaque(err)
}

func (c *limited) DeleteJoinToken(ctx context.Context, hash []byte) error {
	return opaque(do(c, ctx, func(ctx context.Context) error { return c.inner.DeleteJoinToken(ctx, hash) }))
}

func (c *limited) CAPins(ctx context.Context) ([]string, error) {
	return call(c, ctx, c.inner.CAPins)
}

// Watch opens a watch with the caller's context: a watch is long-lived, so
// neither the per-call timeout nor a concurrency slot applies; only the
// open and the watch's final error are mapped.
func (c *limited) Watch(ctx context.Context, kinds []string) (Watcher, error) {
	w, err := c.inner.Watch(ctx, kinds)
	if err != nil {
		return nil, MapError(err)
	}
	return mappedWatcher{w}, nil
}

type mappedWatcher struct{ Watcher }

func (m mappedWatcher) Error() error { return MapError(m.Watcher.Error()) }
