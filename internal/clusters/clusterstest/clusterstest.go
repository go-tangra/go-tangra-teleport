// Package clusterstest is the US1 test harness, reused by the later stories
// and by tests/contract and tests/security: a clusters.Service over the
// in-memory store, the secrets fake, one scriptable Teleport fake (answering
// both the verification dial and the pool), an event recorder, the audit
// writer, the notification fake, a static permission map and a settable
// clock. Imported by tests only.
package clusterstest

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi/identitytest"
	"github.com/go-tangra/go-tangra-teleport/v4/pkg/teleportmanifest"
)

// Fixed identities of the harness.
const (
	TenantA  = "11111111-1111-7111-8111-111111111111"
	TenantB  = "22222222-2222-7222-8222-222222222222"
	Admin    = "55555555-5555-7555-8555-555555555555" // every module permission
	Viewer   = "44444444-4444-7444-8444-444444444444" // the viewer module role: *:read except audit:read
	Operator = "77777777-7777-7777-8777-777777777777" // the operator module role: reads, tokens, locks, links
	Auditor  = "88888888-8888-7888-8888-888888888888" // the auditor module role: *:read (with audit:read)
	Nobody   = "66666666-6666-7666-8666-666666666666" // no permission

	// Management is the identity's Teleport user; it holds ManagerRole.
	Management  = "tangra-mgmt"
	ManagerRole = "tangra-manager"

	ProxyAddr   = "teleport.example.com:443" // resolves to a public address
	ClusterName = "prod.example.com"         // the fake's cluster and the identity's CA
)

// Env is one wired service.
type Env struct {
	Service  *clusters.Service
	Repo     *memstore.Mem
	Secrets  *secrets.Fake
	Teleport *teleportapi.Fake
	Events   *events.Recorder
	Audit    *audit.Writer
	Notify   *notify.Fake
	Pool     *teleportapi.Pool
	Perms    authz.Static

	mu    sync.Mutex
	now   time.Time
	dials atomic.Int64 // verification dials
	pools atomic.Int64 // pool dials
}

type resolver map[string]netip.Addr

func (r resolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return []netip.Addr{a}, nil
	}
	return nil, netguard.ErrResolve
}

// New wires the harness. log receives the service's records (nil discards).
func New(t testing.TB, log slog.Handler) *Env {
	t.Helper()
	if log == nil {
		log = slog.DiscardHandler
	}
	e := &Env{Repo: memstore.New(), Secrets: secrets.NewFake(), Teleport: teleportapi.NewFake(), Events: &events.Recorder{},
		Notify: notify.NewFake(), now: time.Now().UTC().Truncate(time.Second),
		Perms: authz.Static{Admin: authz.Permissions, Viewer: teleportmanifest.Grants["member"], Operator: teleportmanifest.Grants["operator"],
			Auditor: teleportmanifest.Grants["auditor"]}}
	e.Teleport.Info = teleportapi.Info{ClusterName: ClusterName, ServerVersion: "19.0.1", Edition: teleportapi.EditionCommunity}
	e.Teleport.Users = []teleportapi.User{{Name: Management, Roles: []string{ManagerRole}, Revision: "u1"},
		{Name: "alice", Roles: []string{"access"}, Logins: []string{"ubuntu"}, Revision: "u2"}}
	e.Teleport.Roles = []teleportapi.Role{{Name: "access", Preset: true, Revision: "r1"}, {Name: "editor", Preset: true, Revision: "r2"},
		{Name: ManagerRole, Revision: "r3"}}
	e.Teleport.Resources = []teleportapi.Resource{{Kind: teleportapi.KindNode, Name: "n1"}, {Kind: teleportapi.KindApp, Name: "a1"}}
	guard, err := netguard.New(netguard.Policy{}, netguard.WithResolver(resolver{
		"teleport.example.com": netip.MustParseAddr("93.184.216.34"),
		"other.example.com":    netip.MustParseAddr("93.184.216.35"),
		"metadata.example.com": netip.MustParseAddr("169.254.169.254"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	e.Audit = audit.NewWriter(e.Repo, func(err error) { t.Errorf("audit: %v", err) })
	t.Cleanup(e.Audit.Close)
	e.Pool = teleportapi.NewPool(func(ctx context.Context, k teleportapi.Key) (teleportapi.Client, error) {
		ref, err := secrets.ParseRef(k.CredentialRef)
		if err != nil {
			return nil, teleportapi.ErrCredentialInvalid
		}
		if _, err := e.Secrets.Get(ctx, ref); err != nil {
			return nil, teleportapi.ErrCredentialInvalid
		}
		e.pools.Add(1)
		return teleportapi.Limit(e.Teleport, teleportapi.Limits{}), nil
	})
	t.Cleanup(e.Pool.Close)
	e.Service = &clusters.Service{
		Repo: e.Repo, Secrets: e.Secrets, Pool: e.Pool, Guard: guard,
		Dial: func(ctx context.Context, p teleportapi.DialParams) (teleportapi.Client, error) {
			e.dials.Add(1)
			return teleportapi.Limit(e.Teleport, p.Limits), nil
		},
		Authz: &authz.Authorizer{Checker: e.Perms, Clusters: e.Repo}, Audit: e.Audit, Events: e.Events, Notify: e.Notify,
		Recipients: clusters.RuleRecipients(e.Repo), Log: slog.New(log), Now: e.Now,
	}
	return e
}

// Now is the harness clock.
func (e *Env) Now() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

// Advance moves the clock forward.
func (e *Env) Advance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.now = e.now.Add(d)
}

// Dials is the number of verification dials; PoolDials the pool dials.
func (e *Env) Dials() int64     { return e.dials.Load() }
func (e *Env) PoolDials() int64 { return e.pools.Load() }

// As returns a request context for a signed-in user of tenant.
func As(tenant, user string) context.Context {
	return authz.WithSubjects(context.Background(), authz.User(tenant, user, nil))
}

// Identity returns an identity file for the harness cluster valid for
// lifetime from now (harness clock).
func (e *Env) Identity(t testing.TB, lifetime time.Duration) string {
	t.Helper()
	nb := e.Now().Add(-time.Minute)
	return identitytest.New(t, identitytest.Options{Cluster: ClusterName, NotBefore: nb, NotAfter: nb.Add(lifetime)})
}

// Register registers a cluster as Admin of tenant with a 30-day identity.
func (e *Env) Register(t testing.TB, tenant, name string) clusters.View {
	t.Helper()
	v, err := e.Service.Register(As(tenant, Admin), clusters.RegisterInput{DisplayName: name, ProxyAddr: ProxyAddr,
		Credential: clusters.NewCredential([]byte(e.Identity(t, 30*24*time.Hour)))})
	if err != nil {
		t.Fatalf("register %s: %v", name, err)
	}
	return v
}

// AuditRows flushes the writer and returns the stored rows.
func (e *Env) AuditRows() []string {
	e.Audit.Flush(context.Background())
	var out []string
	for _, r := range e.Repo.Audit() {
		out = append(out, r.Action+":"+r.Outcome)
	}
	return out
}
