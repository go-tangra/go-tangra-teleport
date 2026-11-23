// Package app wires the Teleport service: configuration -> Freya runtime
// (mesh identity, admin listener) -> store/audit -> peers (auth verifier and
// permission checker, warden-backed secret store) -> events/stream, the
// Valkey read cache and worker leases -> metrics -> the netguard-pinned
// Teleport connection pool -> the mesh HTTP surface (reached only through the
// gateway), plus gateway registration and permission seeding. Adapted from
// dns-v4 internal/app.
//
// Domain services and background workers are added by the user-story phases
// (US1 clusters + health monitor, US2 users/roles/locks/tokens, US3
// resources + links, US4 audit/sessions/alerts, US5 provisioning, US6
// deployments) in buildDomain, through httpapi.Deps, AddWorker and
// AddLeasedWorker. Phase 9 adds the scheduler task executor and registrar
// (scheduler.go) and the optional tenant-lifecycle consumer.
//
// Teleport credentials are never held here: the pool's dialer resolves a
// cluster's credential reference through the secret store on every dial and
// hands the identity straight to teleportapi.Dial.
package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/valkey-io/valkey-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra-lcm/sdk/v4/pkg/lcmidentity"
	"github.com/go-tangra/go-tangra/v4"
	"github.com/go-tangra/go-tangra/v4/helpdocs"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	inventoryv1 "github.com/go-tangra/go-tangra-inventory/sdk/v4/api/proto/inventory/v1"
	"github.com/go-tangra/go-tangra-notification/sdk/v4/pkg/notifyclient"
	"github.com/go-tangra/go-tangra-portal/sdk/v4/pkg/gatewayclient"

	"github.com/go-tangra/go-tangra-teleport/v4/docs"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/alerts"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/auditlog"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/backup"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/config"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/deploy"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/enroll"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/grpcapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/lease"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/lease/valkeylease"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/locks"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/metrics"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/provisioning"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/recording"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repodb"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/resources"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/roles"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/stream"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/stream/valkeykv"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/tasks"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi/valkeycache"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/tokens"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/users"
	"github.com/go-tangra/go-tangra-teleport/v4/pkg/teleportmanifest"
)

// Options override infrastructure (tests) and attach optional parts.
type Options struct {
	Logger   slog.Handler
	Verifier httpapi.Verifier
	Checker  authz.Checker        // API-permission checker override (default: auth Authorization/Check)
	Repo     repo.Store           // store override (tests: memstore); skips the DB
	Secrets  secrets.Store        // credential store override (tests: secrets.NewFake())
	Stream   stream.Client        // event-bus client override (tests: stream.NewMemory())
	Cache    teleportapi.CacheKV  // read-cache override (tests: teleportapi.NewMemoryKV())
	Lease    lease.KV             // worker-lease override (tests: lease.NewMemory())
	Dial     teleportapi.DialFunc // whole pool dial override (tests: return a teleportapi.Fake)
	Notify   notify.Notifier      // notification override (tests: notify.NewFake())
	// Inventory overrides the inventory TeleportJoinDeliveryService dial
	// (spec 002; tests: a fake).
	Inventory enroll.Inventory
	Freya     []freya.Option
	Migrate   bool
	Remote    fs.FS // built federated UI remote (nil serves no remote)

	// dialer replaces teleportapi.Dial under the default pool dial and the
	// clusters verification dial (tests).
	dialer func(context.Context, teleportapi.DialParams) (teleportapi.Client, error)
}

// Worker is a background loop started by Run and stopped by ctx cancellation.
type Worker struct {
	Name string
	Run  func(ctx context.Context)
}

// App is the wired service.
type App struct {
	Cfg         config.Config
	Log         *slog.Logger
	Freya       *freya.App
	Store       *store.Store
	Repo        repo.Store
	Audit       *audit.Writer
	Verifier    httpapi.Verifier
	Checker     authz.Checker
	Authz       *authz.Authorizer // permission + cluster-ownership checks for the domain services
	Secrets     secrets.Store
	Events      events.Publisher
	Metrics     *metrics.Metrics
	Bus         stream.Client
	Hub         *stream.Hub
	Cache       *teleportapi.Cache
	Lease       lease.KV
	Guard       *netguard.Guard
	Limits      teleportapi.Limits
	Pool        *teleportapi.Pool
	Notify      notify.Notifier    // notification module (lazy mesh connection)
	Clusters    *clusters.Service  // US1
	Users       *users.Service     // US2
	Roles       *roles.Service     // US2
	Locks       *locks.Service     // US2
	Tokens      *tokens.Service    // US3
	Resources   *resources.Service // US3
	Enroll      *enroll.Service    // spec 002: inventory-agent SSH enrollment
	AuditLog    *auditlog.Service  // US4: Teleport events and sessions, module audit trail
	AlertRules  *alerts.Rules      // US4
	AlertEngine *alerts.Engine     // US4: the leased alert poller
	// Recording replays recorded SSH sessions in the portal (spec 003).
	Recording *recording.Service
	// Provisioning is US5. Auth publishes no membership events (research
	// D10), so there is no consumer: the Phase 9 scheduler tasks call
	// Provisioning.Reconcile and PurgeDeprovisioned.
	Provisioning *provisioning.Service
	Deployments  *deploy.Service // US6: wizard drafts, artifacts, netguard prerequisite checks
	// Tasks executes the scheduler task types (Phase 9, T116).
	Tasks *tasks.Runner
	// Backup exports and imports the tenant configuration (FR-035, T117;
	// references only). No route serves it yet (plan.md Phase 9 deviations).
	Backup *backup.Service
	// Alerter raises module-condition alerts (resource_offline): the alert
	// engine since US4 (US3 sent through resources.NotifyAlerter).
	Alerter resources.Alerter
	HTTP    *httpapi.Server
	// Docs is the embedded help bundle (docs/help) served to the gateway;
	// its digest is announced at registration.
	Docs *helpdocs.Bundle

	valkey  valkey.Client // shared by bus, cache and leases (nil when all are overridden)
	closers []func()
	workers []Worker
}

// Build wires the service.
func Build(ctx context.Context, cfg config.Config, o Options) (a *App, err error) {
	a = &App{Cfg: cfg}
	// The help pages ship in the binary; a bundle that does not load is a
	// broken build: refuse to start.
	if a.Docs, err = helpdocs.Load(docs.Help(), teleportmanifest.Module); err != nil {
		return nil, fmt.Errorf("teleport: help docs: %w", err)
	}
	handler := o.Logger
	if handler == nil {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	}
	a.Log = slog.New(handler)
	built := a
	defer func() { // release what was opened when wiring fails half-way
		if err != nil {
			built.Close()
		}
	}()

	if err = a.buildRuntime(ctx, cfg, handler, o.Freya); err != nil {
		return nil, err
	}
	if err = a.buildStorage(ctx, cfg, o); err != nil {
		return nil, err
	}
	if err = a.buildPeers(ctx, cfg, o); err != nil {
		return nil, err
	}
	if err = a.buildEvents(cfg, o); err != nil {
		return nil, err
	}
	if a.Metrics, err = metrics.New(a.Freya.Metrics().Meter(metrics.Scope)); err != nil {
		return nil, fmt.Errorf("metrics: %w", err)
	}
	if err = a.buildTeleport(cfg, o); err != nil {
		return nil, err
	}
	a.buildDomain(cfg, o)
	a.wireTenantLifecycle()

	// Mesh HTTP surface (reached only through the gateway).
	hopts := []httpapi.Option{httpapi.WithVerifier(a.Verifier), httpapi.WithChecker(a.Checker), httpapi.WithLogger(a.Log)}
	if o.Remote != nil {
		hopts = append(hopts, httpapi.WithRemote(o.Remote))
	}
	if a.HTTP, err = httpapi.NewHandler(a.Freya, hopts...); err != nil {
		return nil, err
	}
	a.HTTP.Register(httpapi.Deps{Health: a.health, Hub: a.Hub, Clusters: a.Clusters, Users: a.Users, Roles: a.Roles, Locks: a.Locks,
		Tokens: a.Tokens, Resources: a.Resources, Audit: a.AuditLog, Alerts: a.AlertRules, Provisioning: a.Provisioning,
		Deployments: a.Deployments, Enroll: a.Enroll, Recording: a.Recording})
	// Mesh gRPC surface (teleport.v1, SPIFFE mTLS; deploy/policy.yaml) and
	// the scheduler task executor (svc/scheduler only).
	grpcapi.Register(a.Freya.GRPC(), grpcapi.Deps{Resources: a.Resources, Enroll: a.Enroll, Audit: a.Audit})
	a.wireScheduler()
	// Help bundle for the gateway only (its verified service identity, behind
	// the Freya security chain); mounted before the catch-all, which would
	// otherwise shadow it.
	a.Freya.HTTP().Handle(helpdocs.BundlePath, helpdocs.NewHandler(a.Docs, helpdocs.AllowServices(cfg.Gateway.Service)))
	a.Freya.HTTP().HandlePrefix("/", a.HTTP.Handler())
	return a, nil
}

func (a *App) buildRuntime(ctx context.Context, cfg config.Config, handler slog.Handler, extra []freya.Option) error {
	fopts := append([]freya.Option{freya.WithLogger(handler)}, extra...)
	if cfg.MeshEnroll.Enabled {
		raw, err := os.ReadFile(cfg.MeshEnroll.TokenFile)
		if err != nil {
			return fmt.Errorf("teleport: mesh enroll token: %w", err)
		}
		prov, err := lcmidentity.NewNet(ctx, lcmidentity.NetConfig{
			EnrollURL: cfg.MeshEnroll.EnrollURL, LCMGRPCTarget: cfg.MeshEnroll.LCMGRPCTarget,
			TenantID: cfg.MeshEnroll.TenantID, TrustDomain: cfg.Config.TrustDomain, ServiceName: cfg.Config.ServiceName,
			EnrollmentToken: strings.TrimSpace(string(raw)), Insecure: cfg.MeshEnroll.Insecure, StateFile: cfg.MeshEnroll.StateFile,
		})
		if err != nil {
			return fmt.Errorf("teleport: mesh enroll: %w", err)
		}
		a.closers = append(a.closers, func() { _ = prov.Close() })
		fopts = append(fopts, freya.WithIdentityProvider(prov))
	}
	f, err := freya.New(cfg.Config, fopts...)
	if err != nil {
		return err
	}
	a.Freya = f
	a.closers = append(a.closers, f.Close)
	return nil
}

func (a *App) buildStorage(ctx context.Context, cfg config.Config, o Options) (err error) {
	a.Repo = o.Repo
	if a.Repo == nil {
		if o.Migrate {
			mdsn := cfg.DB.MigrateDSN
			if mdsn == "" {
				mdsn = cfg.DB.DSN
			}
			if err = store.Migrate(ctx, mdsn); err != nil {
				return err
			}
		}
		if a.Store, err = store.Open(ctx, cfg.DB.DSN, cfg.DB.MaxConns); err != nil {
			return err
		}
		a.closers = append(a.closers, a.Store.Close)
		a.Repo = repodb.New(a.Store)
	}
	a.Audit = audit.NewWriter(a.Repo, func(err error) { a.Log.Error("audit write failed", "err", err) })
	a.closers = append(a.closers, a.Audit.Close)
	return nil
}

// buildPeers wires what the module asks other services: the platform-token
// verifier and the permission checker (auth), and the credential store
// (warden references; file: in development). Mesh connections are dialled
// lazily where possible so the module starts while a peer is down.
func (a *App) buildPeers(ctx context.Context, cfg config.Config, o Options) error {
	a.Verifier, a.Checker = o.Verifier, o.Checker
	if a.Verifier == nil || a.Checker == nil {
		conn, err := a.Freya.Client(ctx, "auth")
		if err != nil {
			return fmt.Errorf("auth client: %w", err)
		}
		if a.Verifier == nil {
			a.Verifier = authclient.New(authclient.Config{Issuer: cfg.Gateway.Issuer},
				authclient.GRPCKeys{Client: authv1.NewKeysClient(conn)},
				authclient.GRPCRevocations{Client: authv1.NewSessionsClient(conn)})
		}
		if a.Checker == nil {
			a.Checker = authz.AuthChecker{Client: authv1.NewAuthorizationClient(conn), Module: teleportmanifest.Module}
		}
	}
	a.Authz = &authz.Authorizer{Checker: a.Checker, Clusters: a.Repo}
	a.Secrets = o.Secrets
	if a.Secrets == nil {
		var tok secrets.TokenFunc
		if cfg.Secrets.TokenFile != "" {
			tok = secrets.FileToken(cfg.Secrets.TokenFile)
		}
		r := secrets.Router{Warden: secrets.NewWarden(&lazyConn{app: a, service: cfg.Secrets.WardenService}, tok), Write: secrets.SchemeWarden}
		if cfg.Secrets.AllowFile { // development only (config.Validate refuses it in production)
			files, err := secrets.NewFileStore(cfg.Secrets.FileDir)
			if err != nil {
				return fmt.Errorf("secrets: %w", err)
			}
			r.Files, r.Write = files, secrets.SchemeFile
		}
		a.Secrets = r
	}
	return nil
}

// buildEvents wires the event bus and SSE hub, the Teleport read cache and
// the worker leases. All three share one Valkey connection unless every one
// is overridden.
func (a *App) buildEvents(cfg config.Config, o Options) error {
	if o.Stream == nil || o.Cache == nil || o.Lease == nil {
		sc := valkeykv.Config{Addresses: cfg.Valkey.Addresses, Username: cfg.Valkey.Username, Password: cfg.Valkey.Password, AllowPlaintext: cfg.Valkey.AllowPlaintext}
		if cfg.Valkey.CAFile != "" {
			pem, err := os.ReadFile(cfg.Valkey.CAFile)
			if err != nil {
				return fmt.Errorf("valkey ca: %w", err)
			}
			sc.CAPEM = pem
		}
		c, err := valkeykv.Dial(sc)
		if err != nil {
			return fmt.Errorf("event bus: %w", err)
		}
		a.valkey = c
		a.closers = append(a.closers, c.Close)
	}
	a.Bus = o.Stream
	if a.Bus == nil {
		a.Bus = valkeykv.Wrap(a.valkey)
	}
	// The SSE relay forwards only this module's events (T052).
	a.Hub = stream.NewHub(a.Bus, stream.Config{TypePrefix: "teleport."}, a.Log)
	a.closers = append(a.closers, a.Hub.Close)
	a.Events = events.HubPublisher{}
	if cfg.Events.Enabled {
		a.Events = events.HubPublisher{Hub: a.Hub}
	}
	kv := o.Cache
	if kv == nil {
		kv = valkeycache.KV{C: a.valkey}
	}
	a.Cache = &teleportapi.Cache{KV: kv, TTL: cfg.CacheTTL()}
	a.Lease = o.Lease
	if a.Lease == nil {
		a.Lease = valkeylease.KV{C: a.valkey}
	}
	return nil
}

// buildTeleport wires the SSRF guard (research D12) and the per-cluster
// connection pool with its bounds (research D13).
func (a *App) buildTeleport(cfg config.Config, o Options) error {
	private, err := cfg.PrivateNetworks()
	if err != nil {
		return err
	}
	if a.Guard, err = netguard.New(netguard.Policy{AllowedPrivate: private, AllowedPorts: cfg.Ports(), Timeout: cfg.ProbeTimeout()}); err != nil {
		return fmt.Errorf("netguard: %w", err)
	}
	a.Limits = teleportapi.Limits{CallTimeout: cfg.CallTimeout(), MaxMessageBytes: cfg.Teleport.MaxMessageBytes,
		MaxConcurrent: cfg.Teleport.MaxConcurrentPerCluster}
	dial := o.Dial
	if dial == nil {
		dialer := o.dialer
		if dialer == nil {
			dialer = teleportapi.Dial
		}
		dial = a.poolDial(dialer)
	}
	a.Pool = teleportapi.NewPool(dial)
	a.closers = append(a.closers, a.Pool.Close)
	return nil
}

// buildDomain wires the user-story services and their workers: the
// notification sender (dialled on first use, so the module runs while
// notification is down) and US1 clusters with its leased health monitor.
func (a *App) buildDomain(cfg config.Config, o Options) {
	a.Notify = o.Notify
	if a.Notify == nil {
		a.Notify = notify.NewClient(func(ctx context.Context) (grpc.ClientConnInterface, error) {
			return a.Freya.Client(ctx, notifyclient.Service)
		}, a.Log)
	}
	verify := o.dialer
	if verify == nil {
		verify = teleportapi.Dial
	}
	a.Clusters = &clusters.Service{
		Repo: a.Repo, Secrets: a.Secrets, Pool: a.Pool, Dial: verify, Guard: a.Guard, Limits: a.Limits,
		Authz: a.Authz, Audit: a.Audit, Events: a.Events, Notify: a.Notify, Recipients: clusters.RuleRecipients(a.Repo),
		Log: a.Log, WarnBefore: cfg.CredentialWarn(), UnreachableAfter: cfg.Thresholds.UnreachableAfterFailures,
		OfflineThresholdMinutes: cfg.Thresholds.OfflineMinutes,
	}
	monitor := &clusters.Monitor{Service: a.Clusters}
	a.AddLeasedWorker("health-monitor", monitor.Run)

	// US2: users, roles and locks, through the cluster gate.
	a.Users = &users.Service{Clusters: a.Clusters, Audit: a.Audit, Events: a.Events, Cache: a.Cache}
	a.Roles = &roles.Service{Clusters: a.Clusters, Audit: a.Audit, Events: a.Events, Cache: a.Cache}
	a.Locks = &locks.Service{Clusters: a.Clusters, Audit: a.Audit, Events: a.Events, Cache: a.Cache}

	// US3: join tokens, the resource inventory and its links. The
	// inventory/asset host lookup needs a cross-repo RPC that does not exist
	// yet: automatic matching reports dependency_unavailable until it does;
	// manual links work.
	a.Tokens = &tokens.Service{Clusters: a.Clusters, Repo: a.Repo, Audit: a.Audit, Events: a.Events}
	linker := &resources.Linker{Repo: a.Repo, Directory: resources.UnavailableDirectory{}, Events: a.Events}
	a.Resources = &resources.Service{Clusters: a.Clusters, Repo: a.Repo, Linker: linker, Cache: a.Cache, Audit: a.Audit, Events: a.Events}
	a.Alerter = resources.NotifyAlerter{Notify: a.Notify, Recipients: clusters.RuleRecipients(a.Repo), Log: a.Log}
	watcher := &resources.Watcher{Clusters: a.Clusters, Repo: a.Repo, Linker: linker, Cache: a.Cache, Events: a.Events, Log: a.Log}
	a.AddLeasedWorker("resource-watcher", watcher.Run)
	sweep := &resources.Sweep{Repo: a.Repo, Events: a.Events, Log: a.Log, Alerter: lateAlerter{a}}
	a.AddLeasedWorker("offline-sweep", sweep.Run)

	// Spec 002: enrolling inventory hosts as SSH nodes through their
	// inventory agent; inventory is dialled lazily (enrollment answers
	// dependency_unavailable while it is down) and a leased sweep follows
	// unfinished enrollments.
	inv := o.Inventory
	if inv == nil {
		conn := &lazyConn{app: a, service: InventoryService}
		inv = func(context.Context) (inventoryv1.TeleportJoinDeliveryServiceClient, error) {
			return inventoryv1.NewTeleportJoinDeliveryServiceClient(conn), nil
		}
	}
	a.Enroll = &enroll.Service{Clusters: a.Clusters, Repo: a.Repo, Inventory: inv, Audit: a.Audit, Events: a.Events}
	a.AddLeasedWorker("enrollment-sweep", (&enroll.Sweep{Service: a.Enroll, Log: a.Log}).Run)

	// US4: event and session search, the module audit trail, alert rules
	// and the leased alert poller. The poller also delivers the module
	// conditions of the sweep (replacing NotifyAlerter), de-duplicated in
	// alert_delivery.
	a.AuditLog = &auditlog.Service{Clusters: a.Clusters}
	a.AlertRules = &alerts.Rules{Repo: a.Repo, Authz: a.Authz, Audit: a.Audit}
	a.AlertEngine = &alerts.Engine{Clusters: a.Clusters, Repo: a.Repo, Notify: a.Notify, Audit: a.Audit, Log: a.Log}
	a.Alerter = a.AlertEngine
	a.AddLeasedWorker("alert-poller", a.AlertEngine.Run)

	// Spec 003: in-portal playback of recorded SSH sessions, read live from
	// the cluster page by page. The cursor key is per process (a restart or
	// another replica answers playback_expired); the bounds are per process.
	a.Recording = &recording.Service{Clusters: a.Clusters, Audit: a.Audit, Signer: recording.NewSigner(),
		Limiter: recording.NewLimiter(cfg.Recording.MaxConcurrent, cfg.Recording.MaxPerUser), MaxBytes: cfg.Recording.MaxBytes}

	// US5: role mappings and provisioning. The auth SDK cannot list a
	// tenant's members with their module roles, groups and login, so the
	// membership is Unavailable: syncs and provisioning answer
	// dependency_unavailable and change nothing, mappings work (NEEDS
	// CROSS-REPO, plan.md Phase 7 deviations).
	a.Provisioning = &provisioning.Service{Clusters: a.Clusters, Repo: a.Repo, Users: a.Users, Locks: a.Locks,
		Membership: provisioning.Unavailable{}, Notify: a.Notify, Audit: a.Audit, Events: a.Events, Log: a.Log,
		Grace: cfg.DeprovisionGrace()}

	// US6: the deployment wizard. Prerequisite checks go only through the
	// netguard guard (same private-network opt-out and port allow-list as
	// cluster addresses), at most once per 10 s per draft.
	a.Deployments = &deploy.Service{Repo: a.Repo, Authz: a.Authz, Prober: &deploy.Prober{Guard: a.Guard}, Audit: a.Audit}

	// Phase 9: the tenant configuration backup (credential references only).
	a.Backup = &backup.Service{Repo: a.Repo, Authz: a.Authz, Audit: a.Audit}
}

// InventoryService is the mesh name of the inventory module.
const InventoryService = "inventory"

// lateAlerter resolves App.Alerter at alert time, so a later story can
// replace it after the sweep is built.
type lateAlerter struct{ a *App }

// Alert implements resources.Alerter.
func (l lateAlerter) Alert(ctx context.Context, c repo.Cluster, condition, key string, vars map[string]string) {
	if l.a.Alerter != nil {
		l.a.Alerter.Alert(ctx, c, condition, key, vars)
	}
}

// poolDial resolves the key's credential reference at use time and dials
// through the guard. An unusable reference is credential_invalid; a secret
// store outage stays retryable. The identity lives only for the dial call.
func (a *App) poolDial(dialer func(context.Context, teleportapi.DialParams) (teleportapi.Client, error)) teleportapi.DialFunc {
	return func(ctx context.Context, k teleportapi.Key) (teleportapi.Client, error) {
		ref, err := secrets.ParseRef(k.CredentialRef)
		if err != nil {
			return nil, teleportapi.ErrCredentialInvalid
		}
		id, err := a.Secrets.Get(ctx, ref)
		switch {
		case errors.Is(err, secrets.ErrNotFound), errors.Is(err, secrets.ErrEmpty), errors.Is(err, secrets.ErrInvalidRef):
			return nil, teleportapi.ErrCredentialInvalid
		case err != nil:
			return nil, err
		}
		return dialer(ctx, teleportapi.DialParams{ProxyAddr: k.ProxyAddr, Identity: id, Guard: a.Guard, Limits: a.Limits})
	}
}

// KeyFor is the pool key of a cluster (clusters.KeyFor).
func KeyFor(c repo.Cluster) teleportapi.Key { return clusters.KeyFor(c) }

// AddWorker registers a background loop started by Run. It must be called
// before Run.
func (a *App) AddWorker(name string, run func(ctx context.Context)) {
	a.workers = append(a.workers, Worker{Name: name, Run: run})
}

// leaseRetry is how long a replica waits before trying a held lease again.
const leaseRetry = 5 * time.Second

// AddLeasedWorker registers a loop that runs on one replica at a time
// (research D7): the replica holding the "teleport:lease:<name>" lease runs
// run with a context cancelled on lease loss; the others retry.
func (a *App) AddLeasedWorker(name string, run func(ctx context.Context)) {
	key := "teleport:lease:" + name
	a.AddWorker(name, func(ctx context.Context) {
		for ctx.Err() == nil {
			if _, err := lease.Run(ctx, a.Lease, key, lease.Options{}, run); err != nil && !errors.Is(err, lease.ErrLost) {
				a.Log.Warn("worker lease", "worker", name, "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(leaseRetry):
			}
		}
	})
}

// Workers lists the registered background loops.
func (a *App) Workers() []Worker { return append([]Worker(nil), a.workers...) }

// lazyConn dials a mesh peer on first use so the module starts while it is
// down (warden). A failed dial is retried on the next call and surfaces as
// secrets.ErrUnavailable through the warden client's error mapping.
type lazyConn struct {
	app     *App
	service string
	mu      sync.Mutex
	conn    *grpc.ClientConn
}

func (l *lazyConn) get(ctx context.Context) (*grpc.ClientConn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		c, err := l.app.Freya.Client(ctx, l.service)
		if err != nil {
			return nil, status.Error(codes.Unavailable, l.service+" unavailable")
		}
		l.conn = c
	}
	return l.conn, nil
}

// Invoke implements grpc.ClientConnInterface.
func (l *lazyConn) Invoke(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	c, err := l.get(ctx)
	if err != nil {
		return err
	}
	return c.Invoke(ctx, method, args, reply, opts...)
}

// NewStream implements grpc.ClientConnInterface.
func (l *lazyConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	c, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	return c.NewStream(ctx, desc, method, opts...)
}

// health reports component reachability for /health (never an error text).
func (a *App) health() map[string]string {
	out := map[string]string{"store": "ok", "event_bus": "ok"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if a.Store != nil {
		if err := a.Store.Ping(ctx); err != nil {
			out["store"] = "unreachable"
		}
	}
	if p, ok := a.Bus.(interface{ Ping(context.Context) error }); ok {
		if err := p.Ping(ctx); err != nil {
			out["event_bus"] = "unreachable"
		}
	}
	return out
}

// Run starts the verifier, gateway registration, permission seeding, the
// background workers and the Freya runtime.
func (a *App) Run(ctx context.Context) error {
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if v, ok := a.Verifier.(*authclient.Verifier); ok {
		go func() {
			for wctx.Err() == nil {
				if err := v.Start(wctx, func(err error) { a.Log.Warn("verifier", "err", err) }); err == nil {
					return
				}
				select {
				case <-wctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
		}()
	}
	go a.register(wctx)
	for _, w := range a.workers {
		a.Log.Info("worker starting", "worker", w.Name)
		go w.Run(wctx)
	}
	go func() {
		for wctx.Err() == nil && !a.Freya.Ready() {
			time.Sleep(100 * time.Millisecond)
		}
		a.seedLoop(wctx)
	}()
	return a.Freya.Run(ctx)
}

// Close releases resources (idempotent).
func (a *App) Close() {
	for i := len(a.closers) - 1; i >= 0; i-- {
		a.closers[i]()
	}
	a.closers = nil
}

// register keeps the gateway lease for the manifest.
func (a *App) register(ctx context.Context) {
	for ctx.Err() == nil && !a.Freya.Ready() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	man, err := teleportmanifest.Manifest()
	if err != nil {
		a.Log.Error("gateway manifest", "err", err)
		return
	}
	httpEP, err := a.Freya.HTTP().Endpoint()
	if err != nil {
		a.Log.Error("gateway registration: http endpoint", "err", err)
		return
	}
	grpcEP, err := a.Freya.GRPC().Endpoint()
	if err != nil {
		a.Log.Error("gateway registration: grpc endpoint", "err", err)
		return
	}
	var client *gatewayclient.Client
	for ctx.Err() == nil && client == nil {
		conn, cerr := a.Freya.Client(ctx, a.Cfg.Gateway.Service)
		if cerr != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		client, err = gatewayclient.New(conn, gatewayclient.Options{Manifest: man, HTTPURL: "https://" + httpEP.Host, GRPCTarget: grpcEP.Host, Logger: a.Log,
			DocsDigest: a.Docs.Digest, // the gateway fetches the help bundle when it changes
			OnState: func(s gatewayclient.State) {
				a.Log.Info("gateway lease", "registered", s.Registered, "lease", s.LeaseID, "err", s.Err)
			}})
		if err != nil {
			a.Log.Error("gateway client", "err", err)
			return
		}
	}
	if client != nil {
		if err := client.Run(ctx); err != nil {
			a.Log.Error("gateway registration", "err", err)
		}
	}
}
