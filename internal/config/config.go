// Package config loads and validates the Teleport module configuration: the
// Freya framework config plus the module's own sections. Every value is
// explicit and typed; insecure opt-outs are named and surfaced at start
// (Constitution I/VII). The service refuses to start without a database,
// Valkey, warden or gateway configuration.
//
// Secrets never live in this file: Teleport management credentials are
// secret references (warden:<id>, or file:<path> in development) resolved at
// use time by the secrets package (research D2/D11). Private-network cluster
// addresses are refused unless teleport.allowed_private_networks lists them,
// and that opt-out logs a warning (research D12). The module's request bounds
// live under "limits_teleport", never the framework "limits".
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	fconfig "github.com/go-tangra/go-tangra/v4/config"
	"gopkg.in/yaml.v3"
)

// Config is the Teleport module configuration. The embedded framework config
// (inline) already carries service_name, trust_domain, env, identity, authz,
// limits, admin, discovery and server (grpc_addr/http_addr).
type Config struct {
	fconfig.Config `yaml:",inline"`

	DB         DB         `yaml:"db"`
	Valkey     Valkey     `yaml:"valkey"`
	Secrets    Secrets    `yaml:"secrets"`
	Events     Events     `yaml:"events"`
	Gateway    Gateway    `yaml:"gateway"`
	MeshEnroll MeshEnroll `yaml:"mesh_enroll"`
	Teleport   Teleport   `yaml:"teleport"`
	Thresholds Thresholds `yaml:"thresholds"`
	Limits     Limits     `yaml:"limits_teleport"`
	// TaskScheduler configures the scheduler integration. The TaskExecutor
	// service is always served (the mesh policy admits only the scheduler);
	// Enabled only controls registering the task types.
	TaskScheduler TaskScheduler `yaml:"task_scheduler"`
}

// TaskScheduler configures the scheduler module integration (T116).
type TaskScheduler struct {
	Enabled bool   `yaml:"enabled"`
	Service string `yaml:"service"`
}

// DB configures the PostgreSQL/TimescaleDB store.
type DB struct {
	DSN        string `yaml:"dsn"`
	MigrateDSN string `yaml:"migrate_dsn"`
	MaxConns   int32  `yaml:"max_conns"`
}

// Valkey configures the platform event bus, the watcher leases and the read
// cache.
type Valkey struct {
	Addresses      []string `yaml:"addresses"`
	Username       string   `yaml:"username"`
	Password       string   `yaml:"password"`
	AllowPlaintext bool     `yaml:"allow_plaintext"`
	CAFile         string   `yaml:"ca_file"`
}

// Secrets configures where management credentials are kept: the warden
// service on the mesh and the file holding the module's platform token used
// to call it. AllowFile (development only) keeps credentials as files under
// FileDir instead (file: references); it is refused in production.
type Secrets struct {
	WardenService string `yaml:"warden_service"`
	TokenFile     string `yaml:"token_file"`
	AllowFile     bool   `yaml:"allow_file"`
	FileDir       string `yaml:"file_dir"`
}

// Events toggles the platform event publisher. TenantStream (optional)
// names the platform-wide stream carrying tenant lifecycle events; when set,
// a TenantDeletedType event removes the tenant's registrations and
// credentials (T118). auth v4 publishes no such event yet, so it is empty by
// default.
type Events struct {
	Enabled           bool   `yaml:"enabled"`
	TenantStream      string `yaml:"tenant_stream"`
	TenantDeletedType string `yaml:"tenant_deleted_type"`
}

// Gateway names the application gateway and the platform token issuer.
type Gateway struct {
	Service string `yaml:"service"`
	Issuer  string `yaml:"issuer"`
}

// MeshEnroll configures how the service obtains its own mesh SVID by
// enrolling with lcm over the network (identity.provider=provided).
type MeshEnroll struct {
	Enabled       bool   `yaml:"enabled"`
	EnrollURL     string `yaml:"enroll_url"`
	LCMGRPCTarget string `yaml:"lcm_grpc"`
	TenantID      string `yaml:"tenant_id"`
	TokenFile     string `yaml:"token_file"`
	StateFile     string `yaml:"state_file"`
	Insecure      bool   `yaml:"insecure"`
}

// Teleport bounds every call to a managed cluster (plan Constraints, research
// D4/D12).
type Teleport struct {
	// AllowedPrivateNetworks are RFC 1918 / ULA / CGNAT prefixes cluster
	// addresses and probes may resolve to (explicit, logged opt-out).
	AllowedPrivateNetworks []string `yaml:"allowed_private_networks"`
	// AllowedPorts is the proxy/probe port allow-list (default 443, 3080).
	AllowedPorts            []int `yaml:"allowed_ports"`
	CallTimeoutSeconds      int   `yaml:"call_timeout_seconds"`
	MaxMessageBytes         int   `yaml:"max_message_bytes"`
	MaxConcurrentPerCluster int   `yaml:"max_concurrent_per_cluster"`
	CacheTTLSeconds         int   `yaml:"cache_ttl_seconds"`
	ProbeTimeoutSeconds     int   `yaml:"probe_timeout_seconds"`
}

// Thresholds drive status changes and alerts.
type Thresholds struct {
	CredentialWarnDays       int `yaml:"credential_warn_days"`
	UnreachableAfterFailures int `yaml:"unreachable_after_failures"`
	OfflineMinutes           int `yaml:"offline_minutes"`
	DeprovisionGraceDays     int `yaml:"deprovision_grace_days"`
}

// Limits bound the module's browser request shapes.
type Limits struct {
	MaxRequestBytes int64 `yaml:"max_request_bytes"`
	// MaxUploadBytes bounds identity-file and role-YAML uploads.
	MaxUploadBytes int64 `yaml:"max_upload_bytes"`
	MaxPageSize    int   `yaml:"max_page_size"`
}

// Default returns secure defaults on top of the Freya defaults.
func Default() Config {
	return Config{
		Config:        fconfig.Default(),
		DB:            DB{MaxConns: 16},
		Secrets:       Secrets{WardenService: "warden"},
		Events:        Events{Enabled: true},
		Gateway:       Gateway{Service: "gateway"},
		TaskScheduler: TaskScheduler{Service: "scheduler"},
		Teleport: Teleport{AllowedPorts: []int{443, 3080}, CallTimeoutSeconds: 10, MaxMessageBytes: 4 << 20,
			MaxConcurrentPerCluster: 4, CacheTTLSeconds: 15, ProbeTimeoutSeconds: 5},
		Thresholds: Thresholds{CredentialWarnDays: 7, UnreachableAfterFailures: 3, OfflineMinutes: 15, DeprovisionGraceDays: 7},
		Limits:     Limits{MaxRequestBytes: 1 << 20, MaxUploadBytes: 64 << 10, MaxPageSize: 200},
	}
}

// Load reads YAML over Default(); unknown fields are rejected.
func Load(path string) (Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path
	if err != nil {
		return cfg, fmt.Errorf("config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

func within[T int | int64](v, lo, hi T) bool { return v >= lo && v <= hi }

// Validate checks the Freya config and every module section. It refuses a
// missing db, valkey, warden or gateway outright and enforces the production
// TLS guards.
func (c Config) Validate() error {
	if err := c.Config.Validate(); err != nil {
		return err
	}
	for _, check := range []func() error{c.validateInfra, c.validatePeers, c.validateTeleport, c.validateLimits} {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) validateInfra() error {
	prod := c.IsProduction()
	if c.DB.DSN == "" {
		return errors.New("config: db.dsn is required")
	}
	if prod && !strings.Contains(c.DB.DSN, "sslmode=verify-full") && !strings.Contains(c.DB.DSN, "sslmode=verify-ca") {
		return errors.New("config: db.dsn must use sslmode=verify-full (or verify-ca) in production")
	}
	if len(c.Valkey.Addresses) == 0 {
		return errors.New("config: valkey.addresses is required")
	}
	if prod && c.Valkey.AllowPlaintext {
		return errors.New("config: valkey.allow_plaintext is not permitted in production")
	}
	return nil
}

func (c Config) validatePeers() error {
	prod := c.IsProduction()
	s := c.Secrets
	if strings.TrimSpace(s.WardenService) == "" {
		return errors.New("config: secrets.warden_service is required")
	}
	if s.AllowFile {
		if prod {
			return errors.New("config: secrets.allow_file is not permitted in production")
		}
		if s.FileDir == "" || !filepath.IsAbs(s.FileDir) || filepath.Clean(s.FileDir) != s.FileDir {
			return errors.New("config: secrets.file_dir must be an absolute, clean path when secrets.allow_file is set")
		}
	}
	if strings.TrimSpace(c.Gateway.Service) == "" {
		return errors.New("config: gateway.service is required")
	}
	if iu, err := url.Parse(c.Gateway.Issuer); err != nil || iu.Scheme != "https" || iu.Host == "" {
		return errors.New("config: gateway.issuer must be an https origin")
	}
	if prod && c.MeshEnroll.Enabled && c.MeshEnroll.Insecure {
		return errors.New("config: mesh_enroll.insecure is not permitted in production")
	}
	if c.TaskScheduler.Enabled && c.TaskScheduler.Service == "" {
		return errors.New("config: task_scheduler.service is required when task_scheduler.enabled")
	}
	if c.TaskScheduler.Service != "" && !serviceNameRE.MatchString(c.TaskScheduler.Service) {
		return errors.New("config: task_scheduler.service must be a discovery service name")
	}
	if e := c.Events; e.TenantStream != "" && !streamKeyRE.MatchString(e.TenantStream) {
		return errors.New("config: events.tenant_stream must be a stream key such as platform:events:system")
	}
	if e := c.Events; e.TenantDeletedType != "" && !eventTypeRE.MatchString(e.TenantDeletedType) {
		return errors.New("config: events.tenant_deleted_type must be a dotted event type")
	}
	return nil
}

var (
	serviceNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	streamKeyRE   = regexp.MustCompile(`^[a-z][a-z0-9_.-]*(:[a-z0-9_.-]+){1,4}$`)
	eventTypeRE   = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,5}$`)
)

// privateRanges are the ranges allowed_private_networks may open: RFC 1918,
// CGNAT and IPv6 ULA. Loopback, link-local and public ranges never qualify.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

func inPrivate(p netip.Prefix) bool {
	for _, r := range privateRanges {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// PrivateNetworks parses teleport.allowed_private_networks.
func (c Config) PrivateNetworks() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(c.Teleport.AllowedPrivateNetworks))
	for _, s := range c.Teleport.AllowedPrivateNetworks {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("config: teleport.allowed_private_networks: %q is not a CIDR prefix", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Ports returns the port allow-list.
func (c Config) Ports() []uint16 {
	out := make([]uint16, 0, len(c.Teleport.AllowedPorts))
	for _, p := range c.Teleport.AllowedPorts {
		out = append(out, uint16(p)) // #nosec G115 -- validated to [1, 65535]
	}
	return out
}

func (c Config) validateTeleport() error {
	t := c.Teleport
	prefixes, err := c.PrivateNetworks()
	if err != nil {
		return err
	}
	for _, p := range prefixes {
		if !inPrivate(p) {
			return fmt.Errorf("config: teleport.allowed_private_networks: %s is not inside an RFC 1918, CGNAT or ULA range", p)
		}
	}
	if len(t.AllowedPorts) == 0 || len(t.AllowedPorts) > 16 {
		return errors.New("config: teleport.allowed_ports needs 1..16 ports")
	}
	for _, p := range t.AllowedPorts {
		if !within(p, 1, 65535) {
			return errors.New("config: teleport.allowed_ports must be within [1, 65535]")
		}
	}
	if !within(t.CallTimeoutSeconds, 1, 60) {
		return errors.New("config: teleport.call_timeout_seconds must be within [1, 60]")
	}
	if !within(t.MaxMessageBytes, 64<<10, 64<<20) {
		return errors.New("config: teleport.max_message_bytes must be within [64 KiB, 64 MiB]")
	}
	if !within(t.MaxConcurrentPerCluster, 1, 64) {
		return errors.New("config: teleport.max_concurrent_per_cluster must be within [1, 64]")
	}
	if !within(t.CacheTTLSeconds, 1, 300) {
		return errors.New("config: teleport.cache_ttl_seconds must be within [1, 300]")
	}
	if !within(t.ProbeTimeoutSeconds, 1, 30) {
		return errors.New("config: teleport.probe_timeout_seconds must be within [1, 30]")
	}
	th := c.Thresholds
	if !within(th.CredentialWarnDays, 1, 90) {
		return errors.New("config: thresholds.credential_warn_days must be within [1, 90]")
	}
	if !within(th.UnreachableAfterFailures, 1, 20) {
		return errors.New("config: thresholds.unreachable_after_failures must be within [1, 20]")
	}
	if !within(th.OfflineMinutes, 1, 1440) {
		return errors.New("config: thresholds.offline_minutes must be within [1, 1440]")
	}
	if !within(th.DeprovisionGraceDays, 0, 90) {
		return errors.New("config: thresholds.deprovision_grace_days must be within [0, 90]")
	}
	return nil
}

func (c Config) validateLimits() error {
	l := c.Limits
	if !within(l.MaxRequestBytes, 1<<10, 64<<20) {
		return errors.New("config: limits_teleport.max_request_bytes must be within [1 KiB, 64 MiB]")
	}
	if !within(l.MaxUploadBytes, 1<<10, 1<<20) {
		return errors.New("config: limits_teleport.max_upload_bytes must be within [1 KiB, 1 MiB]")
	}
	if !within(l.MaxPageSize, 1, 200) {
		return errors.New("config: limits_teleport.max_page_size must be within [1, 200]")
	}
	return nil
}

// Warnings lists accepted insecure opt-outs (surfaced at start).
func (c Config) Warnings() []string {
	w := c.Config.Warnings()
	if n := c.Teleport.AllowedPrivateNetworks; len(n) > 0 {
		w = append(w, "teleport.allowed_private_networks: cluster addresses and probes may reach private networks "+
			strings.Join(n, ", ")+" (SSRF opt-out)")
	}
	if c.Valkey.AllowPlaintext {
		w = append(w, "valkey.allow_plaintext: event-bus traffic without TLS (development only)")
	}
	if c.Secrets.AllowFile {
		w = append(w, "secrets.allow_file: management credentials are kept as files under "+c.Secrets.FileDir+" (development only; use warden)")
	}
	if c.MeshEnroll.Enabled && c.MeshEnroll.Insecure {
		w = append(w, "mesh_enroll.insecure: SVID enrollment without TLS (development only)")
	}
	return w
}

// GRPCAddr is the mesh gRPC listener (framework server section).
func (c Config) GRPCAddr() string { return c.Config.Server.GRPCAddr }

// HTTPAddr is the mesh HTTP listener (framework server section).
func (c Config) HTTPAddr() string { return c.Config.Server.HTTPAddr }

// AdminAddr is the framework admin/operations listener.
func (c Config) AdminAddr() string { return c.Config.Admin.Addr }

// CallTimeout bounds one Teleport API call.
func (c Config) CallTimeout() time.Duration {
	return time.Duration(c.Teleport.CallTimeoutSeconds) * time.Second
}

// CacheTTL is the read-cache lifetime.
func (c Config) CacheTTL() time.Duration {
	return time.Duration(c.Teleport.CacheTTLSeconds) * time.Second
}

// ProbeTimeout bounds one netguard probe or dial.
func (c Config) ProbeTimeout() time.Duration {
	return time.Duration(c.Teleport.ProbeTimeoutSeconds) * time.Second
}

// CredentialWarn is how long before expiry a credential is reported expiring.
func (c Config) CredentialWarn() time.Duration {
	return time.Duration(c.Thresholds.CredentialWarnDays) * 24 * time.Hour
}

// OfflineThreshold is how long a resource may be offline before it is flagged.
func (c Config) OfflineThreshold() time.Duration {
	return time.Duration(c.Thresholds.OfflineMinutes) * time.Minute
}

// DeprovisionGrace is how long a de-provisioned user stays locked before
// deletion.
func (c Config) DeprovisionGrace() time.Duration {
	return time.Duration(c.Thresholds.DeprovisionGraceDays) * 24 * time.Hour
}
