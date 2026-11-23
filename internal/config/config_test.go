package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// valid returns a Config that passes both the framework and module Validate.
func valid() Config {
	c := Default()
	c.ServiceName = "teleport"
	c.TrustDomain = "example.org"
	c.Authz.Path = "/etc/teleport/policy.yaml"
	c.DB.DSN = "postgres://localhost/teleport"
	c.Valkey.Addresses = []string{"valkey:6379"}
	c.Gateway.Issuer = "https://gw.example.org"
	return c
}

func TestDefaultSecure(t *testing.T) {
	d := Default()
	if d.Valkey.AllowPlaintext || !d.Events.Enabled || len(d.Teleport.AllowedPrivateNetworks) != 0 || d.Secrets.AllowFile {
		t.Fatalf("insecure defaults: %+v", d)
	}
	tp := d.Teleport
	if tp.CallTimeoutSeconds != 10 || tp.MaxMessageBytes != 4<<20 || tp.MaxConcurrentPerCluster != 4 ||
		tp.CacheTTLSeconds != 15 || tp.ProbeTimeoutSeconds != 5 {
		t.Fatalf("teleport defaults: %+v", tp)
	}
	if len(tp.AllowedPorts) != 2 || tp.AllowedPorts[0] != 443 || tp.AllowedPorts[1] != 3080 {
		t.Fatalf("allowed ports: %v", tp.AllowedPorts)
	}
	th := d.Thresholds
	if th.CredentialWarnDays != 7 || th.UnreachableAfterFailures != 3 || th.OfflineMinutes != 15 || th.DeprovisionGraceDays != 7 {
		t.Fatalf("threshold defaults: %+v", th)
	}
	if d.Limits.MaxRequestBytes != 1<<20 || d.Limits.MaxUploadBytes != 64<<10 || d.Limits.MaxPageSize != 200 {
		t.Fatalf("limits defaults: %+v", d.Limits)
	}
	// Spec 003 R7/R8: the playback bounds default to their maximum.
	if r := d.Recording; r.MaxBytes != 500<<20 || r.MaxConcurrent != 8 || r.MaxPerUser != 2 {
		t.Fatalf("recording defaults: %+v", r)
	}
	if d.Secrets.WardenService != "warden" || d.Gateway.Service != "gateway" {
		t.Fatalf("peer defaults: %+v %+v", d.Secrets, d.Gateway)
	}
	if err := Default().Validate(); err == nil {
		t.Fatal("Default() must not validate without required fields")
	}
}

func TestDurations(t *testing.T) {
	c := valid()
	if c.CallTimeout() != 10*time.Second || c.CacheTTL() != 15*time.Second || c.ProbeTimeout() != 5*time.Second ||
		c.CredentialWarn() != 7*24*time.Hour || c.OfflineThreshold() != 15*time.Minute || c.DeprovisionGrace() != 7*24*time.Hour {
		t.Fatal("duration helpers")
	}
	if c.GRPCAddr() != c.Config.Server.GRPCAddr || c.HTTPAddr() != c.Config.Server.HTTPAddr || c.AdminAddr() != c.Config.Admin.Addr {
		t.Fatal("address helpers")
	}
}

func TestValidateOK(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	c := valid()
	c.Teleport.AllowedPrivateNetworks = []string{"10.0.0.0/8", "fd00:1::/64"}
	c.Teleport.AllowedPorts = []int{443}
	c.Secrets.AllowFile, c.Secrets.FileDir = true, "/var/lib/teleport/secrets"
	c.TaskScheduler.Enabled = true
	c.Events.TenantStream, c.Events.TenantDeletedType = "platform:events:system", "auth.tenant.deleted"
	c.Recording = Recording{MaxBytes: 1 << 20, MaxConcurrent: 1, MaxPerUser: 1} // lowered playback bounds
	if err := c.Validate(); err != nil {
		t.Fatalf("dev config rejected: %v", err)
	}
	c = valid()
	c.Env = "production"
	c.DB.DSN = "postgres://db/teleport?sslmode=verify-full"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid production config rejected: %v", err)
	}
}

func TestValidateRefuses(t *testing.T) {
	cases := map[string]func(*Config){
		"no dsn":            func(c *Config) { c.DB.DSN = "" },
		"prod plaintext db": func(c *Config) { c.Env = "production" },
		"no valkey":         func(c *Config) { c.Valkey.Addresses = nil },
		"prod plaintext valkey": func(c *Config) {
			c.Env = "production"
			c.DB.DSN += "?sslmode=verify-full"
			c.Valkey.AllowPlaintext = true
		},
		"no warden":     func(c *Config) { c.Secrets.WardenService = "" },
		"no gateway":    func(c *Config) { c.Gateway.Service = "" },
		"no issuer":     func(c *Config) { c.Gateway.Issuer = "" },
		"http issuer":   func(c *Config) { c.Gateway.Issuer = "http://gw" },
		"file no dir":   func(c *Config) { c.Secrets.AllowFile = true },
		"file relative": func(c *Config) { c.Secrets.AllowFile, c.Secrets.FileDir = true, "secrets" },
		"prod file": func(c *Config) {
			c.Env = "production"
			c.DB.DSN += "?sslmode=verify-full"
			c.Secrets.AllowFile, c.Secrets.FileDir = true, "/s"
		},
		"bad cidr":         func(c *Config) { c.Teleport.AllowedPrivateNetworks = []string{"10.0.0.0/33"} },
		"cidr not private": func(c *Config) { c.Teleport.AllowedPrivateNetworks = []string{"8.8.8.0/24"} },
		"cidr loopback":    func(c *Config) { c.Teleport.AllowedPrivateNetworks = []string{"127.0.0.0/8"} },
		"no ports":         func(c *Config) { c.Teleport.AllowedPorts = nil },
		"bad port":         func(c *Config) { c.Teleport.AllowedPorts = []int{0} },
		"call timeout":     func(c *Config) { c.Teleport.CallTimeoutSeconds = 0 },
		"message cap":      func(c *Config) { c.Teleport.MaxMessageBytes = 10 },
		"concurrency":      func(c *Config) { c.Teleport.MaxConcurrentPerCluster = 0 },
		"cache ttl":        func(c *Config) { c.Teleport.CacheTTLSeconds = 0 },
		"probe timeout":    func(c *Config) { c.Teleport.ProbeTimeoutSeconds = 60 },
		"warn days":        func(c *Config) { c.Thresholds.CredentialWarnDays = 0 },
		"unreachable":      func(c *Config) { c.Thresholds.UnreachableAfterFailures = 0 },
		"offline":          func(c *Config) { c.Thresholds.OfflineMinutes = 0 },
		"grace":            func(c *Config) { c.Thresholds.DeprovisionGraceDays = 400 },
		"request bytes":    func(c *Config) { c.Limits.MaxRequestBytes = 1 },
		"upload bytes":     func(c *Config) { c.Limits.MaxUploadBytes = 2 << 20 },
		"page size":        func(c *Config) { c.Limits.MaxPageSize = 0 },
		// The playback bounds can be lowered, never raised.
		"recording bytes up":     func(c *Config) { c.Recording.MaxBytes = 501 << 20 },
		"recording bytes zero":   func(c *Config) { c.Recording.MaxBytes = 0 },
		"recording concurrent":   func(c *Config) { c.Recording.MaxConcurrent = 9 },
		"recording no slots":     func(c *Config) { c.Recording.MaxConcurrent = 0 },
		"recording per user":     func(c *Config) { c.Recording.MaxPerUser = 3 },
		"recording per user > n": func(c *Config) { c.Recording.MaxConcurrent, c.Recording.MaxPerUser = 1, 2 },
		"prod insecure enroll": func(c *Config) {
			c.Env = "production"
			c.DB.DSN += "?sslmode=verify-full"
			c.MeshEnroll.Enabled, c.MeshEnroll.Insecure = true, true
		},
		"framework invalid":   func(c *Config) { c.ServiceName = "" },
		"scheduler no name":   func(c *Config) { c.TaskScheduler.Enabled, c.TaskScheduler.Service = true, "" },
		"scheduler bad name":  func(c *Config) { c.TaskScheduler.Service = "Sched uler" },
		"tenant stream":       func(c *Config) { c.Events.TenantStream = "no spaces allowed" },
		"tenant deleted type": func(c *Config) { c.Events.TenantDeletedType = "Tenant Deleted" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := valid()
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatalf("%s: accepted", name)
			}
		})
	}
}

func TestWarnings(t *testing.T) {
	if w := strings.Join(valid().Warnings(), "\n"); strings.Contains(w, "allowed_private_networks") {
		t.Fatalf("no opt-out, warned: %s", w)
	}
	c := valid()
	c.Teleport.AllowedPrivateNetworks = []string{"10.0.0.0/8"}
	c.Valkey.AllowPlaintext = true
	c.Secrets.AllowFile, c.Secrets.FileDir = true, "/s"
	c.MeshEnroll.Enabled, c.MeshEnroll.Insecure = true, true
	w := strings.Join(c.Warnings(), "\n")
	for _, want := range []string{"teleport.allowed_private_networks", "10.0.0.0/8", "valkey.allow_plaintext", "secrets.allow_file", "mesh_enroll.insecure"} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings miss %q: %s", want, w)
		}
	}
}

func TestPrivateNetworks(t *testing.T) {
	c := valid()
	c.Teleport.AllowedPrivateNetworks = []string{"10.0.0.0/8", " 192.168.0.0/16 "}
	p, err := c.PrivateNetworks()
	if err != nil || len(p) != 2 || p[1].String() != "192.168.0.0/16" {
		t.Fatalf("prefixes = %v, %v", p, err)
	}
	c.Teleport.AllowedPrivateNetworks = []string{"nope"}
	if _, err := c.PrivateNetworks(); err == nil {
		t.Fatal("bad prefix accepted")
	}
	ports := valid().Ports()
	if len(ports) != 2 || ports[0] != 443 {
		t.Fatalf("ports = %v", ports)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	body := `service_name: teleport
trust_domain: example.org
authz: { source: file, path: /etc/policy.yaml }
db: { dsn: "postgres://localhost/teleport" }
valkey: { addresses: ["valkey:6379"] }
gateway: { service: gateway, issuer: "https://gw.example.org" }
teleport: { allowed_private_networks: ["10.0.0.0/8"], call_timeout_seconds: 7 }
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Teleport.CallTimeoutSeconds != 7 || c.Teleport.MaxConcurrentPerCluster != 4 || len(c.Teleport.AllowedPrivateNetworks) != 1 {
		t.Fatalf("loaded %+v", c.Teleport)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("loaded config invalid: %v", err)
	}
	if err := os.WriteFile(p, []byte("unknown_field: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("missing file accepted")
	}
}
