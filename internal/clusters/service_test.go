package clusters_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"
	"github.com/gravitational/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

var (
	admin  = ct.As(ct.TenantA, ct.Admin)
	viewer = ct.As(ct.TenantA, ct.Viewer)
	down   = trace.ConnectionProblem(errors.New("dial tcp: connection refused"), "connection refused")
	reject = status.Error(codes.Unauthenticated, "bad certificate")
)

func register(e *ct.Env, t *testing.T, name, addr string, identity string) (clusters.View, error) {
	t.Helper()
	return e.Service.Register(admin, clusters.RegisterInput{DisplayName: name, ProxyAddr: addr, Credential: clusters.NewCredential([]byte(identity))})
}

func stored(t *testing.T, e *ct.Env, id string) repo.Cluster {
	t.Helper()
	c, err := e.Repo.GetCluster(context.Background(), ct.TenantA, id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Registration verifies the cluster first, stores the credential only as a
// secret reference and reports name, version, edition and counts.
func TestRegisterVerifiesThenSaves(t *testing.T) {
	e := ct.New(t, nil)
	raw := e.Identity(t, 30*24*time.Hour)
	v, err := register(e, t, " Production ", "Teleport.Example.com", raw)
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != repo.StatusConnected || v.DisplayName != "Production" || v.ProxyAddr != ct.ProxyAddr || v.ClusterName != ct.ClusterName ||
		v.ServerVersion != "19.0.1" || v.Edition != repo.EditionCommunity || v.CredentialKind != repo.CredentialIdentityFile ||
		v.CredentialIdentity != "tangra-mgmt" || v.CredentialExpiresAt == nil || v.LastContactAt == nil || v.WritesBlocked {
		t.Fatalf("view %+v", v)
	}
	if v.Counts != (repo.Counts{Users: 2, Roles: 3, Nodes: 1, Apps: 1}) || len(v.MissingPermissions) != 0 {
		t.Fatalf("counts %+v missing %v", v.Counts, v.MissingPermissions)
	}
	if !v.Settings.AlertsEnabled || v.Settings.OfflineThresholdMinutes != 15 {
		t.Fatalf("default settings %+v", v.Settings)
	}
	c := stored(t, e, v.ID)
	if !strings.HasPrefix(c.CredentialRef, "warden:") || c.CredentialIssuedAt.IsZero() || c.CreatedBy != ct.Admin {
		t.Fatalf("stored %+v", c)
	}
	ref, _ := secrets.ParseRef(c.CredentialRef)
	if got, err := e.Secrets.Get(context.Background(), ref); err != nil || string(got.Reveal()) != raw {
		t.Fatalf("secret not stored under the reference: %v", err)
	}
	// The view never carries the reference or the credential.
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "warden:") || strings.Contains(string(b), "credential_ref") || strings.Contains(string(b), "PRIVATE") {
		t.Fatalf("view leaks: %s", b)
	}
	if e.Dials() != 1 || len(e.Events.OfType(events.ClusterRegistered)) != 1 {
		t.Fatalf("dials %d events %+v", e.Dials(), e.Events.All())
	}
	if got := e.AuditRows(); !slices.Equal(got, []string{"teleport.cluster.register:success"}) {
		t.Fatalf("audit %v", got)
	}
}

// Nothing is saved when verification fails, and the reason is specific.
func TestRegisterSavesNothingOnFailure(t *testing.T) {
	cases := []struct {
		name   string
		addr   string
		ident  func(e *ct.Env) string
		script func(e *ct.Env)
		want   error
		dialed bool
	}{
		{name: "credential rejected", script: func(e *ct.Env) { e.Teleport.FailNext("Ping", reject) }, want: teleportapi.ErrCredentialInvalid, dialed: true},
		{name: "unreachable", script: func(e *ct.Env) { e.Teleport.FailNext("Ping", down) }, want: teleportapi.ErrUnreachable, dialed: true},
		{name: "metadata address", addr: "169.254.169.254:443", want: teleportapi.ErrBlockedTarget},
		{name: "loopback", addr: "127.0.0.1", want: teleportapi.ErrBlockedTarget},
		{name: "name resolving to metadata", addr: "metadata.example.com", want: teleportapi.ErrBlockedTarget},
		{name: "port not allowed", addr: "teleport.example.com:22", want: teleportapi.ErrBlockedTarget},
		{name: "unresolvable", addr: "nowhere.example.com", want: teleportapi.ErrUnreachable},
		{name: "bad address", addr: "https://teleport.example.com/", want: clusters.ErrInvalid},
		{name: "malformed identity", ident: func(*ct.Env) string { return "nope" }, want: teleportapi.ErrCredentialInvalid},
		{name: "store cannot write (production warden)", script: func(e *ct.Env) { e.Secrets.SetErr(secrets.ErrWriteUnsupported) },
			want: secrets.ErrWriteUnsupported, dialed: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := ct.New(t, nil)
			if c.addr == "" {
				c.addr = ct.ProxyAddr
			}
			raw := e.Identity(t, 30*24*time.Hour)
			if c.ident != nil {
				raw = c.ident(e)
			}
			if c.script != nil {
				c.script(e)
			}
			_, err := register(e, t, "prod", c.addr, raw)
			if !errors.Is(err, c.want) {
				t.Fatalf("err %v, want %v", err, c.want)
			}
			if got, _ := e.Repo.ListClusters(context.Background(), ct.TenantA); len(got) != 0 {
				t.Fatalf("saved %+v", got)
			}
			e.Secrets.SetErr(nil)
			if e.Secrets.Len() != 0 || (e.Dials() > 0) != c.dialed || len(e.Events.All()) != 0 {
				t.Fatalf("secrets %d dials %d events %d", e.Secrets.Len(), e.Dials(), len(e.Events.All()))
			}
		})
	}
}

func TestRegisterValidation(t *testing.T) {
	e := ct.New(t, nil)
	raw := e.Identity(t, 30*24*time.Hour)
	for _, in := range []clusters.RegisterInput{
		{DisplayName: "", ProxyAddr: ct.ProxyAddr},
		{DisplayName: strings.Repeat("x", 65), ProxyAddr: ct.ProxyAddr},
		{DisplayName: "bad\nname", ProxyAddr: ct.ProxyAddr},
		{DisplayName: "prod", ProxyAddr: ct.ProxyAddr, CredentialKind: "bot"},
	} {
		in.Credential = clusters.NewCredential([]byte(raw))
		var fe *clusters.FieldError
		if _, err := e.Service.Register(admin, in); !errors.As(err, &fe) || !errors.Is(err, clusters.ErrInvalid) {
			t.Errorf("%+v: %v", in, err)
		}
	}
	e.Register(t, ct.TenantA, "prod")
	if _, err := register(e, t, "prod", ct.ProxyAddr, raw); !errors.Is(err, repo.ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := e.Service.Register(viewer, clusters.RegisterInput{DisplayName: "x", ProxyAddr: ct.ProxyAddr,
		Credential: clusters.NewCredential([]byte(raw))}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer registered: %v", err)
	}
}

// The status machine of data-model.md.
func TestStatusTransitions(t *testing.T) {
	e := ct.New(t, nil)
	v := e.Register(t, ct.TenantA, "prod")
	rule := repo.AlertRule{ID: "018f3a2b-0000-7000-8000-0000000000a1", TenantID: ct.TenantA, Name: "outage",
		ConditionKind: repo.ConditionClusterUnreachable, Recipients: repo.Recipients{UserIDs: []string{"ops-1"}}, Enabled: true}
	if err := e.Repo.CreateAlertRule(context.Background(), rule); err != nil {
		t.Fatal(err)
	}

	// Two failed checks keep the status; the third marks it unreachable.
	e.Teleport.SetErr(down)
	for i := 1; i <= 3; i++ {
		e.Advance(time.Minute)
		got, err := e.Service.Check(admin, v.ID)
		if err != nil {
			t.Fatalf("check %d: %v", i, err)
		}
		want := repo.StatusConnected
		if i == 3 {
			want = repo.StatusUnreachable
		}
		if got.Status != want {
			t.Fatalf("check %d: status %s", i, got.Status)
		}
	}
	c := stored(t, e, v.ID)
	if c.StatusReason == "" || c.LastContactAt.IsZero() {
		t.Fatalf("unreachable keeps the last contact: %+v", c)
	}
	sc := e.Events.OfType(events.ClusterStatusChanged)
	if len(sc) != 1 || sc[0].Payload != (events.ClusterStatus{ClusterID: v.ID, Status: repo.StatusUnreachable}) {
		t.Fatalf("status events %+v", sc)
	}
	if n := e.Notify.OfTemplate(notify.TemplateClusterUnreachable); len(n) != 1 || n[0].To != "ops-1" || n[0].TenantID != ct.TenantA {
		t.Fatalf("outage notification %+v", n)
	}
	// Still down: no repeated notification.
	if _, err := e.Service.Check(admin, v.ID); err != nil {
		t.Fatal(err)
	}
	if len(e.Notify.OfTemplate(notify.TemplateClusterUnreachable)) != 1 {
		t.Fatal("notified twice for one outage")
	}

	// Contact restored.
	e.Teleport.SetErr(nil)
	if got, _ := e.Service.Check(admin, v.ID); got.Status != repo.StatusConnected {
		t.Fatalf("restored: %s", got.Status)
	}

	// Within 7 days of expiry: credential_expiring, an event and a notification.
	e.Advance(24 * 24 * time.Hour)
	got, _ := e.Service.Check(admin, v.ID)
	if got.Status != repo.StatusCredentialExpiring || len(e.Events.OfType(events.CredentialExpiring)) != 1 ||
		len(e.Notify.OfTemplate(notify.TemplateCredentialExpiring)) != 0 {
		t.Fatalf("expiring: %s, events %d", got.Status, len(e.Events.OfType(events.CredentialExpiring)))
	}
	// (no credential_expiring rule yet: the notification needs recipients)
	rule.ID, rule.ConditionKind = "018f3a2b-0000-7000-8000-0000000000a2", repo.ConditionCredentialExpiring
	if err := e.Repo.CreateAlertRule(context.Background(), rule); err != nil {
		t.Fatal(err)
	}
	e.Advance(5*24*time.Hour + time.Hour) // the 1-day stage
	if got, _ := e.Service.Check(admin, v.ID); got.Status != repo.StatusCredentialExpiring {
		t.Fatalf("1-day: %s", got.Status)
	}
	if len(e.Notify.OfTemplate(notify.TemplateCredentialExpiring)) != 1 || len(e.Events.OfType(events.CredentialExpiring)) != 2 {
		t.Fatalf("1-day stage: %d notifications", len(e.Notify.OfTemplate(notify.TemplateCredentialExpiring)))
	}
	// Rotation returns the cluster to connected.
	if got, err := e.Service.RotateCredential(admin, v.ID, clusters.RotateInput{
		Credential: clusters.NewCredential([]byte(e.Identity(t, 30*24*time.Hour)))}); err != nil || got.Status != repo.StatusConnected {
		t.Fatalf("rotate: %v %+v", err, got)
	}

	// Expired: credential_invalid without dialling.
	e.Advance(31 * 24 * time.Hour)
	calls := e.Teleport.Calls("Ping")
	if got, _ := e.Service.Check(admin, v.ID); got.Status != repo.StatusCredentialInvalid || e.Teleport.Calls("Ping") != calls {
		t.Fatalf("expired: %s", got.Status)
	}
}

// An authentication rejection is credential_invalid at once.
func TestCredentialRejectedIsInvalidImmediately(t *testing.T) {
	e := ct.New(t, nil)
	v := e.Register(t, ct.TenantA, "prod")
	e.Teleport.FailNext("Ping", reject)
	got, err := e.Service.Check(admin, v.ID)
	if err != nil || got.Status != repo.StatusCredentialInvalid {
		t.Fatalf("rejected: %v %s", err, got.Status)
	}
	// The pooled connection is dropped so the next check dials afresh.
	before := e.PoolDials()
	if got, _ := e.Service.Check(admin, v.ID); got.Status != repo.StatusConnected || e.PoolDials() != before+1 {
		t.Fatalf("recovered %s, pool dials %d->%d", got.Status, before, e.PoolDials())
	}
}

// The D3 probe lists the read grants the identity lacks.
func TestMissingPermissionProbe(t *testing.T) {
	e := ct.New(t, nil)
	e.Teleport.Denied = map[string]bool{teleportapi.ProbeToken: true, teleportapi.ProbeEvent: true, teleportapi.ProbeUser: true}
	v := e.Register(t, ct.TenantA, "prod")
	if !slices.Equal(v.MissingPermissions, []string{"user:read", "token:read", "event:read"}) {
		t.Fatalf("missing %v", v.MissingPermissions)
	}
	// Counts are skipped for denied kinds instead of failing the check.
	if v.Counts.Users != 0 || v.Counts.Roles != 3 || v.Status != repo.StatusConnected {
		t.Fatalf("counts %+v status %s", v.Counts, v.Status)
	}
	e.Teleport.Denied = nil
	if got, _ := e.Service.Check(admin, v.ID); len(got.MissingPermissions) != 0 || got.Counts.Users != 2 {
		t.Fatalf("after grant: %v %+v", got.MissingPermissions, got.Counts)
	}
}

// Edition and version detection (research D13): writes are blocked below N-1.
func TestEditionAndVersion(t *testing.T) {
	for _, c := range []struct {
		version string
		edition string
		status  string
		blocked bool
	}{
		{"19.0.1", teleportapi.EditionCommunity, repo.StatusConnected, false},
		{"v19.2.0", teleportapi.EditionEnterprise, repo.StatusConnected, false},
		{"18.7.3", teleportapi.EditionCommunity, repo.StatusConnected, false},
		{"17.4.0", teleportapi.EditionCommunity, repo.StatusUnsupportedVersion, true},
		{"20.0.0-alpha.1", teleportapi.EditionCommunity, repo.StatusConnected, false},
		{"garbage", teleportapi.EditionCommunity, repo.StatusConnected, false},
	} {
		e := ct.New(t, nil)
		e.Teleport.Info.ServerVersion, e.Teleport.Info.Edition = c.version, c.edition
		v := e.Register(t, ct.TenantA, "prod")
		if v.Status != c.status || v.WritesBlocked != c.blocked || v.Edition != c.edition || v.ServerVersion != c.version {
			t.Errorf("%s: %+v", c.version, v)
		}
		err := clusters.Writable(stored(t, e, v.ID))
		if c.blocked != errors.Is(err, clusters.ErrUnsupportedVersion) {
			t.Errorf("%s: writable %v", c.version, err)
		}
		if c.version == "20.0.0-alpha.1" && !strings.Contains(v.StatusReason, "newer") {
			t.Errorf("newer version not flagged: %q", v.StatusReason)
		}
		// An upgrade returns the cluster to connected.
		if c.blocked {
			e.Teleport.Info.ServerVersion = "19.0.0"
			if got, _ := e.Service.Check(admin, v.ID); got.Status != repo.StatusConnected || got.WritesBlocked {
				t.Errorf("upgrade: %+v", got)
			}
		}
	}
}

// Removal deletes the registration and its secret; Teleport is not called.
func TestRemoveDeletesSecretAndLeavesTeleport(t *testing.T) {
	e := ct.New(t, nil)
	v := e.Register(t, ct.TenantA, "prod")
	if _, err := e.Service.Check(admin, v.ID); err != nil { // opens a pooled connection
		t.Fatal(err)
	}
	calls := map[string]int{}
	for _, m := range []string{"Ping", "ListUsers", "ListRoles", "ListLocks", "ListResources", "ProbeRead"} {
		calls[m] = e.Teleport.Calls(m)
	}
	if err := e.Service.Remove(viewer, v.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer removed: %v", err)
	}
	if err := e.Service.Remove(admin, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Repo.GetCluster(context.Background(), ct.TenantA, v.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("registration kept: %v", err)
	}
	if e.Secrets.Len() != 0 || e.Pool.Len() != 0 {
		t.Fatalf("secret %d pool %d", e.Secrets.Len(), e.Pool.Len())
	}
	for m, n := range calls {
		if e.Teleport.Calls(m) != n {
			t.Errorf("Teleport %s called on removal", m)
		}
	}
	if len(e.Events.OfType(events.ClusterRemoved)) != 1 || !slices.Contains(e.AuditRows(), "teleport.cluster.remove:success") {
		t.Fatal("removal not announced or audited")
	}
	if err := e.Service.Remove(admin, v.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("second removal: %v", err)
	}
}

// A secret store outage keeps the registration so removal can be retried.
func TestRemoveKeepsRegistrationWhenSecretStoreIsDown(t *testing.T) {
	e := ct.New(t, nil)
	v := e.Register(t, ct.TenantA, "prod")
	e.Secrets.SetErr(secrets.ErrUnavailable)
	if err := e.Service.Remove(admin, v.ID); !errors.Is(err, secrets.ErrUnavailable) {
		t.Fatalf("remove: %v", err)
	}
	stored(t, e, v.ID)
}

func TestRotateCredential(t *testing.T) {
	e := ct.New(t, nil)
	v := e.Register(t, ct.TenantA, "prod")
	if _, err := e.Service.Check(admin, v.ID); err != nil {
		t.Fatal(err)
	}
	pool := e.PoolDials()
	raw := e.Identity(t, 60*24*time.Hour)
	got, err := e.Service.RotateCredential(admin, v.ID, clusters.RotateInput{Credential: clusters.NewCredential([]byte(raw))})
	if err != nil {
		t.Fatal(err)
	}
	if !got.CredentialExpiresAt.After(*v.CredentialExpiresAt) {
		t.Fatalf("expiry not updated: %v", got.CredentialExpiresAt)
	}
	ref, _ := secrets.ParseRef(stored(t, e, v.ID).CredentialRef)
	if s, _ := e.Secrets.Get(context.Background(), ref); string(s.Reveal()) != raw || e.Secrets.Len() != 1 {
		t.Fatal("new credential not stored")
	}
	if _, err := e.Service.Check(admin, v.ID); err != nil || e.PoolDials() != pool+1 {
		t.Fatalf("pooled connection not replaced: %v", err)
	}
	if len(e.Events.OfType(events.CredentialRotated)) != 1 || !slices.Contains(e.AuditRows(), "teleport.credential.rotate:success") {
		t.Fatal("rotation not announced or audited")
	}
	// An identity of another cluster, or one the cluster rejects, changes nothing.
	e.Teleport.Info.ClusterName = "other.example.com"
	if _, err := e.Service.RotateCredential(admin, v.ID, clusters.RotateInput{Credential: clusters.NewCredential([]byte(e.Identity(t, 90*24*time.Hour)))}); !errors.Is(err, clusters.ErrInvalid) {
		t.Fatalf("foreign identity: %v", err)
	}
	e.Teleport.Info.ClusterName = ct.ClusterName
	e.Teleport.FailNext("Ping", reject)
	if _, err := e.Service.RotateCredential(admin, v.ID, clusters.RotateInput{Credential: clusters.NewCredential([]byte(e.Identity(t, 90*24*time.Hour)))}); !errors.Is(err, teleportapi.ErrCredentialInvalid) {
		t.Fatalf("rejected identity: %v", err)
	}
	if s, _ := e.Secrets.Get(context.Background(), ref); string(s.Reveal()) != raw {
		t.Fatal("a refused rotation replaced the credential")
	}
	if !slices.Contains(e.AuditRows(), "teleport.credential.rotate:failure") {
		t.Fatal("refused rotation not audited")
	}
}

func TestUpdateListGetAndIsolation(t *testing.T) {
	e := ct.New(t, nil)
	a := e.Register(t, ct.TenantA, "prod")
	e.Register(t, ct.TenantA, "staging")
	b := e.Register(t, ct.TenantB, "theirs")

	name, mins, off := "production", 30, false
	got, err := e.Service.Update(admin, a.ID, clusters.UpdateInput{DisplayName: &name,
		Settings: &clusters.SettingsInput{OfflineThresholdMinutes: &mins, AlertsEnabled: &off}})
	if err != nil || got.DisplayName != "production" || got.Settings.OfflineThresholdMinutes != 30 || got.Settings.AlertsEnabled {
		t.Fatalf("update: %v %+v", err, got)
	}
	bad := 2
	if _, err := e.Service.Update(admin, a.ID, clusters.UpdateInput{Settings: &clusters.SettingsInput{OfflineThresholdMinutes: &bad}}); !errors.Is(err, clusters.ErrInvalid) {
		t.Fatalf("bad threshold: %v", err)
	}
	dup := "staging"
	if _, err := e.Service.Update(admin, a.ID, clusters.UpdateInput{DisplayName: &dup}); !errors.Is(err, repo.ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	if len(e.Events.OfType(events.ClusterUpdated)) != 1 {
		t.Fatal("update not announced")
	}

	page, err := e.Service.List(viewer, listquery.Request{Page: 1, PageSize: 25, Sort: "display_name", Order: listquery.Asc})
	if err != nil || page.Total != 2 || page.Items[0].DisplayName != "production" || page.Items[1].DisplayName != "staging" {
		t.Fatalf("list: %v %+v", err, page)
	}
	// Another tenant's cluster is not found, never forbidden.
	if _, err := e.Service.Get(viewer, b.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if _, err := e.Service.Check(admin, b.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("cross-tenant check: %v", err)
	}
	if err := e.Service.Remove(admin, b.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("cross-tenant remove: %v", err)
	}
	if _, err := e.Service.Get(ct.As(ct.TenantA, ct.Nobody), a.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("no permission: %v", err)
	}
	// Later stories reach the cluster through Client (ownership + pool).
	c, cl, err := e.Service.Client(viewer, a.ID, authz.ClustersRead)
	if err != nil || c.ID != a.ID || cl == nil {
		t.Fatalf("client: %v", err)
	}
	if _, _, err := e.Service.Client(viewer, b.ID, authz.ClustersRead); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("cross-tenant client: %v", err)
	}
}

// The credential type redacts itself everywhere and decodes from JSON.
func TestCredentialRedaction(t *testing.T) {
	var in clusters.RegisterInput
	if err := json.Unmarshal([]byte(`{"display_name":"p","proxy_addr":"x","credential":"TOP-SECRET-BYTES"}`), &in); err != nil {
		t.Fatal(err)
	}
	if string(in.Credential.Reveal()) != "TOP-SECRET-BYTES" {
		t.Fatal("credential not decoded")
	}
	b, _ := json.Marshal(in)
	for _, s := range []string{string(b), in.Credential.String()} {
		if strings.Contains(s, "TOP-SECRET") {
			t.Fatalf("credential printed: %s", s)
		}
	}
	if err := json.Unmarshal([]byte(`{"credential":42}`), &in); err == nil {
		t.Fatal("non-string credential accepted")
	}
}
