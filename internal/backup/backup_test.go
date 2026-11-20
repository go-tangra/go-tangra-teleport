package backup_test

// T117: the export carries clusters with their credential reference only,
// mappings, alert rules, deployment drafts and confirmed links (never a
// secret value, never snapshots, cursors, deliveries or managed users);
// import restores them into the caller's tenant idempotently.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/backup"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
)

var (
	ctx   = context.Background()
	admin = ct.As(ct.TenantA, ct.Admin)
)

type fixture struct {
	*ct.Env
	svc     *backup.Service
	cluster string
	snap    repo.ResourceSnapshot
}

func service(e *ct.Env) *backup.Service {
	return &backup.Service{Repo: e.Repo, Authz: &authz.Authorizer{Checker: e.Perms, Clusters: e.Repo}, Audit: e.Audit, Now: e.Now}
}

func seed(t *testing.T) *fixture {
	t.Helper()
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	e.Register(t, ct.TenantB, "other")
	now := e.Now()
	must(t, e.Repo.CreateMapping(ctx, repo.RoleMapping{ID: store.NewID(), TenantID: ct.TenantA, ClusterID: c.ID, SubjectKind: repo.SubjectModuleRole,
		SubjectRef: "operator", TeleportRoles: []string{"access"}, Logins: []string{"ubuntu"}, CreatedBy: ct.Admin, CreatedAt: now, UpdatedAt: now}))
	must(t, e.Repo.CreateAlertRule(ctx, repo.AlertRule{ID: store.NewID(), TenantID: ct.TenantA, ClusterID: c.ID, Name: "burst",
		ConditionKind: repo.ConditionTeleportEvent, EventTypes: []string{"user.login.failure"}, ThresholdCount: 3, WindowMinutes: 5,
		Recipients: repo.Recipients{UserIDs: []string{ct.Admin}}, Enabled: true, CreatedBy: ct.Admin, CreatedAt: now, UpdatedAt: now}))
	must(t, e.Repo.CreateDraft(ctx, repo.DeploymentDraft{ID: store.NewID(), TenantID: ct.TenantA, Domain: "tp.example.test", CertMode: repo.CertACME,
		ACMEEmail: "ops@example.test", TeleportVersion: "19.0.1", AdminUsername: "admin", AdminLogins: []string{"root"},
		Checks: []repo.DraftCheck{{Name: "dns_apex", OK: true, CheckedAt: now}}, RegisteredClusterID: c.ID, CreatedBy: ct.Admin, CreatedAt: now, UpdatedAt: now}))
	sn, err := e.Repo.UpsertSnapshot(ctx, repo.ResourceSnapshot{TenantID: ct.TenantA, ClusterID: c.ID, Kind: repo.KindNode, TeleportName: "web1",
		Hostname: "web1.example", Addr: "10.0.0.1:3022", Labels: map[string]string{"env": "prod"}, Online: true, LastSeenAt: now})
	must(t, err)
	sn2, err := e.Repo.UpsertSnapshot(ctx, repo.ResourceSnapshot{TenantID: ct.TenantA, ClusterID: c.ID, Kind: repo.KindNode, TeleportName: "web2",
		Labels: map[string]string{}, Online: true, LastSeenAt: now})
	must(t, err)
	must(t, e.Repo.CreateLink(ctx, repo.ResourceLink{ID: store.NewID(), TenantID: ct.TenantA, SnapshotID: sn.ID, TargetModule: repo.TargetInventory,
		TargetID: "host-1", Match: repo.MatchConfirmed, MatchedOn: repo.MatchedOnHostname, CreatedAt: now}))
	must(t, e.Repo.CreateLink(ctx, repo.ResourceLink{ID: store.NewID(), TenantID: ct.TenantA, SnapshotID: sn2.ID, TargetModule: repo.TargetAsset,
		TargetID: "asset-9", Match: repo.MatchAuto, MatchedOn: repo.MatchedOnHostname, CreatedAt: now}))
	return &fixture{Env: e, svc: service(e), cluster: c.ID, snap: sn}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestExportCarriesReferencesOnly(t *testing.T) {
	f := seed(t)
	b, err := f.svc.Export(admin)
	must(t, err)
	if b.SchemaVersion != backup.SchemaVersion || b.TenantID != ct.TenantA || len(b.Clusters) != 1 || len(b.Mappings) != 1 ||
		len(b.Rules) != 1 || len(b.Drafts) != 1 || len(b.Links) != 1 {
		t.Fatalf("export %+v", b)
	}
	if l := b.Links[0]; l.TeleportName != "web1" || l.TargetID != "host-1" || l.Kind != repo.KindNode {
		t.Fatalf("link %+v (only the confirmed link)", l)
	}
	c, _ := f.Repo.GetCluster(ctx, ct.TenantA, f.cluster)
	if b.Clusters[0].CredentialRef != c.CredentialRef || !strings.HasPrefix(c.CredentialRef, "warden:") && !strings.HasPrefix(c.CredentialRef, "file:") {
		t.Fatalf("ref %q", b.Clusters[0].CredentialRef)
	}
	raw, err := json.Marshal(b)
	must(t, err)
	ref, _ := secrets.ParseRef(c.CredentialRef)
	sec, err := f.Secrets.Get(ctx, ref)
	must(t, err)
	value := string(sec.Reveal())
	doc := string(raw)
	for _, leak := range []string{value, "PRIVATE KEY", "BEGIN CERTIFICATE", "dns_apex", "web2", "10.0.0.1"} {
		if strings.Contains(doc, strings.TrimSpace(leak)) {
			t.Errorf("export carries %.40q", leak)
		}
	}
	for _, key := range []string{"snapshots", "cursors", "deliveries", "managed_users", "join_tokens", "status"} {
		if strings.Contains(doc, `"`+key+`"`) {
			t.Errorf("export carries %s", key)
		}
	}
	// Parse accepts its own output.
	if _, err := backup.Parse(raw); err != nil {
		t.Fatal(err)
	}
	rows := f.AuditRows()
	if len(rows) == 0 || rows[len(rows)-1] != "teleport.backup.export:success" {
		t.Fatalf("audit %v", rows)
	}
}

func TestImportRestoresIdempotently(t *testing.T) {
	f := seed(t)
	b, err := f.svc.Export(admin)
	must(t, err)
	g := ct.New(t, nil) // an empty installation of the same tenant
	svc := service(g)
	res, err := svc.Import(admin, b, "")
	must(t, err)
	for _, c := range []string{backup.CClusters, backup.CMappings, backup.CRules, backup.CDrafts, backup.CLinks} {
		if res.Imported[c] != 1 {
			t.Errorf("%s imported %d", c, res.Imported[c])
		}
	}
	c, err := g.Repo.GetCluster(ctx, ct.TenantA, f.cluster)
	must(t, err)
	if c.Status != repo.StatusUnreachable || c.CredentialRef != b.Clusters[0].CredentialRef || c.DisplayName != "prod" {
		t.Fatalf("restored cluster %+v", c)
	}
	ls, _ := g.Repo.ListClusterLinks(ctx, ct.TenantA, f.cluster)
	if len(ls) != 1 || ls[0].Match != repo.MatchConfirmed {
		t.Fatalf("links %+v", ls)
	}
	snaps, _ := g.Repo.ListSnapshots(ctx, ct.TenantA, f.cluster)
	if len(snaps) != 1 || snaps[0].Online || !snaps[0].OfflineSince.IsZero() {
		t.Fatalf("placeholder snapshot %+v", snaps)
	}
	ds, _ := g.Repo.ListDrafts(ctx, ct.TenantA)
	if len(ds) != 1 || ds[0].RegisteredClusterID != f.cluster || len(ds[0].Checks) != 0 {
		t.Fatalf("drafts %+v", ds)
	}
	// Again: nothing new.
	res, err = svc.Import(admin, b, backup.ModeSkip)
	must(t, err)
	if len(res.Imported) != 0 || res.Skipped[backup.CClusters] != 1 || res.Skipped[backup.CLinks] != 1 {
		t.Fatalf("second import %+v", res)
	}
	// Overwrite rewrites the configuration but keeps the live health state.
	c.Status, c.StatusReason = repo.StatusConnected, ""
	_, err = g.Repo.UpdateCluster(ctx, c)
	must(t, err)
	b.Clusters[0].DisplayName = "prod-renamed"
	b.Rules[0].Name = "burst-2"
	res, err = svc.Import(admin, b, backup.ModeOverwrite)
	must(t, err)
	if res.Imported[backup.CClusters] != 1 || res.Imported[backup.CRules] != 1 || res.Skipped[backup.CLinks] != 1 {
		t.Fatalf("overwrite %+v", res)
	}
	c, _ = g.Repo.GetCluster(ctx, ct.TenantA, f.cluster)
	if c.DisplayName != "prod-renamed" || c.Status != repo.StatusConnected {
		t.Fatalf("overwritten cluster %+v", c)
	}
}

// A link to a resource the watcher already knows reuses its snapshot; rows
// referring to a cluster the document and the tenant do not have are skipped.
func TestImportReattachesAndSkipsOrphans(t *testing.T) {
	f := seed(t)
	b, err := f.svc.Export(admin)
	must(t, err)
	g := ct.New(t, nil)
	svc := service(g)
	clusterRow := b.Clusters
	b.Clusters = nil
	res, err := svc.Import(admin, b, "")
	must(t, err)
	if len(res.Imported) != 1 || res.Imported[backup.CDrafts] != 1 || res.Skipped[backup.CMappings] != 1 || res.Skipped[backup.CLinks] != 1 || res.Skipped[backup.CRules] != 1 {
		t.Fatalf("orphans %+v", res)
	}
	if ds, _ := g.Repo.ListDrafts(ctx, ct.TenantA); len(ds) != 1 || ds[0].RegisteredClusterID != "" {
		t.Fatalf("draft %+v", ds)
	}
	b.Clusters = clusterRow
	_, err = svc.Import(admin, backup.Backup{SchemaVersion: 1, TenantID: ct.TenantA, Clusters: clusterRow}, "")
	must(t, err)
	live, err := g.Repo.UpsertSnapshot(ctx, repo.ResourceSnapshot{TenantID: ct.TenantA, ClusterID: f.cluster, Kind: repo.KindNode, TeleportName: "web1",
		Labels: map[string]string{}, Online: true, LastSeenAt: g.Now()})
	must(t, err)
	res, err = svc.Import(admin, b, "")
	must(t, err)
	if res.Imported[backup.CLinks] != 1 {
		t.Fatalf("relink %+v", res)
	}
	ls, _ := g.Repo.ListLinks(ctx, ct.TenantA, live.ID)
	if len(ls) != 1 {
		t.Fatalf("link not on the live snapshot: %+v", ls)
	}
	if sn, _ := g.Repo.GetSnapshot(ctx, ct.TenantA, live.ID); !sn.Online {
		t.Fatal("the live snapshot was overwritten")
	}
}

func TestImportRefusals(t *testing.T) {
	f := seed(t)
	b, err := f.svc.Export(admin)
	must(t, err)
	if _, err := f.svc.Export(ct.As(ct.TenantA, ct.Viewer)); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer export: %v", err)
	}
	if _, err := f.svc.Import(ct.As(ct.TenantA, ct.Operator), b, ""); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("operator import: %v", err)
	}
	if _, err := f.svc.Export(ctx); err == nil {
		t.Fatal("anonymous export")
	}
	// Another tenant's document is refused (no cross-tenant restore).
	if _, err := f.svc.Import(ct.As(ct.TenantB, ct.Admin), b, ""); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("cross-tenant: %v", err)
	}
	if _, err := f.svc.Import(admin, b, "merge"); !errors.Is(err, backup.ErrBadSchema) {
		t.Fatalf("mode: %v", err)
	}
	inline := b
	inline.Clusters = append([]backup.Cluster(nil), b.Clusters...)
	inline.Clusters[0].CredentialRef = "-----BEGIN RSA PRIVATE KEY-----"
	if _, err := f.svc.Import(admin, inline, ""); !errors.Is(err, backup.ErrBadSchema) {
		t.Fatalf("inline secret: %v", err)
	}
	// Store failures are returned.
	f.Repo.FailNext("GetCluster")
	if _, err := f.svc.Import(admin, b, ""); err == nil {
		t.Fatal("store failure swallowed")
	}
	f.Repo.FailNext("ListClusters")
	if _, err := f.svc.Export(admin); err == nil {
		t.Fatal("store failure swallowed")
	}
	for _, m := range []string{"ListMappings", "ListSnapshots", "ListClusterLinks", "ListAlertRules", "ListDrafts"} {
		f.Repo.FailNext(m)
		if _, err := f.svc.Export(admin); err == nil {
			t.Errorf("%s failure swallowed", m)
		}
	}
	for _, m := range []string{"GetMapping", "GetAlertRule", "GetDraft", "GetLink", "ListSnapshots", "CreateCluster"} {
		g := ct.New(t, nil)
		g.Repo.FailNext(m)
		if _, err := service(g).Import(admin, b, ""); err == nil {
			t.Errorf("%s failure swallowed", m)
		}
	}
}

func TestParseRefusals(t *testing.T) {
	f := seed(t)
	b, err := f.svc.Export(admin)
	must(t, err)
	raw, _ := json.Marshal(b)
	if _, err := backup.Parse([]byte(`{"schema_version":1,"tenant_id":"` + ct.TenantA + `","secret":"x"}`)); !errors.Is(err, backup.ErrBadSchema) {
		t.Fatalf("unknown field: %v", err)
	}
	if _, err := backup.Parse(append(raw, []byte(` {}`)...)); !errors.Is(err, backup.ErrBadSchema) {
		t.Fatalf("trailing: %v", err)
	}
	mutate := func(fn func(*backup.Backup)) error {
		c := b
		c.Clusters = append([]backup.Cluster(nil), b.Clusters...)
		c.Mappings = append([]backup.Mapping(nil), b.Mappings...)
		c.Rules = append([]backup.Rule(nil), b.Rules...)
		c.Drafts = append([]backup.Draft(nil), b.Drafts...)
		c.Links = append([]backup.Link(nil), b.Links...)
		fn(&c)
		return backup.Validate(c)
	}
	for name, fn := range map[string]func(*backup.Backup){
		"version":       func(c *backup.Backup) { c.SchemaVersion = 2 },
		"tenant":        func(c *backup.Backup) { c.TenantID = "x" },
		"dup id":        func(c *backup.Backup) { c.Mappings[0].ID = c.Clusters[0].ID },
		"cluster kind":  func(c *backup.Backup) { c.Clusters[0].CredentialKind = "bot" },
		"cluster name":  func(c *backup.Backup) { c.Clusters[0].DisplayName = "a\nb" },
		"plain ref":     func(c *backup.Backup) { c.Clusters[0].CredentialRef = "s3cr3t" },
		"mapping kind":  func(c *backup.Backup) { c.Mappings[0].SubjectKind = "user" },
		"mapping roles": func(c *backup.Backup) { c.Mappings[0].TeleportRoles = []string{""} },
		"rule cond":     func(c *backup.Backup) { c.Rules[0].ConditionKind = "x" },
		"rule window":   func(c *backup.Backup) { c.Rules[0].WindowMinutes = 5000 },
		"draft mode":    func(c *backup.Backup) { c.Drafts[0].CertMode = "self" },
		"draft reg":     func(c *backup.Backup) { c.Drafts[0].RegisteredClusterID = "x" },
		"link kind":     func(c *backup.Backup) { c.Links[0].Kind = "printer" },
		"link target":   func(c *backup.Backup) { c.Links[0].TargetModule = "dns" },
		"link match":    func(c *backup.Backup) { c.Links[0].MatchedOn = "mac" },
		"too many": func(c *backup.Backup) {
			c.Links = make([]backup.Link, backup.MaxRows+1)
		},
	} {
		if err := mutate(fn); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := mutate(func(c *backup.Backup) { c.Links = make([]backup.Link, backup.MaxRows+1) }); !errors.Is(err, backup.ErrTooLarge) {
		t.Fatalf("too many: %v", err)
	}
}
