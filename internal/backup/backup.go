// Package backup exports and imports a tenant's Teleport-module
// configuration (FR-035, data-model "Backup export"): cluster registrations
// with their credential REFERENCE only, role mappings, alert rules,
// deployment drafts and confirmed resource links. Snapshots, alert cursors,
// deliveries, managed users and token metadata are not exported: they are
// rebuilt after a restore (watchers, pollers and the provisioning sync).
//
// Secret values never enter a document: a cluster row carries the
// credential_ref (warden:… or file:…) as stored, and the parser refuses a row
// whose reference is not a reference. Restoring therefore needs the
// referenced secrets to exist in warden (or the file store) already.
//
// Import is tenant-scoped and idempotent: rows are keyed by their exported
// id, a row that already exists is skipped (mode skip, the default) or
// rewritten (mode overwrite); a restore never deletes. The document's tenant
// must be the caller's tenant (no cross-tenant restore). A confirmed link is
// re-attached to its resource by (cluster, kind, Teleport name); when the
// watcher has not seen the resource yet a placeholder snapshot (offline, no
// offline-since) is created, and the next watch resync fills it in.
// Restored clusters start unreachable until their first health check.
package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
)

// SchemaVersion is the document version this package reads and writes.
const SchemaVersion = 1

// Restore modes.
const (
	ModeSkip      = "skip"
	ModeOverwrite = "overwrite"
)

// MaxRows bounds every collection of a document (a parser guard).
const MaxRows = 10000

// Collection names (Result keys).
const (
	CClusters = "clusters"
	CMappings = "mappings"
	CRules    = "alert_rules"
	CDrafts   = "deployment_drafts"
	CLinks    = "links"
)

// Errors. ErrBadSchema and ErrTooLarge are validation failures (422).
var (
	ErrBadSchema = errors.New("backup: invalid backup document")
	ErrTooLarge  = errors.New("backup: document exceeds the row limit")
)

// Permissions are what export and import both require: the document holds
// the whole module configuration of the tenant.
var Permissions = []string{authz.ClustersManage, authz.ProvisioningManage, authz.AlertsManage, authz.DeploymentsManage, authz.ResourcesLink}

// Cluster is an exported registration. CredentialRef is a reference.
type Cluster struct {
	ID                  string               `json:"id"`
	DisplayName         string               `json:"display_name"`
	ProxyAddr           string               `json:"proxy_addr"`
	ClusterName         string               `json:"cluster_name,omitempty"`
	CredentialKind      string               `json:"credential_kind"`
	CredentialRef       string               `json:"credential_ref"`
	CredentialIdentity  string               `json:"credential_identity,omitempty"`
	CredentialIssuedAt  time.Time            `json:"credential_issued_at,omitzero"`
	CredentialExpiresAt time.Time            `json:"credential_expires_at,omitzero"`
	Settings            repo.ClusterSettings `json:"settings"`
	CreatedBy           string               `json:"created_by"`
	CreatedAt           time.Time            `json:"created_at"`
}

// Mapping is an exported role mapping.
type Mapping struct {
	ID            string    `json:"id"`
	ClusterID     string    `json:"cluster_id"`
	SubjectKind   string    `json:"subject_kind"`
	SubjectRef    string    `json:"subject_ref"`
	TeleportRoles []string  `json:"teleport_roles"`
	Logins        []string  `json:"logins"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
}

// Rule is an exported alert rule.
type Rule struct {
	ID             string          `json:"id"`
	ClusterID      string          `json:"cluster_id,omitempty"`
	Name           string          `json:"name"`
	ConditionKind  string          `json:"condition_kind"`
	EventTypes     []string        `json:"event_types"`
	ThresholdCount int             `json:"threshold_count"`
	WindowMinutes  int             `json:"window_minutes"`
	Recipients     repo.Recipients `json:"recipients"`
	Enabled        bool            `json:"enabled"`
	CreatedBy      string          `json:"created_by"`
	CreatedAt      time.Time       `json:"created_at"`
}

// Draft is an exported deployment draft (its check results are not kept).
type Draft struct {
	ID                  string    `json:"id"`
	Domain              string    `json:"domain"`
	CertMode            string    `json:"cert_mode"`
	ACMEEmail           string    `json:"acme_email,omitempty"`
	TeleportVersion     string    `json:"teleport_version"`
	AdminUsername       string    `json:"admin_username"`
	AdminLogins         []string  `json:"admin_logins"`
	RegisteredClusterID string    `json:"registered_cluster_id,omitempty"`
	CreatedBy           string    `json:"created_by"`
	CreatedAt           time.Time `json:"created_at"`
}

// Link is an exported confirmed link, keyed to its resource by name.
type Link struct {
	ID           string    `json:"id"`
	ClusterID    string    `json:"cluster_id"`
	Kind         string    `json:"kind"`
	TeleportName string    `json:"teleport_name"`
	Hostname     string    `json:"hostname,omitempty"`
	TargetModule string    `json:"target_module"`
	TargetID     string    `json:"target_id"`
	MatchedOn    string    `json:"matched_on,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// Backup is the export document.
type Backup struct {
	SchemaVersion int       `json:"schema_version"`
	ExportedAt    time.Time `json:"exported_at"`
	TenantID      string    `json:"tenant_id"`
	Clusters      []Cluster `json:"clusters"`
	Mappings      []Mapping `json:"mappings"`
	Rules         []Rule    `json:"alert_rules"`
	Drafts        []Draft   `json:"deployment_drafts"`
	Links         []Link    `json:"links"`
}

// Result reports what an import did.
type Result struct {
	TenantID string         `json:"tenant_id"`
	Mode     string         `json:"mode"`
	Imported map[string]int `json:"imported"`
	Skipped  map[string]int `json:"skipped"`
}

// Store is the persistence the service uses (repo.Store satisfies it).
type Store interface {
	repo.Clusters
	repo.Mappings
	repo.AlertRules
	repo.Drafts
	repo.Snapshots
	repo.Links
}

// Service exports and imports a tenant's configuration.
type Service struct {
	Repo  Store
	Authz *authz.Authorizer
	Audit audit.Recorder
	Now   func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// caller authorises the operation and returns the caller's tenant.
func (s *Service) caller(ctx context.Context, a audit.Action) (string, error) {
	for _, p := range Permissions {
		if err := s.Authz.Require(ctx, p); err != nil {
			s.record(ctx, a, err, nil)
			return "", err
		}
	}
	subj, _ := authz.FromContext(ctx)
	return subj.TenantID, nil
}

func (s *Service) record(ctx context.Context, a audit.Action, err error, details map[string]any) {
	clusters.Audit(ctx, s.Audit, a, audit.TargetBackup, "", "", err, details)
}

// Export returns the caller's tenant configuration.
func (s *Service) Export(ctx context.Context) (b Backup, err error) {
	tenant, err := s.caller(ctx, audit.BackupExport)
	if err != nil {
		return Backup{}, err
	}
	defer func() {
		s.record(ctx, audit.BackupExport, err, map[string]any{CClusters: len(b.Clusters), CMappings: len(b.Mappings),
			CRules: len(b.Rules), CDrafts: len(b.Drafts), CLinks: len(b.Links)})
	}()
	b = Backup{SchemaVersion: SchemaVersion, ExportedAt: s.now(), TenantID: tenant,
		Clusters: []Cluster{}, Mappings: []Mapping{}, Rules: []Rule{}, Drafts: []Draft{}, Links: []Link{}}
	cs, err := s.Repo.ListClusters(ctx, tenant)
	if err != nil {
		return Backup{}, err
	}
	for _, c := range cs {
		b.Clusters = append(b.Clusters, Cluster{ID: c.ID, DisplayName: c.DisplayName, ProxyAddr: c.ProxyAddr, ClusterName: c.ClusterName,
			CredentialKind: c.CredentialKind, CredentialRef: c.CredentialRef, CredentialIdentity: c.CredentialIdentity,
			CredentialIssuedAt: c.CredentialIssuedAt, CredentialExpiresAt: c.CredentialExpiresAt, Settings: c.Settings,
			CreatedBy: c.CreatedBy, CreatedAt: c.CreatedAt})
		ms, err := s.Repo.ListMappings(ctx, tenant, c.ID)
		if err != nil {
			return Backup{}, err
		}
		for _, m := range ms {
			b.Mappings = append(b.Mappings, Mapping{ID: m.ID, ClusterID: m.ClusterID, SubjectKind: m.SubjectKind, SubjectRef: m.SubjectRef,
				TeleportRoles: nonNil(m.TeleportRoles), Logins: nonNil(m.Logins), CreatedBy: m.CreatedBy, CreatedAt: m.CreatedAt})
		}
		snaps, err := s.Repo.ListSnapshots(ctx, tenant, c.ID)
		if err != nil {
			return Backup{}, err
		}
		byID := map[string]repo.ResourceSnapshot{}
		for _, sn := range snaps {
			byID[sn.ID] = sn
		}
		ls, err := s.Repo.ListClusterLinks(ctx, tenant, c.ID)
		if err != nil {
			return Backup{}, err
		}
		for _, l := range ls {
			sn, ok := byID[l.SnapshotID]
			if l.Match != repo.MatchConfirmed || !ok {
				continue
			}
			b.Links = append(b.Links, Link{ID: l.ID, ClusterID: c.ID, Kind: sn.Kind, TeleportName: sn.TeleportName, Hostname: sn.Hostname,
				TargetModule: l.TargetModule, TargetID: l.TargetID, MatchedOn: l.MatchedOn, CreatedAt: l.CreatedAt})
		}
	}
	rs, err := s.Repo.ListAlertRules(ctx, tenant)
	if err != nil {
		return Backup{}, err
	}
	for _, r := range rs {
		b.Rules = append(b.Rules, Rule{ID: r.ID, ClusterID: r.ClusterID, Name: r.Name, ConditionKind: r.ConditionKind,
			EventTypes: nonNil(r.EventTypes), ThresholdCount: r.ThresholdCount, WindowMinutes: r.WindowMinutes, Recipients: r.Recipients,
			Enabled: r.Enabled, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt})
	}
	ds, err := s.Repo.ListDrafts(ctx, tenant)
	if err != nil {
		return Backup{}, err
	}
	for _, d := range ds {
		b.Drafts = append(b.Drafts, Draft{ID: d.ID, Domain: d.Domain, CertMode: d.CertMode, ACMEEmail: d.ACMEEmail,
			TeleportVersion: d.TeleportVersion, AdminUsername: d.AdminUsername, AdminLogins: nonNil(d.AdminLogins),
			RegisteredClusterID: d.RegisteredClusterID, CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt})
	}
	return b, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return slices.Clone(s)
}

// ---- parsing and validation

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func bad(what string) error { return fmt.Errorf("%w: %s", ErrBadSchema, what) }

// text checks a bounded single-line string.
func text(s string, max int, required bool) bool {
	if required && strings.TrimSpace(s) == "" {
		return false
	}
	return len(s) <= max && strings.IndexFunc(s, unicode.IsControl) < 0
}

func texts(ss []string, max int) bool {
	if len(ss) > 64 {
		return false
	}
	for _, s := range ss {
		if !text(s, max, true) {
			return false
		}
	}
	return true
}

// Parse decodes and validates a document (unknown fields are refused).
func Parse(raw []byte) (Backup, error) {
	var b Backup
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return Backup{}, bad("not a backup document")
	}
	if dec.More() {
		return Backup{}, bad("trailing data")
	}
	return b, Validate(b)
}

// Validate checks a document's shape, references and secret hygiene.
func Validate(b Backup) error {
	if b.SchemaVersion != SchemaVersion {
		return bad("unsupported schema_version")
	}
	if !uuidRE.MatchString(b.TenantID) {
		return bad("tenant_id")
	}
	for _, n := range []int{len(b.Clusters), len(b.Mappings), len(b.Rules), len(b.Drafts), len(b.Links)} {
		if n > MaxRows {
			return ErrTooLarge
		}
	}
	ids := map[string]bool{}
	id := func(v string) bool {
		if !uuidRE.MatchString(v) || ids[v] {
			return false
		}
		ids[v] = true
		return true
	}
	cl := map[string]bool{}
	for _, c := range b.Clusters {
		if !id(c.ID) || !text(c.DisplayName, 128, true) || !text(c.ProxyAddr, 255, true) || !text(c.ClusterName, 255, false) ||
			!text(c.CredentialIdentity, 255, false) || !text(c.CreatedBy, 128, false) || c.CredentialKind != repo.CredentialIdentityFile {
			return bad("cluster row")
		}
		// Only a reference may travel: an inline secret is refused.
		if _, err := secrets.ParseRef(c.CredentialRef); err != nil || !text(c.CredentialRef, 512, true) {
			return bad("cluster credential_ref is not a secret reference")
		}
		cl[c.ID] = true
	}
	for _, m := range b.Mappings {
		if !id(m.ID) || !uuidRE.MatchString(m.ClusterID) || !text(m.SubjectRef, 128, true) || !texts(m.TeleportRoles, 128) ||
			!texts(m.Logins, 64) || !text(m.CreatedBy, 128, false) || (m.SubjectKind != repo.SubjectModuleRole && m.SubjectKind != repo.SubjectGroup) {
			return bad("mapping row")
		}
	}
	for _, r := range b.Rules {
		if !id(r.ID) || (r.ClusterID != "" && !uuidRE.MatchString(r.ClusterID)) || !text(r.Name, 128, true) ||
			!slices.Contains([]string{repo.ConditionTeleportEvent, repo.ConditionClusterUnreachable, repo.ConditionCredentialExpiring, repo.ConditionResourceOffline}, r.ConditionKind) ||
			!texts(r.EventTypes, 64) || r.ThresholdCount < 0 || r.WindowMinutes < 0 || r.WindowMinutes > 1440 ||
			!texts(r.Recipients.UserIDs, 64) || !texts(r.Recipients.ChannelIDs, 64) || !text(r.CreatedBy, 128, false) {
			return bad("alert rule row")
		}
	}
	for _, d := range b.Drafts {
		if !id(d.ID) || !text(d.Domain, 253, true) || (d.CertMode != repo.CertACME && d.CertMode != repo.CertOwn) ||
			!text(d.ACMEEmail, 254, false) || !text(d.TeleportVersion, 32, true) || !text(d.AdminUsername, 64, true) ||
			!texts(d.AdminLogins, 64) || (d.RegisteredClusterID != "" && !uuidRE.MatchString(d.RegisteredClusterID)) || !text(d.CreatedBy, 128, false) {
			return bad("deployment draft row")
		}
	}
	for _, l := range b.Links {
		if !id(l.ID) || !uuidRE.MatchString(l.ClusterID) || !slices.Contains(repo.ResourceKinds, l.Kind) || !text(l.TeleportName, 255, true) ||
			!text(l.Hostname, 255, false) || (l.TargetModule != repo.TargetInventory && l.TargetModule != repo.TargetAsset) ||
			!text(l.TargetID, 128, true) || (l.MatchedOn != "" && l.MatchedOn != repo.MatchedOnHostname && l.MatchedOn != repo.MatchedOnIP) {
			return bad("link row")
		}
	}
	return nil
}

// ---- import

type importer struct {
	s         *Service
	ctx       context.Context
	tenant    string
	overwrite bool
	known     map[string]bool // clusters of the tenant after the cluster pass
	res       Result
}

func (im *importer) imported(c string) { im.res.Imported[c]++ }
func (im *importer) skipped(c string)  { im.res.Skipped[c]++ }

// Import restores b into the caller's tenant.
func (s *Service) Import(ctx context.Context, b Backup, mode string) (res Result, err error) {
	tenant, err := s.caller(ctx, audit.BackupImport)
	if err != nil {
		return Result{}, err
	}
	if mode == "" {
		mode = ModeSkip
	}
	im := &importer{s: s, ctx: ctx, tenant: tenant, overwrite: mode == ModeOverwrite, known: map[string]bool{},
		res: Result{TenantID: tenant, Mode: mode, Imported: map[string]int{}, Skipped: map[string]int{}}}
	defer func() {
		s.record(ctx, audit.BackupImport, err, map[string]any{"mode": mode, "imported": im.res.Imported, "skipped": im.res.Skipped})
	}()
	switch {
	case mode != ModeSkip && mode != ModeOverwrite:
		return Result{}, bad("mode")
	case b.TenantID != tenant:
		return Result{}, fmt.Errorf("%w: the backup belongs to another tenant", authz.ErrForbidden)
	}
	if err := Validate(b); err != nil {
		return Result{}, err
	}
	if err := im.run(b); err != nil {
		return im.res, err
	}
	return im.res, nil
}

func (im *importer) run(b Backup) error {
	for _, c := range b.Clusters {
		if err := im.cluster(c); err != nil {
			return err
		}
	}
	cs, err := im.s.Repo.ListClusters(im.ctx, im.tenant)
	if err != nil {
		return err
	}
	for _, c := range cs {
		im.known[c.ID] = true
	}
	for _, m := range b.Mappings {
		if err := im.mapping(m); err != nil {
			return err
		}
	}
	for _, r := range b.Rules {
		if err := im.rule(r); err != nil {
			return err
		}
	}
	for _, d := range b.Drafts {
		if err := im.draft(d); err != nil {
			return err
		}
	}
	for _, l := range b.Links {
		if err := im.link(l); err != nil {
			return err
		}
	}
	return nil
}

// exists reports whether get found the row; a lookup failure other than
// not-found is returned.
func exists(err error) (bool, error) {
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, repo.ErrNotFound):
		return false, nil
	}
	return false, err
}

func (im *importer) cluster(c Cluster) error {
	now := im.s.now()
	row := repo.Cluster{ID: c.ID, TenantID: im.tenant, DisplayName: c.DisplayName, ProxyAddr: c.ProxyAddr, ClusterName: c.ClusterName,
		Edition: repo.EditionUnknown, CredentialRef: c.CredentialRef, CredentialKind: c.CredentialKind, CredentialIdentity: c.CredentialIdentity,
		CredentialIssuedAt: c.CredentialIssuedAt, CredentialExpiresAt: c.CredentialExpiresAt,
		Status: repo.StatusUnreachable, StatusReason: "Restored from a backup; waiting for the first health check.",
		MissingPermissions: []string{}, Settings: c.Settings, CreatedBy: c.CreatedBy, CreatedAt: c.CreatedAt, UpdatedAt: now}
	cur, err := im.s.Repo.GetCluster(im.ctx, im.tenant, c.ID)
	found, err := exists(err)
	if err != nil {
		return err
	}
	switch {
	case !found:
		err = im.s.Repo.CreateCluster(im.ctx, row)
	case !im.overwrite:
		im.skipped(CClusters)
		return nil
	default:
		// Keep the live health state; restore the configuration.
		cur.DisplayName, cur.ProxyAddr, cur.CredentialRef, cur.CredentialKind = row.DisplayName, row.ProxyAddr, row.CredentialRef, row.CredentialKind
		cur.CredentialIdentity, cur.CredentialIssuedAt, cur.CredentialExpiresAt = row.CredentialIdentity, row.CredentialIssuedAt, row.CredentialExpiresAt
		cur.Settings, cur.UpdatedAt = row.Settings, now
		_, err = im.s.Repo.UpdateCluster(im.ctx, cur)
	}
	if errors.Is(err, repo.ErrConflict) { // e.g. the same address registered under another id
		im.skipped(CClusters)
		return nil
	}
	if err != nil {
		return err
	}
	im.imported(CClusters)
	return nil
}

func (im *importer) mapping(m Mapping) error {
	if !im.known[m.ClusterID] {
		im.skipped(CMappings)
		return nil
	}
	now := im.s.now()
	row := repo.RoleMapping{ID: m.ID, TenantID: im.tenant, ClusterID: m.ClusterID, SubjectKind: m.SubjectKind, SubjectRef: m.SubjectRef,
		TeleportRoles: nonNil(m.TeleportRoles), Logins: nonNil(m.Logins), CreatedBy: m.CreatedBy, CreatedAt: m.CreatedAt, UpdatedAt: now}
	_, err := im.s.Repo.GetMapping(im.ctx, im.tenant, m.ID)
	return im.put(CMappings, err, func() error { return im.s.Repo.CreateMapping(im.ctx, row) },
		func() error { _, err := im.s.Repo.UpdateMapping(im.ctx, row); return err })
}

func (im *importer) rule(r Rule) error {
	if r.ClusterID != "" && !im.known[r.ClusterID] {
		im.skipped(CRules)
		return nil
	}
	now := im.s.now()
	row := repo.AlertRule{ID: r.ID, TenantID: im.tenant, ClusterID: r.ClusterID, Name: r.Name, ConditionKind: r.ConditionKind,
		EventTypes: nonNil(r.EventTypes), ThresholdCount: r.ThresholdCount, WindowMinutes: r.WindowMinutes, Recipients: r.Recipients,
		Enabled: r.Enabled, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, UpdatedAt: now}
	_, err := im.s.Repo.GetAlertRule(im.ctx, im.tenant, r.ID)
	return im.put(CRules, err, func() error { return im.s.Repo.CreateAlertRule(im.ctx, row) },
		func() error { _, err := im.s.Repo.UpdateAlertRule(im.ctx, row); return err })
}

func (im *importer) draft(d Draft) error {
	reg := d.RegisteredClusterID
	if reg != "" && !im.known[reg] {
		reg = "" // the registered cluster is not part of this tenant (any more)
	}
	now := im.s.now()
	row := repo.DeploymentDraft{ID: d.ID, TenantID: im.tenant, Domain: d.Domain, CertMode: d.CertMode, ACMEEmail: d.ACMEEmail,
		TeleportVersion: d.TeleportVersion, AdminUsername: d.AdminUsername, AdminLogins: nonNil(d.AdminLogins), Checks: []repo.DraftCheck{},
		RegisteredClusterID: reg, CreatedBy: d.CreatedBy, CreatedAt: d.CreatedAt, UpdatedAt: now}
	_, err := im.s.Repo.GetDraft(im.ctx, im.tenant, d.ID)
	return im.put(CDrafts, err, func() error { return im.s.Repo.CreateDraft(im.ctx, row) },
		func() error { _, err := im.s.Repo.UpdateDraft(im.ctx, row); return err })
}

// put creates or (in overwrite mode) updates one row after its lookup.
func (im *importer) put(collection string, lookup error, create, update func() error) error {
	found, err := exists(lookup)
	if err != nil {
		return err
	}
	switch {
	case !found:
		err = create()
	case im.overwrite:
		err = update()
	default:
		im.skipped(collection)
		return nil
	}
	if errors.Is(err, repo.ErrConflict) || errors.Is(err, repo.ErrNotFound) {
		im.skipped(collection)
		return nil
	}
	if err != nil {
		return err
	}
	im.imported(collection)
	return nil
}

func (im *importer) link(l Link) error {
	if !im.known[l.ClusterID] {
		im.skipped(CLinks)
		return nil
	}
	if _, err := im.s.Repo.GetLink(im.ctx, im.tenant, l.ID); err == nil {
		im.skipped(CLinks) // links are immutable: overwrite keeps them
		return nil
	} else if !errors.Is(err, repo.ErrNotFound) {
		return err
	}
	snaps, err := im.s.Repo.ListSnapshots(im.ctx, im.tenant, l.ClusterID)
	if err != nil {
		return err
	}
	var sn repo.ResourceSnapshot
	for _, s := range snaps {
		if s.Kind == l.Kind && s.TeleportName == l.TeleportName {
			sn = s
			break
		}
	}
	if sn.ID == "" {
		if sn, err = im.s.Repo.UpsertSnapshot(im.ctx, repo.ResourceSnapshot{TenantID: im.tenant, ClusterID: l.ClusterID, Kind: l.Kind,
			TeleportName: l.TeleportName, Hostname: l.Hostname, Labels: map[string]string{}, LastSeenAt: l.CreatedAt}); err != nil {
			return err
		}
	}
	err = im.s.Repo.CreateLink(im.ctx, repo.ResourceLink{ID: l.ID, TenantID: im.tenant, SnapshotID: sn.ID, TargetModule: l.TargetModule,
		TargetID: l.TargetID, Match: repo.MatchConfirmed, MatchedOn: l.MatchedOn, CreatedAt: l.CreatedAt})
	if errors.Is(err, repo.ErrConflict) {
		im.skipped(CLinks)
		return nil
	}
	if err != nil {
		return err
	}
	im.imported(CLinks)
	return nil
}
