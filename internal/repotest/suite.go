// Package repotest is the behavioural conformance suite of repo.Store. The
// in-memory store runs it in the unit suite; the TimescaleDB store runs it in
// the tagged integration suite, so both implementations provably agree on
// CRUD of every data-model table, tenant isolation, the unique guards and the
// cascades from cluster.
package repotest

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
)

// Fixed tenants of the suite.
const (
	TenantA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	TenantB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
)

// Factory returns a fresh, empty store for one subtest.
type Factory func(t *testing.T) repo.Store

// Run executes every conformance case against stores built by newStore.
func Run(t *testing.T, newStore Factory) {
	cases := map[string]func(*testing.T, repo.Store){
		"clusters":      testClusters,
		"join tokens":   testJoinTokens,
		"snapshots":     testSnapshots,
		"links":         testLinks,
		"mappings":      testMappings,
		"managed users": testManagedUsers,
		"alert rules":   testAlertRules,
		"alert state":   testAlertState,
		"drafts":        testDrafts,
		"enrollments":   testEnrollments,
		"access":        testAccessSettings,
		"cascade":       testCascade,
		"audit":         testAudit,
		"audit list":    testAuditList,
		"lookups":       testLookups,
	}
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fn := cases[n]
		t.Run(n, func(t *testing.T) { fn(t, newStore(t)) })
	}
}

var ctx = context.Background()

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func base() time.Time { return time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond) }

// NewCluster builds a valid cluster row.
func NewCluster(tenant, name string) repo.Cluster {
	now := base()
	return repo.Cluster{ID: store.NewID(), TenantID: tenant, DisplayName: name, ProxyAddr: "teleport.example.com:443",
		ClusterName: "teleport.example.com", Edition: repo.EditionCommunity, ServerVersion: "18.1.0",
		CredentialRef: "warden:" + store.NewID(), CredentialKind: repo.CredentialIdentityFile, CredentialIdentity: "tangra-mgmt", // #nosec G101 -- a reference and a user name
		CredentialIssuedAt: now, CredentialExpiresAt: now.Add(90 * 24 * time.Hour), Status: repo.StatusConnected, MissingPermissions: []string{},
		Settings: repo.ClusterSettings{OfflineThresholdMinutes: 15, AlertsEnabled: true}, CreatedBy: "u1", CreatedAt: now, UpdatedAt: now}
}

func testClusters(t *testing.T, s repo.Store) {
	a := NewCluster(TenantA, "prod")
	a.Counts = repo.Counts{Users: 3, Roles: 5, Nodes: 10, Apps: 1, DBs: 2, Kube: 1, Desktops: 0}
	a.MissingPermissions = []string{"event:list"}
	a.LastContactAt = base()
	must(t, s.CreateCluster(ctx, a))
	// Display names are unique per tenant only.
	dup := NewCluster(TenantA, "prod")
	wantErr(t, s.CreateCluster(ctx, dup), repo.ErrConflict)
	must(t, s.CreateCluster(ctx, NewCluster(TenantB, "prod")))

	got, err := s.GetCluster(ctx, TenantA, a.ID)
	must(t, err)
	if got.DisplayName != "prod" || got.CredentialRef != a.CredentialRef || got.Counts != a.Counts || got.Settings != a.Settings ||
		len(got.MissingPermissions) != 1 || got.CredentialIdentity != "tangra-mgmt" || !got.LastContactAt.Equal(a.LastContactAt) ||
		!got.CredentialExpiresAt.Equal(a.CredentialExpiresAt) || !got.CredentialIssuedAt.Equal(a.CredentialIssuedAt) || got.Edition != repo.EditionCommunity || got.CreatedBy != "u1" {
		t.Fatalf("get = %+v", got)
	}
	// Tenant B cannot see tenant A's cluster; a malformed id is not found.
	_, err = s.GetCluster(ctx, TenantB, a.ID)
	wantErr(t, err, repo.ErrNotFound)
	_, err = s.GetCluster(ctx, TenantA, "not-a-uuid")
	wantErr(t, err, repo.ErrNotFound)

	b := NewCluster(TenantA, "lab")
	must(t, s.CreateCluster(ctx, b))
	list, err := s.ListClusters(ctx, TenantA)
	must(t, err)
	if len(list) != 2 || list[0].DisplayName != "lab" || list[1].DisplayName != "prod" {
		t.Fatalf("list = %+v", list)
	}

	got.Status, got.StatusReason, got.DisplayName = repo.StatusUnreachable, "3 failed checks", "production"
	got.MissingPermissions = nil
	up, err := s.UpdateCluster(ctx, got)
	must(t, err)
	if up.Status != repo.StatusUnreachable || up.DisplayName != "production" || up.MissingPermissions == nil || !up.UpdatedAt.After(a.UpdatedAt) {
		t.Fatalf("update = %+v", up)
	}
	b.DisplayName = "production"
	_, err = s.UpdateCluster(ctx, b)
	wantErr(t, err, repo.ErrConflict)
	other := got
	other.TenantID = TenantB
	_, err = s.UpdateCluster(ctx, other)
	wantErr(t, err, repo.ErrNotFound)

	all, err := s.AllClusters(ctx)
	must(t, err)
	if len(all) != 3 {
		t.Fatalf("all clusters = %d", len(all))
	}
	wantErr(t, s.DeleteCluster(ctx, TenantB, a.ID), repo.ErrNotFound)
	must(t, s.DeleteCluster(ctx, TenantA, a.ID))
	wantErr(t, s.DeleteCluster(ctx, TenantA, a.ID), repo.ErrNotFound)
}

func testJoinTokens(t *testing.T, s repo.Store) {
	c := NewCluster(TenantA, "c")
	must(t, s.CreateCluster(ctx, c))
	now := base()
	tok := func(exp time.Time) repo.JoinToken {
		return repo.JoinToken{ID: store.NewID(), TenantID: TenantA, ClusterID: c.ID, TokenHash: []byte{1, 2, 3},
			ResourceType: repo.KindNode, ExpiresAt: exp, CreatedBy: "u1", CreatedAt: now}
	}
	t1, t2 := tok(now.Add(30*time.Minute)), tok(now.Add(-30*24*time.Hour))
	t2.CreatedAt = now.Add(time.Second)
	must(t, s.CreateJoinToken(ctx, t1))
	must(t, s.CreateJoinToken(ctx, t2))
	// A token for another tenant's cluster is refused.
	x := tok(now)
	x.TenantID = TenantB
	wantErr(t, s.CreateJoinToken(ctx, x), repo.ErrNotFound)

	got, err := s.GetJoinToken(ctx, TenantA, t1.ID)
	must(t, err)
	if string(got.TokenHash) != "\x01\x02\x03" || got.ResourceType != repo.KindNode || !got.RevokedAt.IsZero() {
		t.Fatalf("get = %+v", got)
	}
	_, err = s.GetJoinToken(ctx, TenantB, t1.ID)
	wantErr(t, err, repo.ErrNotFound)
	list, err := s.ListJoinTokens(ctx, TenantA, c.ID)
	must(t, err)
	if len(list) != 2 || list[0].ID != t2.ID {
		t.Fatalf("list (newest first) = %+v", list)
	}
	must(t, s.RevokeJoinToken(ctx, TenantA, t1.ID, now))
	got, _ = s.GetJoinToken(ctx, TenantA, t1.ID)
	if !got.RevokedAt.Equal(now) {
		t.Fatalf("revoked_at = %v", got.RevokedAt)
	}
	wantErr(t, s.RevokeJoinToken(ctx, TenantB, t1.ID, now), repo.ErrNotFound)
	n, err := s.PruneJoinTokens(ctx, now.Add(-7*24*time.Hour))
	must(t, err)
	if n != 1 {
		t.Fatalf("pruned %d", n)
	}
	if list, _ := s.ListJoinTokens(ctx, TenantA, c.ID); len(list) != 1 {
		t.Fatalf("after prune: %+v", list)
	}
	// The tenant-scoped prune (teleport:token-gc) touches only its tenant.
	t3 := tok(now.Add(-30 * 24 * time.Hour))
	must(t, s.CreateJoinToken(ctx, t3))
	if n, err := s.PruneTenantJoinTokens(ctx, TenantB, now.Add(-7*24*time.Hour)); err != nil || n != 0 {
		t.Fatalf("tenant B pruned %d, %v", n, err)
	}
	if n, err := s.PruneTenantJoinTokens(ctx, TenantA, now.Add(-7*24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("tenant A pruned %d, %v", n, err)
	}
	if list, _ := s.ListJoinTokens(ctx, TenantA, c.ID); len(list) != 1 || list[0].ID != t1.ID {
		t.Fatalf("after tenant prune: %+v", list)
	}
}

// NewSnapshot builds a valid snapshot row.
func NewSnapshot(tenant, clusterID, name string) repo.ResourceSnapshot {
	return repo.ResourceSnapshot{TenantID: tenant, ClusterID: clusterID, Kind: repo.KindNode, TeleportName: name,
		Hostname: name + ".example", Addr: "10.0.0.1:3022", Labels: map[string]string{"env": "prod"}, AgentVersion: "18.1.0",
		Online: true, LastSeenAt: base()}
}

func testSnapshots(t *testing.T, s repo.Store) {
	c := NewCluster(TenantA, "c")
	must(t, s.CreateCluster(ctx, c))
	a, err := s.UpsertSnapshot(ctx, NewSnapshot(TenantA, c.ID, "web1"))
	must(t, err)
	if a.ID == "" || a.Labels["env"] != "prod" {
		t.Fatalf("upsert = %+v", a)
	}
	// Same (cluster, kind, name) replaces the row and keeps its id.
	again := NewSnapshot(TenantA, c.ID, "web1")
	again.Online, again.OfflineSince = false, base()
	b, err := s.UpsertSnapshot(ctx, again)
	must(t, err)
	if b.ID != a.ID || b.Online || !b.OfflineSince.Equal(again.OfflineSince) {
		t.Fatalf("re-upsert = %+v (first id %s)", b, a.ID)
	}
	db := NewSnapshot(TenantA, c.ID, "web1")
	db.Kind = repo.KindDB
	d, err := s.UpsertSnapshot(ctx, db)
	must(t, err)
	if d.ID == a.ID {
		t.Fatal("another kind shares the row")
	}
	_, err = s.UpsertSnapshot(ctx, NewSnapshot(TenantB, c.ID, "x"))
	wantErr(t, err, repo.ErrNotFound)

	got, err := s.GetSnapshot(ctx, TenantA, a.ID)
	must(t, err)
	if got.TeleportName != "web1" || got.Hostname != "web1.example" || got.AgentVersion != "18.1.0" {
		t.Fatalf("get = %+v", got)
	}
	_, err = s.GetSnapshot(ctx, TenantB, a.ID)
	wantErr(t, err, repo.ErrNotFound)
	list, err := s.ListSnapshots(ctx, TenantA, c.ID)
	must(t, err)
	if len(list) != 2 {
		t.Fatalf("list = %+v", list)
	}
	must(t, s.DeleteSnapshot(ctx, TenantA, d.ID))
	wantErr(t, s.DeleteSnapshot(ctx, TenantA, d.ID), repo.ErrNotFound)
}

func testLinks(t *testing.T, s repo.Store) {
	c := NewCluster(TenantA, "c")
	must(t, s.CreateCluster(ctx, c))
	snap, err := s.UpsertSnapshot(ctx, NewSnapshot(TenantA, c.ID, "web1"))
	must(t, err)
	l := repo.ResourceLink{ID: store.NewID(), TenantID: TenantA, SnapshotID: snap.ID, TargetModule: repo.TargetInventory,
		TargetID: "host-1", Match: repo.MatchCandidate, MatchedOn: repo.MatchedOnHostname, CreatedAt: base()}
	must(t, s.CreateLink(ctx, l))
	dup := l
	dup.ID = store.NewID()
	wantErr(t, s.CreateLink(ctx, dup), repo.ErrConflict)
	asset := dup
	asset.TargetModule = repo.TargetAsset
	must(t, s.CreateLink(ctx, asset))
	cross := l
	cross.ID, cross.TenantID = store.NewID(), TenantB
	wantErr(t, s.CreateLink(ctx, cross), repo.ErrNotFound)

	got, err := s.GetLink(ctx, TenantA, l.ID)
	must(t, err)
	if got.TargetID != "host-1" || got.Match != repo.MatchCandidate || got.MatchedOn != repo.MatchedOnHostname {
		t.Fatalf("get = %+v", got)
	}
	_, err = s.GetLink(ctx, TenantB, l.ID)
	wantErr(t, err, repo.ErrNotFound)
	got.Match = repo.MatchConfirmed
	up, err := s.UpdateLink(ctx, got)
	must(t, err)
	if up.Match != repo.MatchConfirmed {
		t.Fatalf("update = %+v", up)
	}
	list, err := s.ListLinks(ctx, TenantA, snap.ID)
	must(t, err)
	if len(list) != 2 {
		t.Fatalf("list = %+v", list)
	}
	must(t, s.DeleteLink(ctx, TenantA, asset.ID))
	wantErr(t, s.DeleteLink(ctx, TenantA, asset.ID), repo.ErrNotFound)
	// Deleting the snapshot cascades to its links.
	must(t, s.DeleteSnapshot(ctx, TenantA, snap.ID))
	_, err = s.GetLink(ctx, TenantA, l.ID)
	wantErr(t, err, repo.ErrNotFound)
}

func testMappings(t *testing.T, s repo.Store) {
	c := NewCluster(TenantA, "c")
	must(t, s.CreateCluster(ctx, c))
	now := base()
	m := repo.RoleMapping{ID: store.NewID(), TenantID: TenantA, ClusterID: c.ID, SubjectKind: repo.SubjectModuleRole,
		SubjectRef: "teleport:operator", TeleportRoles: []string{"access"}, Logins: []string{"ubuntu"}, CreatedBy: "u1", CreatedAt: now, UpdatedAt: now}
	must(t, s.CreateMapping(ctx, m))
	dup := m
	dup.ID = store.NewID()
	wantErr(t, s.CreateMapping(ctx, dup), repo.ErrConflict)
	grp := dup
	grp.SubjectKind = repo.SubjectGroup
	grp.Logins = nil
	must(t, s.CreateMapping(ctx, grp))
	cross := m
	cross.ID, cross.TenantID = store.NewID(), TenantB
	wantErr(t, s.CreateMapping(ctx, cross), repo.ErrNotFound)

	got, err := s.GetMapping(ctx, TenantA, m.ID)
	must(t, err)
	if len(got.TeleportRoles) != 1 || got.Logins[0] != "ubuntu" {
		t.Fatalf("get = %+v", got)
	}
	g2, err := s.GetMapping(ctx, TenantA, grp.ID)
	must(t, err)
	if g2.Logins == nil {
		t.Fatal("logins must be an empty list, not nil")
	}
	_, err = s.GetMapping(ctx, TenantB, m.ID)
	wantErr(t, err, repo.ErrNotFound)
	got.TeleportRoles = []string{"access", "editor"}
	up, err := s.UpdateMapping(ctx, got)
	must(t, err)
	if len(up.TeleportRoles) != 2 || !up.UpdatedAt.After(now) {
		t.Fatalf("update = %+v", up)
	}
	list, err := s.ListMappings(ctx, TenantA, c.ID)
	must(t, err)
	if len(list) != 2 {
		t.Fatalf("list = %+v", list)
	}
	must(t, s.DeleteMapping(ctx, TenantA, m.ID))
	wantErr(t, s.DeleteMapping(ctx, TenantA, m.ID), repo.ErrNotFound)
}

func testManagedUsers(t *testing.T, s repo.Store) {
	c := NewCluster(TenantA, "c")
	must(t, s.CreateCluster(ctx, c))
	now := base()
	u := repo.ManagedUser{ID: store.NewID(), TenantID: TenantA, ClusterID: c.ID, TangraUserID: store.NewID(), TeleportUsername: "alice",
		State: repo.UserProvisioning, AppliedRoles: []string{"access"}, AppliedLogins: []string{}, CreatedAt: now}
	must(t, s.CreateManagedUser(ctx, u))
	sameUser := u
	sameUser.ID, sameUser.TeleportUsername = store.NewID(), "alice2"
	wantErr(t, s.CreateManagedUser(ctx, sameUser), repo.ErrConflict)
	sameName := u
	sameName.ID, sameName.TangraUserID = store.NewID(), store.NewID()
	wantErr(t, s.CreateManagedUser(ctx, sameName), repo.ErrConflict)
	cross := u
	cross.ID, cross.TenantID = store.NewID(), TenantB
	wantErr(t, s.CreateManagedUser(ctx, cross), repo.ErrNotFound)

	got, err := s.GetManagedUser(ctx, TenantA, u.ID)
	must(t, err)
	if got.TeleportUsername != "alice" || got.State != repo.UserProvisioning || got.AppliedLogins == nil {
		t.Fatalf("get = %+v", got)
	}
	_, err = s.GetManagedUser(ctx, TenantB, u.ID)
	wantErr(t, err, repo.ErrNotFound)
	got.State, got.LockName, got.DeprovisionAfter, got.LastSyncedAt = repo.UserLockedPendingDeletion, "tangra-deprov-alice", now.Add(7*24*time.Hour), now
	up, err := s.UpdateManagedUser(ctx, got)
	must(t, err)
	if up.State != repo.UserLockedPendingDeletion || up.LockName == "" || !up.DeprovisionAfter.Equal(got.DeprovisionAfter) {
		t.Fatalf("update = %+v", up)
	}
	list, err := s.ListManagedUsers(ctx, TenantA, c.ID)
	must(t, err)
	if len(list) != 1 {
		t.Fatalf("list = %+v", list)
	}
	must(t, s.DeleteManagedUser(ctx, TenantA, u.ID))
	wantErr(t, s.DeleteManagedUser(ctx, TenantA, u.ID), repo.ErrNotFound)
}

// NewRule builds a valid alert rule ("" cluster = all clusters).
func NewRule(tenant, clusterID string) repo.AlertRule {
	now := base()
	return repo.AlertRule{ID: store.NewID(), TenantID: tenant, ClusterID: clusterID, Name: "failed logins",
		ConditionKind: repo.ConditionTeleportEvent, EventTypes: []string{"user.login"}, ThresholdCount: 5, WindowMinutes: 10,
		Recipients: repo.Recipients{UserIDs: []string{"u1"}}, Enabled: true, CreatedBy: "u1", CreatedAt: now, UpdatedAt: now}
}

func testAlertRules(t *testing.T, s repo.Store) {
	c := NewCluster(TenantA, "c")
	must(t, s.CreateCluster(ctx, c))
	r := NewRule(TenantA, c.ID)
	must(t, s.CreateAlertRule(ctx, r))
	all := NewRule(TenantA, "")
	all.ConditionKind, all.EventTypes, all.ThresholdCount, all.WindowMinutes = repo.ConditionClusterUnreachable, []string{}, 0, 0
	must(t, s.CreateAlertRule(ctx, all))
	cross := NewRule(TenantB, c.ID)
	wantErr(t, s.CreateAlertRule(ctx, cross), repo.ErrNotFound)

	got, err := s.GetAlertRule(ctx, TenantA, r.ID)
	must(t, err)
	if got.ClusterID != c.ID || got.EventTypes[0] != "user.login" || got.ThresholdCount != 5 || got.Recipients.UserIDs[0] != "u1" || !got.Enabled {
		t.Fatalf("get = %+v", got)
	}
	g2, err := s.GetAlertRule(ctx, TenantA, all.ID)
	must(t, err)
	if g2.ClusterID != "" || g2.EventTypes == nil {
		t.Fatalf("all-clusters rule = %+v", g2)
	}
	_, err = s.GetAlertRule(ctx, TenantB, r.ID)
	wantErr(t, err, repo.ErrNotFound)
	got.Enabled, got.Name = false, "renamed"
	up, err := s.UpdateAlertRule(ctx, got)
	must(t, err)
	if up.Enabled || up.Name != "renamed" {
		t.Fatalf("update = %+v", up)
	}
	list, err := s.ListAlertRules(ctx, TenantA)
	must(t, err)
	if len(list) != 2 {
		t.Fatalf("list = %+v", list)
	}
	must(t, s.DeleteAlertRule(ctx, TenantA, r.ID))
	wantErr(t, s.DeleteAlertRule(ctx, TenantA, r.ID), repo.ErrNotFound)
}

// Spec 004 R4: per-cluster access settings, defaulted when never saved,
// tenant-scoped, cascading with the cluster.
func testAccessSettings(t *testing.T, s repo.Store) {
	c := NewCluster(TenantA, "c")
	must(t, s.CreateCluster(ctx, c))
	got, err := s.GetAccessSettings(ctx, TenantA, c.ID)
	must(t, err)
	if got.AccessTTLMinutes != repo.DefaultAccessTTLMinutes || got.ClusterID != c.ID || got.TenantID != TenantA || !got.UpdatedAt.IsZero() {
		t.Fatalf("default = %+v", got)
	}
	now := base()
	must(t, s.PutAccessSettings(ctx, repo.AccessSettings{ClusterID: c.ID, TenantID: TenantA, AccessTTLMinutes: 60, UpdatedAt: now, UpdatedBy: "alice"}))
	must(t, s.PutAccessSettings(ctx, repo.AccessSettings{ClusterID: c.ID, TenantID: TenantA, AccessTTLMinutes: 90, UpdatedAt: now, UpdatedBy: "bob"}))
	got, err = s.GetAccessSettings(ctx, TenantA, c.ID)
	must(t, err)
	if got.AccessTTLMinutes != 90 || got.UpdatedBy != "bob" || !got.UpdatedAt.Equal(now) {
		t.Fatalf("saved = %+v", got)
	}
	// Another tenant neither reads nor writes them.
	if b, err := s.GetAccessSettings(ctx, TenantB, c.ID); err == nil && b.AccessTTLMinutes != repo.DefaultAccessTTLMinutes {
		t.Fatalf("tenant B read %+v", b)
	}
	wantErr(t, s.PutAccessSettings(ctx, repo.AccessSettings{ClusterID: c.ID, TenantID: TenantB, AccessTTLMinutes: 15, UpdatedAt: now}), repo.ErrNotFound)
	wantErr(t, s.PutAccessSettings(ctx, repo.AccessSettings{ClusterID: store.NewID(), TenantID: TenantA, AccessTTLMinutes: 15, UpdatedAt: now}), repo.ErrNotFound)
	if got, _ := s.GetAccessSettings(ctx, TenantA, c.ID); got.AccessTTLMinutes != 90 {
		t.Fatalf("overwritten by another tenant: %+v", got)
	}
	must(t, s.DeleteCluster(ctx, TenantA, c.ID))
	c2 := c
	must(t, s.CreateCluster(ctx, c2))
	if got, _ := s.GetAccessSettings(ctx, TenantA, c.ID); got.AccessTTLMinutes != repo.DefaultAccessTTLMinutes {
		t.Fatalf("settings survived the cluster: %+v", got)
	}
}

func testAlertState(t *testing.T, s repo.Store) {
	c := NewCluster(TenantA, "c")
	must(t, s.CreateCluster(ctx, c))
	_, err := s.GetAlertCursor(ctx, TenantA, c.ID)
	wantErr(t, err, repo.ErrNotFound)
	now := base()
	cur := repo.AlertCursor{ClusterID: c.ID, TenantID: TenantA, LastEventTime: now, LastEventID: "ev-1", UpdatedAt: now}
	must(t, s.PutAlertCursor(ctx, cur))
	cur.LastEventID = "ev-2"
	must(t, s.PutAlertCursor(ctx, cur))
	got, err := s.GetAlertCursor(ctx, TenantA, c.ID)
	must(t, err)
	if got.LastEventID != "ev-2" || !got.LastEventTime.Equal(now) {
		t.Fatalf("cursor = %+v", got)
	}
	_, err = s.GetAlertCursor(ctx, TenantB, c.ID)
	wantErr(t, err, repo.ErrNotFound)
	wantErr(t, s.PutAlertCursor(ctx, repo.AlertCursor{ClusterID: c.ID, TenantID: TenantB, UpdatedAt: now}), repo.ErrNotFound)

	r := NewRule(TenantA, c.ID)
	must(t, s.CreateAlertRule(ctx, r))
	d := repo.AlertDelivery{ID: store.NewID(), TenantID: TenantA, RuleID: r.ID, ClusterID: c.ID, WindowKey: "2026-11-19T10:00", DeliveredAt: now.Add(-40 * 24 * time.Hour)}
	must(t, s.RecordDelivery(ctx, d))
	again := d
	again.ID = store.NewID()
	wantErr(t, s.RecordDelivery(ctx, again), repo.ErrConflict)
	next := again
	next.WindowKey, next.DeliveredAt = "2026-11-19T10:10", now
	must(t, s.RecordDelivery(ctx, next))
	n, err := s.PruneDeliveries(ctx, now.Add(-30*24*time.Hour))
	must(t, err)
	if n != 1 {
		t.Fatalf("pruned %d", n)
	}
	// The tenant-scoped prune (teleport:token-gc) touches only its tenant.
	old := repo.AlertDelivery{ID: store.NewID(), TenantID: TenantA, RuleID: r.ID, ClusterID: c.ID, WindowKey: "old", DeliveredAt: now.Add(-40 * 24 * time.Hour)}
	must(t, s.RecordDelivery(ctx, old))
	if n, err := s.PruneTenantDeliveries(ctx, TenantB, now.Add(-30*24*time.Hour)); err != nil || n != 0 {
		t.Fatalf("tenant B pruned %d, %v", n, err)
	}
	if n, err := s.PruneTenantDeliveries(ctx, TenantA, now.Add(-30*24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("tenant A pruned %d, %v", n, err)
	}
	// The pruned window can be delivered again.
	must(t, s.RecordDelivery(ctx, repo.AlertDelivery{ID: store.NewID(), TenantID: TenantA, RuleID: r.ID, ClusterID: c.ID, WindowKey: d.WindowKey, DeliveredAt: now}))
	// A released window can be claimed again; another tenant cannot release it.
	wantErr(t, s.ReleaseDelivery(ctx, TenantB, r.ID, c.ID, next.WindowKey), repo.ErrNotFound)
	must(t, s.ReleaseDelivery(ctx, TenantA, r.ID, c.ID, next.WindowKey))
	wantErr(t, s.ReleaseDelivery(ctx, TenantA, r.ID, c.ID, next.WindowKey), repo.ErrNotFound)
	must(t, s.RecordDelivery(ctx, repo.AlertDelivery{ID: store.NewID(), TenantID: TenantA, RuleID: r.ID, ClusterID: c.ID, WindowKey: next.WindowKey, DeliveredAt: now}))
}

func testDrafts(t *testing.T, s repo.Store) {
	now := base()
	d := repo.DeploymentDraft{ID: store.NewID(), TenantID: TenantA, Domain: "teleport.example.com", CertMode: repo.CertACME,
		ACMEEmail: "ops@example.com", TeleportVersion: "18.1.0", AdminUsername: "admin", AdminLogins: []string{"root"},
		Checks: []repo.DraftCheck{}, CreatedBy: "u1", CreatedAt: now, UpdatedAt: now}
	must(t, s.CreateDraft(ctx, d))
	got, err := s.GetDraft(ctx, TenantA, d.ID)
	must(t, err)
	if got.Domain != d.Domain || got.ACMEEmail != d.ACMEEmail || got.AdminLogins[0] != "root" || got.Checks == nil || got.RegisteredClusterID != "" {
		t.Fatalf("get = %+v", got)
	}
	_, err = s.GetDraft(ctx, TenantB, d.ID)
	wantErr(t, err, repo.ErrNotFound)
	c := NewCluster(TenantA, "c")
	must(t, s.CreateCluster(ctx, c))
	got.Checks = []repo.DraftCheck{{Name: "dns_apex", OK: true, Detail: "resolves", CheckedAt: now}}
	got.RegisteredClusterID = c.ID
	up, err := s.UpdateDraft(ctx, got)
	must(t, err)
	if len(up.Checks) != 1 || !up.Checks[0].OK || !up.Checks[0].CheckedAt.Equal(now) || up.RegisteredClusterID != c.ID {
		t.Fatalf("update = %+v", up)
	}
	// Linking another tenant's cluster is refused.
	cb := NewCluster(TenantB, "cb")
	must(t, s.CreateCluster(ctx, cb))
	bad := up
	bad.RegisteredClusterID = cb.ID
	_, err = s.UpdateDraft(ctx, bad)
	wantErr(t, err, repo.ErrNotFound)
	list, err := s.ListDrafts(ctx, TenantA)
	must(t, err)
	if len(list) != 1 {
		t.Fatalf("list = %+v", list)
	}
	// Removing the cluster keeps the draft with the link cleared.
	must(t, s.DeleteCluster(ctx, TenantA, c.ID))
	got, err = s.GetDraft(ctx, TenantA, d.ID)
	must(t, err)
	if got.RegisteredClusterID != "" {
		t.Fatalf("draft still links the removed cluster: %+v", got)
	}
	must(t, s.DeleteDraft(ctx, TenantA, d.ID))
	wantErr(t, s.DeleteDraft(ctx, TenantA, d.ID), repo.ErrNotFound)
}

// testCascade: deleting a cluster removes every row that hangs off it, and
// nothing of another cluster.
func testCascade(t *testing.T, s repo.Store) {
	now := base()
	c, keep := NewCluster(TenantA, "gone"), NewCluster(TenantA, "kept")
	must(t, s.CreateCluster(ctx, c))
	must(t, s.CreateCluster(ctx, keep))
	for _, cl := range []repo.Cluster{c, keep} {
		must(t, s.CreateJoinToken(ctx, repo.JoinToken{ID: store.NewID(), TenantID: TenantA, ClusterID: cl.ID, TokenHash: []byte{9},
			ResourceType: repo.KindApp, ExpiresAt: now.Add(time.Hour), CreatedAt: now}))
		snap, err := s.UpsertSnapshot(ctx, NewSnapshot(TenantA, cl.ID, "n1"))
		must(t, err)
		must(t, s.CreateLink(ctx, repo.ResourceLink{ID: store.NewID(), TenantID: TenantA, SnapshotID: snap.ID, TargetModule: repo.TargetAsset,
			TargetID: "a1", Match: repo.MatchAuto, MatchedOn: repo.MatchedOnIP, CreatedAt: now}))
		must(t, s.CreateMapping(ctx, repo.RoleMapping{ID: store.NewID(), TenantID: TenantA, ClusterID: cl.ID, SubjectKind: repo.SubjectGroup,
			SubjectRef: "g1", TeleportRoles: []string{"access"}, CreatedAt: now, UpdatedAt: now}))
		must(t, s.CreateManagedUser(ctx, repo.ManagedUser{ID: store.NewID(), TenantID: TenantA, ClusterID: cl.ID, TangraUserID: store.NewID(),
			TeleportUsername: "bob", State: repo.UserActive, CreatedAt: now}))
		must(t, s.PutAlertCursor(ctx, repo.AlertCursor{ClusterID: cl.ID, TenantID: TenantA, LastEventTime: now, UpdatedAt: now}))
		r := NewRule(TenantA, cl.ID)
		must(t, s.CreateAlertRule(ctx, r))
		must(t, s.RecordDelivery(ctx, repo.AlertDelivery{ID: store.NewID(), TenantID: TenantA, RuleID: r.ID, ClusterID: cl.ID, WindowKey: "w", DeliveredAt: now}))
	}
	global := NewRule(TenantA, "")
	must(t, s.CreateAlertRule(ctx, global))
	must(t, s.RecordDelivery(ctx, repo.AlertDelivery{ID: store.NewID(), TenantID: TenantA, RuleID: global.ID, ClusterID: c.ID, WindowKey: "w", DeliveredAt: now}))

	must(t, s.DeleteCluster(ctx, TenantA, c.ID))
	if l, _ := s.ListJoinTokens(ctx, TenantA, c.ID); len(l) != 0 {
		t.Errorf("tokens survived: %d", len(l))
	}
	if l, _ := s.ListSnapshots(ctx, TenantA, c.ID); len(l) != 0 {
		t.Errorf("snapshots survived: %d", len(l))
	}
	if l, _ := s.ListMappings(ctx, TenantA, c.ID); len(l) != 0 {
		t.Errorf("mappings survived: %d", len(l))
	}
	if l, _ := s.ListManagedUsers(ctx, TenantA, c.ID); len(l) != 0 {
		t.Errorf("managed users survived: %d", len(l))
	}
	if _, err := s.GetAlertCursor(ctx, TenantA, c.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Errorf("cursor survived: %v", err)
	}
	rules, _ := s.ListAlertRules(ctx, TenantA)
	if len(rules) != 2 {
		t.Errorf("rules after delete = %d, want the kept cluster's and the global rule", len(rules))
	}
	// The global rule's delivery for the removed cluster is gone too: the
	// window can be recorded again.
	must(t, s.RecordDelivery(ctx, repo.AlertDelivery{ID: store.NewID(), TenantID: TenantA, RuleID: global.ID, ClusterID: keep.ID, WindowKey: "w", DeliveredAt: now}))

	// The kept cluster is untouched.
	if l, _ := s.ListJoinTokens(ctx, TenantA, keep.ID); len(l) != 1 {
		t.Errorf("kept tokens = %d", len(l))
	}
	snaps, _ := s.ListSnapshots(ctx, TenantA, keep.ID)
	if len(snaps) != 1 {
		t.Fatalf("kept snapshots = %d", len(snaps))
	}
	if l, _ := s.ListLinks(ctx, TenantA, snaps[0].ID); len(l) != 1 {
		t.Errorf("kept links = %d", len(l))
	}
	if l, _ := s.ListMappings(ctx, TenantA, keep.ID); len(l) != 1 {
		t.Errorf("kept mappings = %d", len(l))
	}
	if l, _ := s.ListManagedUsers(ctx, TenantA, keep.ID); len(l) != 1 {
		t.Errorf("kept managed users = %d", len(l))
	}
	if _, err := s.GetAlertCursor(ctx, TenantA, keep.ID); err != nil {
		t.Errorf("kept cursor: %v", err)
	}
}

func testAudit(t *testing.T, s repo.Store) {
	must(t, s.AppendAudit(ctx, repo.AuditRow{ID: store.NewID(), Time: base(), TenantID: TenantA, ActorKind: "user", ActorID: "u1",
		ClusterID: store.NewID(), Action: "teleport.cluster.register", TargetKind: "cluster", TargetName: "prod", Outcome: "success",
		CorrelationID: "req-1", Detail: map[string]any{"display_name": "prod"}}))
	must(t, s.AppendAudit(ctx, repo.AuditRow{ID: store.NewID(), TenantID: "", ActorKind: "system", Action: "teleport.access.refused", Outcome: "failure"}))
}

// testLookups covers the cross-cluster reads of the Access API and the
// resource list: snapshots by hostname or IP, links by target and by cluster.
func testLookups(t *testing.T, s repo.Store) {
	c1, c2, other := NewCluster(TenantA, "c1"), NewCluster(TenantA, "c2"), NewCluster(TenantB, "b")
	for _, c := range []repo.Cluster{c1, c2, other} {
		must(t, s.CreateCluster(ctx, c))
	}
	web := NewSnapshot(TenantA, c1.ID, "n-1")
	web.Hostname, web.Addr = "Web-1.example", "10.0.0.5:3022"
	web2 := NewSnapshot(TenantA, c2.ID, "n-2")
	web2.Hostname, web2.Addr = "web-1.example", "[2001:db8::5]:3022"
	db := NewSnapshot(TenantA, c1.ID, "n-3")
	db.Hostname, db.Addr = "db-1.example", "10.0.0.50"
	foreign := NewSnapshot(TenantB, other.ID, "n-4")
	foreign.Hostname = "web-1.example"
	var ids []string
	for _, sn := range []repo.ResourceSnapshot{web, web2, db, foreign} {
		got, err := s.UpsertSnapshot(ctx, sn)
		must(t, err)
		ids = append(ids, got.ID)
	}
	found, err := s.FindSnapshots(ctx, TenantA, "WEB-1.example", "")
	must(t, err)
	if len(found) != 2 {
		t.Fatalf("by hostname = %+v", found)
	}
	for _, c := range []struct {
		ip   string
		want string
	}{{"10.0.0.5", "n-1"}, {"2001:db8::5", "n-2"}, {"10.0.0.50", "n-3"}} {
		found, err = s.FindSnapshots(ctx, TenantA, "", c.ip)
		must(t, err)
		if len(found) != 1 || found[0].TeleportName != c.want {
			t.Fatalf("by ip %s = %+v", c.ip, found)
		}
	}
	if found, _ = s.FindSnapshots(ctx, TenantA, "", "10.0.0.6"); len(found) != 0 {
		t.Fatalf("prefix match: %+v", found)
	}
	if found, _ = s.FindSnapshots(ctx, TenantA, "", ""); len(found) != 0 {
		t.Fatalf("empty lookup: %+v", found)
	}

	link := func(snap, module, target string) repo.ResourceLink {
		return repo.ResourceLink{ID: store.NewID(), TenantID: TenantA, SnapshotID: snap, TargetModule: module, TargetID: target,
			Match: repo.MatchAuto, MatchedOn: repo.MatchedOnHostname, CreatedAt: base()}
	}
	must(t, s.CreateLink(ctx, link(ids[0], repo.TargetInventory, "h1")))
	must(t, s.CreateLink(ctx, link(ids[1], repo.TargetInventory, "h2")))
	must(t, s.CreateLink(ctx, link(ids[2], repo.TargetAsset, "h1")))
	byTarget, err := s.ListLinksByTarget(ctx, TenantA, repo.TargetInventory, []string{"h1", "h2", "h9"})
	must(t, err)
	if len(byTarget) != 2 {
		t.Fatalf("by target = %+v", byTarget)
	}
	if byTarget, _ = s.ListLinksByTarget(ctx, TenantB, repo.TargetInventory, []string{"h1"}); len(byTarget) != 0 {
		t.Fatalf("cross-tenant by target = %+v", byTarget)
	}
	if byTarget, _ = s.ListLinksByTarget(ctx, TenantA, repo.TargetInventory, nil); len(byTarget) != 0 {
		t.Fatalf("no ids = %+v", byTarget)
	}
	byCluster, err := s.ListClusterLinks(ctx, TenantA, c1.ID)
	must(t, err)
	if len(byCluster) != 2 {
		t.Fatalf("by cluster = %+v", byCluster)
	}
}

func testAuditList(t *testing.T, s repo.Store) {
	c := store.NewID()
	t0 := base()
	for i, a := range []string{"teleport.token.create", "teleport.token.revoke", "teleport.lock.create"} {
		row := repo.AuditRow{ID: store.NewID(), Time: t0.Add(time.Duration(i) * time.Minute), TenantID: TenantA, ActorKind: "user",
			ActorID: "u1", Action: a, TargetKind: "token", Outcome: "success", Detail: map[string]any{"i": float64(i)}}
		if i == 2 {
			row.ClusterID, row.Outcome = c, "failure"
		}
		must(t, s.AppendAudit(ctx, row))
	}
	must(t, s.AppendAudit(ctx, repo.AuditRow{ID: store.NewID(), Time: t0, TenantID: TenantB, ActorKind: "user", Action: "teleport.token.create", Outcome: "success"}))
	rows, total, err := s.ListAudit(ctx, TenantA, repo.AuditQuery{Limit: 2})
	must(t, err)
	if total != 3 || len(rows) != 2 || rows[0].Action != "teleport.lock.create" || rows[0].ClusterID != c {
		t.Fatalf("newest first = %d %+v", total, rows)
	}
	rows, total, _ = s.ListAudit(ctx, TenantA, repo.AuditQuery{Ascending: true, Offset: 1, Limit: 1})
	if total != 3 || len(rows) != 1 || rows[0].Action != "teleport.token.revoke" {
		t.Fatalf("ascending page 2 = %+v", rows)
	}
	for _, q := range []repo.AuditQuery{{ClusterID: c}, {Outcome: "failure"}, {Action: "teleport.lock.create"}, {From: t0.Add(90 * time.Second)}} {
		if rows, total, _ = s.ListAudit(ctx, TenantA, q); total != 1 || rows[0].Action != "teleport.lock.create" {
			t.Fatalf("filter %+v = %d %+v", q, total, rows)
		}
	}
	if _, total, _ = s.ListAudit(ctx, TenantA, repo.AuditQuery{To: t0.Add(30 * time.Second)}); total != 1 {
		t.Fatalf("to = %d", total)
	}
	if _, total, _ = s.ListAudit(ctx, TenantB, repo.AuditQuery{}); total != 1 {
		t.Fatalf("tenant B = %d", total)
	}
}

func testEnrollments(t *testing.T, s repo.Store) {
	c := NewCluster(TenantA, "c")
	must(t, s.CreateCluster(ctx, c))
	now := base()
	host := store.NewID()
	e := repo.Enrollment{ID: store.NewID(), TenantID: TenantA, ClusterID: c.ID, HostID: host, Hostname: "web-1", State: repo.EnrollPending,
		ExpiresAt: now.Add(24 * time.Hour), CreatedBy: "u", CreatedAt: now, UpdatedAt: now}
	must(t, s.CreateEnrollment(ctx, e))
	wantErr(t, s.CreateEnrollment(ctx, e), repo.ErrConflict)
	other := e
	other.ID, other.TenantID = store.NewID(), TenantB
	wantErr(t, s.CreateEnrollment(ctx, other), repo.ErrNotFound) // another tenant's cluster
	got, err := s.GetEnrollment(ctx, TenantA, e.ID)
	must(t, err)
	if got.HostID != host || got.State != repo.EnrollPending || got.Hostname != "web-1" || !got.ExpiresAt.Equal(e.ExpiresAt) {
		t.Fatalf("enrollment = %+v", got)
	}
	_, err = s.GetEnrollment(ctx, TenantB, e.ID)
	wantErr(t, err, repo.ErrNotFound)

	e.State, e.ItemID = repo.EnrollDelivered, "item-1"
	got, err = s.UpdateEnrollment(ctx, e)
	must(t, err)
	if got.State != repo.EnrollDelivered || got.ItemID != "item-1" || got.Renders != 0 {
		t.Fatalf("updated = %+v", got)
	}
	cross := e
	cross.TenantID = TenantB
	_, err = s.UpdateEnrollment(ctx, cross)
	wantErr(t, err, repo.ErrNotFound)

	for i := 1; i <= 2; i++ {
		got, err = s.AddEnrollmentRender(ctx, TenantA, e.ID, 2)
		must(t, err)
		if got.Renders != i {
			t.Fatalf("renders = %d, want %d", got.Renders, i)
		}
	}
	_, err = s.AddEnrollmentRender(ctx, TenantA, e.ID, 2)
	wantErr(t, err, repo.ErrConflict)
	_, err = s.AddEnrollmentRender(ctx, TenantB, e.ID, 5)
	wantErr(t, err, repo.ErrNotFound)

	done := repo.Enrollment{ID: store.NewID(), TenantID: TenantA, ClusterID: c.ID, HostID: store.NewID(), State: repo.EnrollJoined,
		ExpiresAt: now.Add(48 * time.Hour), CreatedAt: now.Add(time.Minute)}
	must(t, s.CreateEnrollment(ctx, done))
	list, err := s.ListEnrollments(ctx, TenantA, c.ID)
	must(t, err)
	if len(list) != 2 || list[0].ID != done.ID {
		t.Fatalf("list = %+v", list)
	}
	active, err := s.ListActiveEnrollments(ctx, 10)
	must(t, err)
	if len(active) != 2 { // e, and done (joined, unlinked, not expired)
		t.Fatalf("active = %+v", active)
	}
	done.LinkID = store.NewID()
	_, err = s.UpdateEnrollment(ctx, done)
	must(t, err)
	active, err = s.ListActiveEnrollments(ctx, 10)
	must(t, err)
	if len(active) != 1 || active[0].ID != e.ID {
		t.Fatalf("active = %+v", active)
	}
	must(t, s.DeleteCluster(ctx, TenantA, c.ID))
	_, err = s.GetEnrollment(ctx, TenantA, e.ID)
	wantErr(t, err, repo.ErrNotFound)
}
