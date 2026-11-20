// Package memstore is an in-memory repo.Store for the Teleport module, used by
// offline tests and local development. It filters by tenant (mirroring RLS),
// enforces every unique guard of the schema, refuses child rows whose parent
// is missing in the tenant (the composite foreign keys), cascades cluster and
// snapshot deletes exactly as the SQL schema does, and offers per-method error
// injection via FailNext. Rows are copied in and out, so callers never share
// slices or maps with the store.
package memstore

import (
	"context"
	"maps"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
)

// injectedErr is the error FailNext arms for a given method.
type injectedErr struct{ method string }

func (e injectedErr) Error() string { return "memstore: injected failure in " + e.method }

// Mem is an in-memory store. It is safe for concurrent use.
type Mem struct {
	mu sync.Mutex

	clusters   map[string]repo.Cluster
	tokens     map[string]repo.JoinToken
	snapshots  map[string]repo.ResourceSnapshot
	links      map[string]repo.ResourceLink
	mappings   map[string]repo.RoleMapping
	users      map[string]repo.ManagedUser
	rules      map[string]repo.AlertRule
	cursors    map[string]repo.AlertCursor // by cluster id
	deliveries map[string]repo.AlertDelivery
	drafts     map[string]repo.DeploymentDraft
	enrolls    map[string]repo.Enrollment
	audit      []repo.AuditRow

	failNext map[string]bool
	// Now is the clock used for updated_at (overridable in tests).
	Now func() time.Time
}

var _ repo.Store = (*Mem)(nil)

// New builds an empty store.
func New() *Mem {
	return &Mem{
		clusters: map[string]repo.Cluster{}, tokens: map[string]repo.JoinToken{}, snapshots: map[string]repo.ResourceSnapshot{},
		links: map[string]repo.ResourceLink{}, mappings: map[string]repo.RoleMapping{}, users: map[string]repo.ManagedUser{},
		rules: map[string]repo.AlertRule{}, cursors: map[string]repo.AlertCursor{}, deliveries: map[string]repo.AlertDelivery{},
		drafts: map[string]repo.DeploymentDraft{}, enrolls: map[string]repo.Enrollment{}, failNext: map[string]bool{},
		Now: func() time.Time { return time.Now().UTC() },
	}
}

// FailNext arms the next call to the named method to return an injected error.
func (m *Mem) FailNext(method string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failNext[method] = true
}

// fail reports (and disarms) an injected failure for method. Callers hold mu.
func (m *Mem) fail(method string) error {
	if m.failNext[method] {
		delete(m.failNext, method)
		return injectedErr{method}
	}
	return nil
}

// Audit returns a copy of the appended audit rows (tests).
func (m *Mem) Audit() []repo.AuditRow {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]repo.AuditRow, len(m.audit))
	for i, r := range m.audit {
		r.Detail = maps.Clone(r.Detail)
		out[i] = r
	}
	return out
}

// now returns a strictly later time than prev (updated_at always advances).
func (m *Mem) now(prev time.Time) time.Time {
	n := m.Now()
	if !n.After(prev) {
		n = prev.Add(time.Microsecond)
	}
	return n
}

func strs(v []string) []string {
	if v == nil {
		return []string{}
	}
	return slices.Clone(v)
}

// owned reports whether the cluster exists in the tenant. Callers hold mu.
func (m *Mem) owned(tenantID, clusterID string) bool {
	c, ok := m.clusters[clusterID]
	return ok && c.TenantID == tenantID
}

// ---------------------------------------------------------------- clusters

func cloneCluster(c repo.Cluster) repo.Cluster {
	c.MissingPermissions = strs(c.MissingPermissions)
	return c
}

// CreateCluster implements repo.Store.
func (m *Mem) CreateCluster(_ context.Context, c repo.Cluster) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("CreateCluster"); err != nil {
		return err
	}
	if _, dup := m.clusters[c.ID]; dup {
		return repo.ErrConflict
	}
	for _, o := range m.clusters {
		if o.TenantID == c.TenantID && o.DisplayName == c.DisplayName {
			return repo.ErrConflict
		}
	}
	m.clusters[c.ID] = cloneCluster(c)
	return nil
}

// GetCluster implements repo.Store.
func (m *Mem) GetCluster(_ context.Context, tenantID, id string) (repo.Cluster, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetCluster"); err != nil {
		return repo.Cluster{}, err
	}
	c, ok := m.clusters[id]
	if !ok || c.TenantID != tenantID {
		return repo.Cluster{}, repo.ErrNotFound
	}
	return cloneCluster(c), nil
}

// ListClusters implements repo.Store.
func (m *Mem) ListClusters(_ context.Context, tenantID string) ([]repo.Cluster, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ListClusters"); err != nil {
		return nil, err
	}
	var out []repo.Cluster
	for _, c := range m.clusters {
		if c.TenantID == tenantID {
			out = append(out, cloneCluster(c))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DisplayName < out[j].DisplayName })
	return out, nil
}

// UpdateCluster implements repo.Store.
func (m *Mem) UpdateCluster(_ context.Context, c repo.Cluster) (repo.Cluster, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("UpdateCluster"); err != nil {
		return repo.Cluster{}, err
	}
	old, ok := m.clusters[c.ID]
	if !ok || old.TenantID != c.TenantID {
		return repo.Cluster{}, repo.ErrNotFound
	}
	for id, o := range m.clusters {
		if id != c.ID && o.TenantID == c.TenantID && o.DisplayName == c.DisplayName {
			return repo.Cluster{}, repo.ErrConflict
		}
	}
	c.CreatedAt, c.CreatedBy = old.CreatedAt, old.CreatedBy
	c.UpdatedAt = m.now(old.UpdatedAt)
	m.clusters[c.ID] = cloneCluster(c)
	return cloneCluster(c), nil
}

// DeleteCluster implements repo.Store, cascading like the schema.
func (m *Mem) DeleteCluster(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("DeleteCluster"); err != nil {
		return err
	}
	if !m.owned(tenantID, id) {
		return repo.ErrNotFound
	}
	delete(m.clusters, id)
	for k, e := range m.enrolls {
		if e.ClusterID == id {
			delete(m.enrolls, k)
		}
	}
	for k, t := range m.tokens {
		if t.ClusterID == id {
			delete(m.tokens, k)
		}
	}
	for k, s := range m.snapshots {
		if s.ClusterID == id {
			m.deleteSnapshot(k)
		}
	}
	for k, x := range m.mappings {
		if x.ClusterID == id {
			delete(m.mappings, k)
		}
	}
	for k, u := range m.users {
		if u.ClusterID == id {
			delete(m.users, k)
		}
	}
	for k, r := range m.rules {
		if r.ClusterID == id {
			m.deleteRule(k)
		}
	}
	delete(m.cursors, id)
	for k, d := range m.deliveries {
		if d.ClusterID == id {
			delete(m.deliveries, k)
		}
	}
	for k, d := range m.drafts {
		if d.RegisteredClusterID == id {
			d.RegisteredClusterID = ""
			m.drafts[k] = d
		}
	}
	return nil
}

// AllClusters implements repo.Store.
func (m *Mem) AllClusters(_ context.Context) ([]repo.Cluster, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("AllClusters"); err != nil {
		return nil, err
	}
	out := make([]repo.Cluster, 0, len(m.clusters))
	for _, c := range m.clusters {
		out = append(out, cloneCluster(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ---------------------------------------------------------------- join tokens

func cloneToken(t repo.JoinToken) repo.JoinToken {
	t.TokenHash = slices.Clone(t.TokenHash)
	return t
}

// CreateJoinToken implements repo.Store.
func (m *Mem) CreateJoinToken(_ context.Context, t repo.JoinToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("CreateJoinToken"); err != nil {
		return err
	}
	if !m.owned(t.TenantID, t.ClusterID) {
		return repo.ErrNotFound
	}
	if _, dup := m.tokens[t.ID]; dup {
		return repo.ErrConflict
	}
	m.tokens[t.ID] = cloneToken(t)
	return nil
}

// GetJoinToken implements repo.Store.
func (m *Mem) GetJoinToken(_ context.Context, tenantID, id string) (repo.JoinToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetJoinToken"); err != nil {
		return repo.JoinToken{}, err
	}
	t, ok := m.tokens[id]
	if !ok || t.TenantID != tenantID {
		return repo.JoinToken{}, repo.ErrNotFound
	}
	return cloneToken(t), nil
}

// ListJoinTokens implements repo.Store (newest first).
func (m *Mem) ListJoinTokens(_ context.Context, tenantID, clusterID string) ([]repo.JoinToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ListJoinTokens"); err != nil {
		return nil, err
	}
	var out []repo.JoinToken
	for _, t := range m.tokens {
		if t.TenantID == tenantID && t.ClusterID == clusterID {
			out = append(out, cloneToken(t))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// RevokeJoinToken implements repo.Store.
func (m *Mem) RevokeJoinToken(_ context.Context, tenantID, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("RevokeJoinToken"); err != nil {
		return err
	}
	t, ok := m.tokens[id]
	if !ok || t.TenantID != tenantID {
		return repo.ErrNotFound
	}
	t.RevokedAt = at
	m.tokens[id] = t
	return nil
}

// PruneJoinTokens implements repo.Store.
func (m *Mem) PruneJoinTokens(_ context.Context, before time.Time) (int, error) {
	return m.pruneTokens("PruneJoinTokens", "", before)
}

// PruneTenantJoinTokens implements repo.Store.
func (m *Mem) PruneTenantJoinTokens(_ context.Context, tenantID string, before time.Time) (int, error) {
	if tenantID == "" {
		return 0, repo.ErrNotFound
	}
	return m.pruneTokens("PruneTenantJoinTokens", tenantID, before)
}

// pruneTokens deletes expired tokens of tenantID ("" = every tenant).
func (m *Mem) pruneTokens(method, tenantID string, before time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(method); err != nil {
		return 0, err
	}
	n := 0
	for k, t := range m.tokens {
		if (tenantID == "" || t.TenantID == tenantID) && t.ExpiresAt.Before(before) {
			delete(m.tokens, k)
			n++
		}
	}
	return n, nil
}

// ---------------------------------------------------------------- snapshots

func cloneSnapshot(s repo.ResourceSnapshot) repo.ResourceSnapshot {
	s.Labels = maps.Clone(s.Labels)
	if s.Labels == nil {
		s.Labels = map[string]string{}
	}
	return s
}

// UpsertSnapshot implements repo.Store.
func (m *Mem) UpsertSnapshot(_ context.Context, s repo.ResourceSnapshot) (repo.ResourceSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("UpsertSnapshot"); err != nil {
		return repo.ResourceSnapshot{}, err
	}
	if !m.owned(s.TenantID, s.ClusterID) {
		return repo.ResourceSnapshot{}, repo.ErrNotFound
	}
	for id, o := range m.snapshots {
		if o.ClusterID == s.ClusterID && o.Kind == s.Kind && o.TeleportName == s.TeleportName {
			s.ID = id
		}
	}
	if s.ID == "" {
		s.ID = store.NewID()
	}
	m.snapshots[s.ID] = cloneSnapshot(s)
	return cloneSnapshot(s), nil
}

// GetSnapshot implements repo.Store.
func (m *Mem) GetSnapshot(_ context.Context, tenantID, id string) (repo.ResourceSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetSnapshot"); err != nil {
		return repo.ResourceSnapshot{}, err
	}
	s, ok := m.snapshots[id]
	if !ok || s.TenantID != tenantID {
		return repo.ResourceSnapshot{}, repo.ErrNotFound
	}
	return cloneSnapshot(s), nil
}

// ListSnapshots implements repo.Store (by kind, then name).
func (m *Mem) ListSnapshots(_ context.Context, tenantID, clusterID string) ([]repo.ResourceSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ListSnapshots"); err != nil {
		return nil, err
	}
	var out []repo.ResourceSnapshot
	for _, s := range m.snapshots {
		if s.TenantID == tenantID && s.ClusterID == clusterID {
			out = append(out, cloneSnapshot(s))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].TeleportName < out[j].TeleportName
	})
	return out, nil
}

// addrHost is the host part of "ip", "ip:port" or "[ip]:port".
func addrHost(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// FindSnapshots implements repo.Store.
func (m *Mem) FindSnapshots(_ context.Context, tenantID, hostname, ip string) ([]repo.ResourceSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("FindSnapshots"); err != nil {
		return nil, err
	}
	var out []repo.ResourceSnapshot
	for _, s := range m.snapshots {
		if s.TenantID != tenantID {
			continue
		}
		if (hostname != "" && strings.EqualFold(s.Hostname, hostname)) || (ip != "" && s.Addr != "" && addrHost(s.Addr) == ip) {
			out = append(out, cloneSnapshot(s))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ClusterID != out[j].ClusterID {
			return out[i].ClusterID < out[j].ClusterID
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].TeleportName < out[j].TeleportName
	})
	return out, nil
}

// deleteSnapshot removes a snapshot and its links. Callers hold mu.
func (m *Mem) deleteSnapshot(id string) {
	delete(m.snapshots, id)
	for k, l := range m.links {
		if l.SnapshotID == id {
			delete(m.links, k)
		}
	}
}

// DeleteSnapshot implements repo.Store.
func (m *Mem) DeleteSnapshot(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("DeleteSnapshot"); err != nil {
		return err
	}
	s, ok := m.snapshots[id]
	if !ok || s.TenantID != tenantID {
		return repo.ErrNotFound
	}
	m.deleteSnapshot(id)
	return nil
}

// ---------------------------------------------------------------- links

// CreateLink implements repo.Store.
func (m *Mem) CreateLink(_ context.Context, l repo.ResourceLink) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("CreateLink"); err != nil {
		return err
	}
	s, ok := m.snapshots[l.SnapshotID]
	if !ok || s.TenantID != l.TenantID {
		return repo.ErrNotFound
	}
	if _, dup := m.links[l.ID]; dup {
		return repo.ErrConflict
	}
	for _, o := range m.links {
		if o.SnapshotID == l.SnapshotID && o.TargetModule == l.TargetModule && o.TargetID == l.TargetID {
			return repo.ErrConflict
		}
	}
	m.links[l.ID] = l
	return nil
}

// GetLink implements repo.Store.
func (m *Mem) GetLink(_ context.Context, tenantID, id string) (repo.ResourceLink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetLink"); err != nil {
		return repo.ResourceLink{}, err
	}
	l, ok := m.links[id]
	if !ok || l.TenantID != tenantID {
		return repo.ResourceLink{}, repo.ErrNotFound
	}
	return l, nil
}

// ListLinks implements repo.Store.
func (m *Mem) ListLinks(_ context.Context, tenantID, snapshotID string) ([]repo.ResourceLink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ListLinks"); err != nil {
		return nil, err
	}
	var out []repo.ResourceLink
	for _, l := range m.links {
		if l.TenantID == tenantID && l.SnapshotID == snapshotID {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ListClusterLinks implements repo.Store.
func (m *Mem) ListClusterLinks(_ context.Context, tenantID, clusterID string) ([]repo.ResourceLink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ListClusterLinks"); err != nil {
		return nil, err
	}
	var out []repo.ResourceLink
	for _, l := range m.links {
		if s, ok := m.snapshots[l.SnapshotID]; ok && l.TenantID == tenantID && s.ClusterID == clusterID {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ListLinksByTarget implements repo.Store.
func (m *Mem) ListLinksByTarget(_ context.Context, tenantID, targetModule string, targetIDs []string) ([]repo.ResourceLink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ListLinksByTarget"); err != nil {
		return nil, err
	}
	var out []repo.ResourceLink
	for _, l := range m.links {
		if l.TenantID == tenantID && l.TargetModule == targetModule && slices.Contains(targetIDs, l.TargetID) {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// UpdateLink implements repo.Store (match and matched_on only).
func (m *Mem) UpdateLink(_ context.Context, l repo.ResourceLink) (repo.ResourceLink, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("UpdateLink"); err != nil {
		return repo.ResourceLink{}, err
	}
	old, ok := m.links[l.ID]
	if !ok || old.TenantID != l.TenantID {
		return repo.ResourceLink{}, repo.ErrNotFound
	}
	old.Match, old.MatchedOn = l.Match, l.MatchedOn
	m.links[l.ID] = old
	return old, nil
}

// DeleteLink implements repo.Store.
func (m *Mem) DeleteLink(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("DeleteLink"); err != nil {
		return err
	}
	l, ok := m.links[id]
	if !ok || l.TenantID != tenantID {
		return repo.ErrNotFound
	}
	delete(m.links, id)
	return nil
}

// ---------------------------------------------------------------- mappings

func cloneMapping(x repo.RoleMapping) repo.RoleMapping {
	x.TeleportRoles, x.Logins = strs(x.TeleportRoles), strs(x.Logins)
	return x
}

// CreateMapping implements repo.Store.
func (m *Mem) CreateMapping(_ context.Context, x repo.RoleMapping) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("CreateMapping"); err != nil {
		return err
	}
	if !m.owned(x.TenantID, x.ClusterID) {
		return repo.ErrNotFound
	}
	if _, dup := m.mappings[x.ID]; dup {
		return repo.ErrConflict
	}
	for _, o := range m.mappings {
		if o.ClusterID == x.ClusterID && o.SubjectKind == x.SubjectKind && o.SubjectRef == x.SubjectRef {
			return repo.ErrConflict
		}
	}
	m.mappings[x.ID] = cloneMapping(x)
	return nil
}

// GetMapping implements repo.Store.
func (m *Mem) GetMapping(_ context.Context, tenantID, id string) (repo.RoleMapping, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetMapping"); err != nil {
		return repo.RoleMapping{}, err
	}
	x, ok := m.mappings[id]
	if !ok || x.TenantID != tenantID {
		return repo.RoleMapping{}, repo.ErrNotFound
	}
	return cloneMapping(x), nil
}

// ListMappings implements repo.Store.
func (m *Mem) ListMappings(_ context.Context, tenantID, clusterID string) ([]repo.RoleMapping, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ListMappings"); err != nil {
		return nil, err
	}
	var out []repo.RoleMapping
	for _, x := range m.mappings {
		if x.TenantID == tenantID && x.ClusterID == clusterID {
			out = append(out, cloneMapping(x))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// UpdateMapping implements repo.Store (roles and logins).
func (m *Mem) UpdateMapping(_ context.Context, x repo.RoleMapping) (repo.RoleMapping, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("UpdateMapping"); err != nil {
		return repo.RoleMapping{}, err
	}
	old, ok := m.mappings[x.ID]
	if !ok || old.TenantID != x.TenantID {
		return repo.RoleMapping{}, repo.ErrNotFound
	}
	old.TeleportRoles, old.Logins = x.TeleportRoles, x.Logins
	old.UpdatedAt = m.now(old.UpdatedAt)
	m.mappings[x.ID] = cloneMapping(old)
	return cloneMapping(old), nil
}

// DeleteMapping implements repo.Store.
func (m *Mem) DeleteMapping(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("DeleteMapping"); err != nil {
		return err
	}
	x, ok := m.mappings[id]
	if !ok || x.TenantID != tenantID {
		return repo.ErrNotFound
	}
	delete(m.mappings, id)
	return nil
}

// ---------------------------------------------------------------- managed users

func cloneUser(u repo.ManagedUser) repo.ManagedUser {
	u.AppliedRoles, u.AppliedLogins = strs(u.AppliedRoles), strs(u.AppliedLogins)
	return u
}

// CreateManagedUser implements repo.Store.
func (m *Mem) CreateManagedUser(_ context.Context, u repo.ManagedUser) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("CreateManagedUser"); err != nil {
		return err
	}
	if !m.owned(u.TenantID, u.ClusterID) {
		return repo.ErrNotFound
	}
	if _, dup := m.users[u.ID]; dup {
		return repo.ErrConflict
	}
	for _, o := range m.users {
		if o.ClusterID == u.ClusterID && (o.TangraUserID == u.TangraUserID || o.TeleportUsername == u.TeleportUsername) {
			return repo.ErrConflict
		}
	}
	m.users[u.ID] = cloneUser(u)
	return nil
}

// GetManagedUser implements repo.Store.
func (m *Mem) GetManagedUser(_ context.Context, tenantID, id string) (repo.ManagedUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetManagedUser"); err != nil {
		return repo.ManagedUser{}, err
	}
	u, ok := m.users[id]
	if !ok || u.TenantID != tenantID {
		return repo.ManagedUser{}, repo.ErrNotFound
	}
	return cloneUser(u), nil
}

// ListManagedUsers implements repo.Store (by Teleport username).
func (m *Mem) ListManagedUsers(_ context.Context, tenantID, clusterID string) ([]repo.ManagedUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ListManagedUsers"); err != nil {
		return nil, err
	}
	var out []repo.ManagedUser
	for _, u := range m.users {
		if u.TenantID == tenantID && u.ClusterID == clusterID {
			out = append(out, cloneUser(u))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TeleportUsername < out[j].TeleportUsername })
	return out, nil
}

// UpdateManagedUser implements repo.Store (state and applied sets).
func (m *Mem) UpdateManagedUser(_ context.Context, u repo.ManagedUser) (repo.ManagedUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("UpdateManagedUser"); err != nil {
		return repo.ManagedUser{}, err
	}
	old, ok := m.users[u.ID]
	if !ok || old.TenantID != u.TenantID {
		return repo.ManagedUser{}, repo.ErrNotFound
	}
	old.State, old.AppliedRoles, old.AppliedLogins = u.State, u.AppliedRoles, u.AppliedLogins
	old.LockName, old.DeprovisionAfter, old.LastSyncedAt = u.LockName, u.DeprovisionAfter, u.LastSyncedAt
	m.users[u.ID] = cloneUser(old)
	return cloneUser(old), nil
}

// DeleteManagedUser implements repo.Store.
func (m *Mem) DeleteManagedUser(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("DeleteManagedUser"); err != nil {
		return err
	}
	u, ok := m.users[id]
	if !ok || u.TenantID != tenantID {
		return repo.ErrNotFound
	}
	delete(m.users, id)
	return nil
}

// ---------------------------------------------------------------- alert rules

func cloneRule(r repo.AlertRule) repo.AlertRule {
	r.EventTypes = strs(r.EventTypes)
	r.Recipients.UserIDs, r.Recipients.ChannelIDs = slices.Clone(r.Recipients.UserIDs), slices.Clone(r.Recipients.ChannelIDs)
	return r
}

// CreateAlertRule implements repo.Store.
func (m *Mem) CreateAlertRule(_ context.Context, r repo.AlertRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("CreateAlertRule"); err != nil {
		return err
	}
	if r.ClusterID != "" && !m.owned(r.TenantID, r.ClusterID) {
		return repo.ErrNotFound
	}
	if _, dup := m.rules[r.ID]; dup {
		return repo.ErrConflict
	}
	m.rules[r.ID] = cloneRule(r)
	return nil
}

// GetAlertRule implements repo.Store.
func (m *Mem) GetAlertRule(_ context.Context, tenantID, id string) (repo.AlertRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetAlertRule"); err != nil {
		return repo.AlertRule{}, err
	}
	r, ok := m.rules[id]
	if !ok || r.TenantID != tenantID {
		return repo.AlertRule{}, repo.ErrNotFound
	}
	return cloneRule(r), nil
}

// ListAlertRules implements repo.Store (by name, then id).
func (m *Mem) ListAlertRules(_ context.Context, tenantID string) ([]repo.AlertRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ListAlertRules"); err != nil {
		return nil, err
	}
	var out []repo.AlertRule
	for _, r := range m.rules {
		if r.TenantID == tenantID {
			out = append(out, cloneRule(r))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// UpdateAlertRule implements repo.Store (every field but the cluster).
func (m *Mem) UpdateAlertRule(_ context.Context, r repo.AlertRule) (repo.AlertRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("UpdateAlertRule"); err != nil {
		return repo.AlertRule{}, err
	}
	old, ok := m.rules[r.ID]
	if !ok || old.TenantID != r.TenantID {
		return repo.AlertRule{}, repo.ErrNotFound
	}
	r.ClusterID, r.CreatedAt, r.CreatedBy = old.ClusterID, old.CreatedAt, old.CreatedBy
	r.UpdatedAt = m.now(old.UpdatedAt)
	m.rules[r.ID] = cloneRule(r)
	return cloneRule(r), nil
}

// deleteRule removes a rule and its deliveries. Callers hold mu.
func (m *Mem) deleteRule(id string) {
	delete(m.rules, id)
	for k, d := range m.deliveries {
		if d.RuleID == id {
			delete(m.deliveries, k)
		}
	}
}

// DeleteAlertRule implements repo.Store.
func (m *Mem) DeleteAlertRule(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("DeleteAlertRule"); err != nil {
		return err
	}
	r, ok := m.rules[id]
	if !ok || r.TenantID != tenantID {
		return repo.ErrNotFound
	}
	m.deleteRule(id)
	return nil
}

// ---------------------------------------------------------------- alert state

// GetAlertCursor implements repo.Store.
func (m *Mem) GetAlertCursor(_ context.Context, tenantID, clusterID string) (repo.AlertCursor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetAlertCursor"); err != nil {
		return repo.AlertCursor{}, err
	}
	c, ok := m.cursors[clusterID]
	if !ok || c.TenantID != tenantID {
		return repo.AlertCursor{}, repo.ErrNotFound
	}
	return c, nil
}

// PutAlertCursor implements repo.Store.
func (m *Mem) PutAlertCursor(_ context.Context, c repo.AlertCursor) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("PutAlertCursor"); err != nil {
		return err
	}
	if !m.owned(c.TenantID, c.ClusterID) {
		return repo.ErrNotFound
	}
	m.cursors[c.ClusterID] = c
	return nil
}

// RecordDelivery implements repo.Store.
func (m *Mem) RecordDelivery(_ context.Context, d repo.AlertDelivery) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("RecordDelivery"); err != nil {
		return err
	}
	r, ok := m.rules[d.RuleID]
	if !ok || r.TenantID != d.TenantID || !m.owned(d.TenantID, d.ClusterID) {
		return repo.ErrNotFound
	}
	for _, o := range m.deliveries {
		if o.RuleID == d.RuleID && o.ClusterID == d.ClusterID && o.WindowKey == d.WindowKey {
			return repo.ErrConflict
		}
	}
	m.deliveries[d.ID] = d
	return nil
}

// ReleaseDelivery implements repo.Store.
func (m *Mem) ReleaseDelivery(_ context.Context, tenantID, ruleID, clusterID, windowKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ReleaseDelivery"); err != nil {
		return err
	}
	for k, d := range m.deliveries {
		if d.TenantID == tenantID && d.RuleID == ruleID && d.ClusterID == clusterID && d.WindowKey == windowKey {
			delete(m.deliveries, k)
			return nil
		}
	}
	return repo.ErrNotFound
}

// PruneDeliveries implements repo.Store.
func (m *Mem) PruneDeliveries(_ context.Context, before time.Time) (int, error) {
	return m.pruneDeliveries("PruneDeliveries", "", before)
}

// PruneTenantDeliveries implements repo.Store.
func (m *Mem) PruneTenantDeliveries(_ context.Context, tenantID string, before time.Time) (int, error) {
	if tenantID == "" {
		return 0, repo.ErrNotFound
	}
	return m.pruneDeliveries("PruneTenantDeliveries", tenantID, before)
}

// pruneDeliveries deletes old deliveries of tenantID ("" = every tenant).
func (m *Mem) pruneDeliveries(method, tenantID string, before time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(method); err != nil {
		return 0, err
	}
	n := 0
	for k, d := range m.deliveries {
		if (tenantID == "" || d.TenantID == tenantID) && d.DeliveredAt.Before(before) {
			delete(m.deliveries, k)
			n++
		}
	}
	return n, nil
}

// ---------------------------------------------------------------- drafts

func cloneDraft(d repo.DeploymentDraft) repo.DeploymentDraft {
	d.AdminLogins = strs(d.AdminLogins)
	d.Checks = slices.Clone(d.Checks)
	if d.Checks == nil {
		d.Checks = []repo.DraftCheck{}
	}
	return d
}

// CreateDraft implements repo.Store.
func (m *Mem) CreateDraft(_ context.Context, d repo.DeploymentDraft) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("CreateDraft"); err != nil {
		return err
	}
	if d.RegisteredClusterID != "" && !m.owned(d.TenantID, d.RegisteredClusterID) {
		return repo.ErrNotFound
	}
	if _, dup := m.drafts[d.ID]; dup {
		return repo.ErrConflict
	}
	m.drafts[d.ID] = cloneDraft(d)
	return nil
}

// GetDraft implements repo.Store.
func (m *Mem) GetDraft(_ context.Context, tenantID, id string) (repo.DeploymentDraft, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetDraft"); err != nil {
		return repo.DeploymentDraft{}, err
	}
	d, ok := m.drafts[id]
	if !ok || d.TenantID != tenantID {
		return repo.DeploymentDraft{}, repo.ErrNotFound
	}
	return cloneDraft(d), nil
}

// ListDrafts implements repo.Store (newest first).
func (m *Mem) ListDrafts(_ context.Context, tenantID string) ([]repo.DeploymentDraft, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ListDrafts"); err != nil {
		return nil, err
	}
	var out []repo.DeploymentDraft
	for _, d := range m.drafts {
		if d.TenantID == tenantID {
			out = append(out, cloneDraft(d))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// UpdateDraft implements repo.Store (every field but the owner and creation).
func (m *Mem) UpdateDraft(_ context.Context, d repo.DeploymentDraft) (repo.DeploymentDraft, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("UpdateDraft"); err != nil {
		return repo.DeploymentDraft{}, err
	}
	old, ok := m.drafts[d.ID]
	if !ok || old.TenantID != d.TenantID {
		return repo.DeploymentDraft{}, repo.ErrNotFound
	}
	if d.RegisteredClusterID != "" && !m.owned(d.TenantID, d.RegisteredClusterID) {
		return repo.DeploymentDraft{}, repo.ErrNotFound
	}
	d.CreatedAt, d.CreatedBy = old.CreatedAt, old.CreatedBy
	d.UpdatedAt = m.now(old.UpdatedAt)
	m.drafts[d.ID] = cloneDraft(d)
	return cloneDraft(d), nil
}

// DeleteDraft implements repo.Store.
func (m *Mem) DeleteDraft(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("DeleteDraft"); err != nil {
		return err
	}
	d, ok := m.drafts[id]
	if !ok || d.TenantID != tenantID {
		return repo.ErrNotFound
	}
	delete(m.drafts, id)
	return nil
}

// ---------------------------------------------------------------- audit

// AppendAudit implements repo.Store.
func (m *Mem) AppendAudit(_ context.Context, row repo.AuditRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("AppendAudit"); err != nil {
		return err
	}
	if row.TenantID == "" {
		row.TenantID = repo.NilTenant
	}
	row.Detail = maps.Clone(row.Detail)
	m.audit = append(m.audit, row)
	return nil
}

// ListAudit implements repo.Store.
func (m *Mem) ListAudit(_ context.Context, tenantID string, q repo.AuditQuery) ([]repo.AuditRow, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ListAudit"); err != nil {
		return nil, 0, err
	}
	var all []repo.AuditRow
	for _, r := range m.audit {
		switch {
		case r.TenantID != tenantID,
			q.ClusterID != "" && r.ClusterID != q.ClusterID,
			q.Action != "" && r.Action != q.Action,
			q.Outcome != "" && r.Outcome != q.Outcome,
			!q.From.IsZero() && r.Time.Before(q.From),
			!q.To.IsZero() && r.Time.After(q.To):
			continue
		}
		r.Detail = maps.Clone(r.Detail)
		all = append(all, r)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if q.Ascending {
			return all[i].Time.Before(all[j].Time)
		}
		return all[i].Time.After(all[j].Time)
	})
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	start := min(max(q.Offset, 0), len(all))
	end := min(start+limit, len(all))
	return all[start:end], len(all), nil
}

// ---------------------------------------------------------------- enrollments

// CreateEnrollment implements repo.Store.
func (m *Mem) CreateEnrollment(_ context.Context, e repo.Enrollment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("CreateEnrollment"); err != nil {
		return err
	}
	if !m.owned(e.TenantID, e.ClusterID) {
		return repo.ErrNotFound
	}
	if _, dup := m.enrolls[e.ID]; dup {
		return repo.ErrConflict
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = m.Now()
	}
	if e.UpdatedAt.IsZero() {
		e.UpdatedAt = e.CreatedAt
	}
	m.enrolls[e.ID] = e
	return nil
}

// GetEnrollment implements repo.Store.
func (m *Mem) GetEnrollment(_ context.Context, tenantID, id string) (repo.Enrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetEnrollment"); err != nil {
		return repo.Enrollment{}, err
	}
	e, ok := m.enrolls[id]
	if !ok || e.TenantID != tenantID {
		return repo.Enrollment{}, repo.ErrNotFound
	}
	return e, nil
}

// ListEnrollments implements repo.Store (newest first).
func (m *Mem) ListEnrollments(_ context.Context, tenantID, clusterID string) ([]repo.Enrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ListEnrollments"); err != nil {
		return nil, err
	}
	var out []repo.Enrollment
	for _, e := range m.enrolls {
		if e.TenantID == tenantID && e.ClusterID == clusterID {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

// UpdateEnrollment implements repo.Store.
func (m *Mem) UpdateEnrollment(_ context.Context, e repo.Enrollment) (repo.Enrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("UpdateEnrollment"); err != nil {
		return repo.Enrollment{}, err
	}
	old, ok := m.enrolls[e.ID]
	if !ok || old.TenantID != e.TenantID {
		return repo.Enrollment{}, repo.ErrNotFound
	}
	old.State, old.Reason, old.ItemID, old.NodeHostUUID, old.LinkID = e.State, e.Reason, e.ItemID, e.NodeHostUUID, e.LinkID
	old.UpdatedAt = m.Now()
	m.enrolls[e.ID] = old
	return old, nil
}

// AddEnrollmentRender implements repo.Store.
func (m *Mem) AddEnrollmentRender(_ context.Context, tenantID, id string, max int) (repo.Enrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("AddEnrollmentRender"); err != nil {
		return repo.Enrollment{}, err
	}
	e, ok := m.enrolls[id]
	if !ok || e.TenantID != tenantID {
		return repo.Enrollment{}, repo.ErrNotFound
	}
	if e.Renders >= max {
		return repo.Enrollment{}, repo.ErrConflict
	}
	e.Renders++
	e.UpdatedAt = m.Now()
	m.enrolls[id] = e
	return e, nil
}

// ListActiveEnrollments implements repo.Store (least recently updated first).
func (m *Mem) ListActiveEnrollments(_ context.Context, limit int) ([]repo.Enrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ListActiveEnrollments"); err != nil {
		return nil, err
	}
	var out []repo.Enrollment
	now := m.Now()
	for _, e := range m.enrolls {
		if repo.EnrollActive(e.State) || e.State == repo.EnrollJoined && e.LinkID == "" && now.Before(e.ExpiresAt) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.Before(out[j].UpdatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
