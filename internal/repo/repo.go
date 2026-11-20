// Package repo defines the storage contract and the row models of the
// Teleport module (data-model.md). Teleport-owned objects (users, roles,
// locks, tokens, resources, audit events, sessions) are NOT stored: they are
// read live from the cluster (research D4). No model carries a secret value:
// credentials are warden references only.
//
// Every tenant-scoped method runs under the tenant's RLS scope. The only
// cross-tenant operations are the system-scope worker listings (AllClusters),
// the retention prunes and audit appends.
package repo

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors every implementation maps its failures to.
var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

// Cluster status (data-model state machine).
const (
	StatusConnected          = "connected"
	StatusUnreachable        = "unreachable"
	StatusCredentialExpiring = "credential_expiring" // #nosec G101 -- a name, not a credential
	StatusCredentialInvalid  = "credential_invalid"  // #nosec G101 -- a name, not a credential
	StatusUnsupportedVersion = "unsupported_version"
)

// Editions.
const (
	EditionCommunity  = "community"
	EditionEnterprise = "enterprise"
	EditionUnknown    = "unknown"
)

// CredentialIdentityFile is the only credential kind of v1: bot identities are
// deferred (research D2).
const CredentialIdentityFile = "identity_file"

// Resource kinds (join tokens and snapshots).
const (
	KindNode    = "node"
	KindApp     = "app"
	KindDB      = "db"
	KindKube    = "kube"
	KindDesktop = "desktop"
)

// ResourceKinds lists every resource kind.
var ResourceKinds = []string{KindNode, KindApp, KindDB, KindKube, KindDesktop}

// Link targets, match kinds and match keys.
const (
	TargetInventory = "inventory"
	TargetAsset     = "asset"

	MatchAuto      = "auto"
	MatchConfirmed = "confirmed"
	MatchCandidate = "candidate"

	MatchedOnHostname = "hostname"
	MatchedOnIP       = "ip"
)

// Mapping subjects.
const (
	SubjectModuleRole = "module_role"
	SubjectGroup      = "group"
)

// Managed-user states.
const (
	UserProvisioning          = "provisioning"
	UserActive                = "active"
	UserLockedPendingDeletion = "locked_pending_deletion"
	UserError                 = "error"
)

// Alert conditions.
const (
	ConditionTeleportEvent      = "teleport_event"
	ConditionClusterUnreachable = "cluster_unreachable"
	ConditionCredentialExpiring = "credential_expiring" // #nosec G101 -- a name, not a credential
	ConditionResourceOffline    = "resource_offline"
)

// Deployment certificate modes.
const (
	CertACME = "acme"
	CertOwn  = "own_cert"
)

// Counts are the last health-check object counts of a cluster.
type Counts struct {
	Users    int `json:"users"`
	Roles    int `json:"roles"`
	Nodes    int `json:"nodes"`
	Apps     int `json:"apps"`
	DBs      int `json:"dbs"`
	Kube     int `json:"kube"`
	Desktops int `json:"desktops"`
}

// ClusterSettings are the tenant-editable cluster settings.
type ClusterSettings struct {
	OfflineThresholdMinutes int  `json:"offline_threshold_minutes"`
	AlertsEnabled           bool `json:"alerts_enabled"`
}

// Cluster is a tenant's registration of one Teleport cluster.
type Cluster struct {
	ID                  string
	TenantID            string
	DisplayName         string
	ProxyAddr           string
	ClusterName         string
	Edition             string
	ServerVersion       string
	CredentialRef       string // warden:… only; never returned by the API
	CredentialKind      string
	CredentialIdentity  string
	CredentialIssuedAt  time.Time // certificate NotBefore (lifetime for the 25% threshold)
	CredentialExpiresAt time.Time
	Status              string
	StatusReason        string
	MissingPermissions  []string
	LastContactAt       time.Time // zero = never
	Counts              Counts
	Settings            ClusterSettings
	CreatedBy           string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// JoinToken is join-token metadata: the token value is never stored.
type JoinToken struct {
	ID           string
	TenantID     string
	ClusterID    string
	TokenHash    []byte // SHA-256 of the token name
	ResourceType string
	ExpiresAt    time.Time
	RevokedAt    time.Time // zero = active
	CreatedBy    string
	CreatedAt    time.Time
}

// Enrollment states (spec 002; mirror inventory's TeleportJoinState).
const (
	EnrollPending     = "pending"
	EnrollDelivered   = "delivered"
	EnrollFetched     = "fetched"
	EnrollInstalling  = "installing"
	EnrollJoined      = "joined"
	EnrollFailed      = "failed"
	EnrollUnsupported = "unsupported"
	EnrollSuperseded  = "superseded"
	EnrollExpired     = "expired"
	EnrollCancelled   = "cancelled"
)

// EnrollActive reports whether an enrollment state is not final.
func EnrollActive(state string) bool {
	switch state {
	case EnrollPending, EnrollDelivered, EnrollFetched, EnrollInstalling:
		return true
	}
	return false
}

// Enrollment is one inventory host being enrolled as a Teleport SSH node
// through its inventory agent (spec 002). The join token is never stored:
// it is minted when the agent fetches the material (Renders counts that).
type Enrollment struct {
	ID           string
	TenantID     string
	ClusterID    string
	HostID       string // inventory host id
	Hostname     string
	State        string
	Reason       string
	ItemID       string // inventory's join item
	Renders      int
	NodeHostUUID string
	LinkID       string // resource link created on joined
	ExpiresAt    time.Time
	CreatedBy    string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// ResourceSnapshot is the last-known state of an enrolled resource.
type ResourceSnapshot struct {
	ID           string
	TenantID     string
	ClusterID    string
	Kind         string
	TeleportName string
	Hostname     string
	Addr         string
	Labels       map[string]string
	AgentVersion string
	Online       bool
	LastSeenAt   time.Time
	OfflineSince time.Time
	FlaggedAt    time.Time
}

// ResourceLink links a Teleport resource to an inventory or asset record.
type ResourceLink struct {
	ID           string
	TenantID     string
	SnapshotID   string
	TargetModule string
	TargetID     string
	Match        string
	MatchedOn    string
	CreatedAt    time.Time
}

// RoleMapping maps a tangra role or group to Teleport roles and logins.
type RoleMapping struct {
	ID            string
	TenantID      string
	ClusterID     string
	SubjectKind   string
	SubjectRef    string
	TeleportRoles []string
	Logins        []string
	CreatedBy     string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// ManagedUser links a tangra user to the Teleport user the module created.
type ManagedUser struct {
	ID               string
	TenantID         string
	ClusterID        string
	TangraUserID     string
	TeleportUsername string
	State            string
	AppliedRoles     []string
	AppliedLogins    []string
	LockName         string
	DeprovisionAfter time.Time
	LastSyncedAt     time.Time
	CreatedAt        time.Time
}

// Recipients are notification recipients by reference.
type Recipients struct {
	UserIDs    []string `json:"user_ids,omitempty"`
	ChannelIDs []string `json:"channel_ids,omitempty"`
}

// AlertRule is a tenant alert rule ("" ClusterID = all of the tenant's clusters).
type AlertRule struct {
	ID             string
	TenantID       string
	ClusterID      string
	Name           string
	ConditionKind  string
	EventTypes     []string
	ThresholdCount int // 0 = any match
	WindowMinutes  int
	Recipients     Recipients
	Enabled        bool
	CreatedBy      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// AlertCursor is the alert poller's position per cluster.
type AlertCursor struct {
	ClusterID     string
	TenantID      string
	LastEventTime time.Time
	LastEventID   string
	UpdatedAt     time.Time
}

// AlertDelivery de-duplicates deliveries per (rule, cluster, window).
type AlertDelivery struct {
	ID          string
	TenantID    string
	RuleID      string
	ClusterID   string
	WindowKey   string
	DeliveredAt time.Time
}

// DraftCheck is one prerequisite check result of a deployment draft.
type DraftCheck struct {
	Name      string    `json:"name"`
	OK        bool      `json:"ok"`
	Detail    string    `json:"detail"`
	CheckedAt time.Time `json:"checked_at"`
}

// DeploymentDraft is the wizard state for a planned cluster.
type DeploymentDraft struct {
	ID                  string
	TenantID            string
	Domain              string
	CertMode            string
	ACMEEmail           string
	TeleportVersion     string
	AdminUsername       string
	AdminLogins         []string
	Checks              []DraftCheck
	RegisteredClusterID string // "" = not yet registered
	CreatedBy           string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// AuditRow is one append-only audit event (data-model audit_event).
type AuditRow struct {
	ID            string
	Time          time.Time
	TenantID      string
	ActorKind     string
	ActorID       string
	ClusterID     string // "" = none
	Action        string
	TargetKind    string
	TargetName    string
	Outcome       string
	Reason        string
	CorrelationID string
	Detail        map[string]any
}

// NilTenant is the tenant recorded for platform-scope audit events.
const NilTenant = "00000000-0000-0000-0000-000000000000"

// Clusters is the registration surface. Deleting a cluster cascades to its
// tokens, snapshots (and their links), mappings, managed users, cursor,
// deliveries and cluster-scoped alert rules; drafts keep their row with the
// registered cluster cleared.
type Clusters interface {
	// CreateCluster inserts c; ErrConflict when the display name is taken in the tenant.
	CreateCluster(ctx context.Context, c Cluster) error
	GetCluster(ctx context.Context, tenantID, id string) (Cluster, error)
	// ListClusters returns the tenant's clusters by display name.
	ListClusters(ctx context.Context, tenantID string) ([]Cluster, error)
	// UpdateCluster writes every mutable field (and updated_at); the stored row is returned.
	UpdateCluster(ctx context.Context, c Cluster) (Cluster, error)
	DeleteCluster(ctx context.Context, tenantID, id string) error
	// AllClusters lists every tenant's clusters (system scope: workers).
	AllClusters(ctx context.Context) ([]Cluster, error)
}

// JoinTokens is the join-token metadata surface.
type JoinTokens interface {
	CreateJoinToken(ctx context.Context, t JoinToken) error
	GetJoinToken(ctx context.Context, tenantID, id string) (JoinToken, error)
	// ListJoinTokens returns the cluster's tokens, newest first.
	ListJoinTokens(ctx context.Context, tenantID, clusterID string) ([]JoinToken, error)
	// RevokeJoinToken sets revoked_at (ErrNotFound when absent).
	RevokeJoinToken(ctx context.Context, tenantID, id string, at time.Time) error
	// PruneJoinTokens deletes tokens that expired before the cut-off (system scope).
	PruneJoinTokens(ctx context.Context, before time.Time) (int, error)
	// PruneTenantJoinTokens deletes tenantID's tokens that expired before the
	// cut-off (the teleport:token-gc task).
	PruneTenantJoinTokens(ctx context.Context, tenantID string, before time.Time) (int, error)
}

// Snapshots is the resource-snapshot surface.
type Snapshots interface {
	// UpsertSnapshot inserts or replaces the row keyed by (cluster, kind,
	// teleport_name), keeping the existing id; the stored row is returned.
	UpsertSnapshot(ctx context.Context, s ResourceSnapshot) (ResourceSnapshot, error)
	GetSnapshot(ctx context.Context, tenantID, id string) (ResourceSnapshot, error)
	ListSnapshots(ctx context.Context, tenantID, clusterID string) ([]ResourceSnapshot, error)
	// FindSnapshots returns the tenant's snapshots (all clusters) whose
	// hostname equals hostname (case-insensitively) or whose address host is
	// ip; an empty argument matches nothing.
	FindSnapshots(ctx context.Context, tenantID, hostname, ip string) ([]ResourceSnapshot, error)
	// DeleteSnapshot removes the row (its links cascade).
	DeleteSnapshot(ctx context.Context, tenantID, id string) error
}

// Links is the resource-link surface.
type Links interface {
	// CreateLink inserts l; ErrConflict on (snapshot, target_module, target_id);
	// ErrNotFound when the snapshot is missing in the tenant.
	CreateLink(ctx context.Context, l ResourceLink) error
	GetLink(ctx context.Context, tenantID, id string) (ResourceLink, error)
	ListLinks(ctx context.Context, tenantID, snapshotID string) ([]ResourceLink, error)
	// ListClusterLinks returns the links of every snapshot of the cluster.
	ListClusterLinks(ctx context.Context, tenantID, clusterID string) ([]ResourceLink, error)
	// ListLinksByTarget returns the tenant's links to the given records of
	// one module (inventory or asset).
	ListLinksByTarget(ctx context.Context, tenantID, targetModule string, targetIDs []string) ([]ResourceLink, error)
	UpdateLink(ctx context.Context, l ResourceLink) (ResourceLink, error)
	DeleteLink(ctx context.Context, tenantID, id string) error
}

// Mappings is the role-mapping surface.
type Mappings interface {
	// CreateMapping inserts m; ErrConflict on (cluster, subject_kind, subject_ref).
	CreateMapping(ctx context.Context, m RoleMapping) error
	GetMapping(ctx context.Context, tenantID, id string) (RoleMapping, error)
	ListMappings(ctx context.Context, tenantID, clusterID string) ([]RoleMapping, error)
	UpdateMapping(ctx context.Context, m RoleMapping) (RoleMapping, error)
	DeleteMapping(ctx context.Context, tenantID, id string) error
}

// ManagedUsers is the managed-user surface.
type ManagedUsers interface {
	// CreateManagedUser inserts u; ErrConflict on (cluster, tangra_user_id) or
	// (cluster, teleport_username).
	CreateManagedUser(ctx context.Context, u ManagedUser) error
	GetManagedUser(ctx context.Context, tenantID, id string) (ManagedUser, error)
	ListManagedUsers(ctx context.Context, tenantID, clusterID string) ([]ManagedUser, error)
	UpdateManagedUser(ctx context.Context, u ManagedUser) (ManagedUser, error)
	DeleteManagedUser(ctx context.Context, tenantID, id string) error
}

// AlertRules is the alert-rule surface.
type AlertRules interface {
	CreateAlertRule(ctx context.Context, r AlertRule) error
	GetAlertRule(ctx context.Context, tenantID, id string) (AlertRule, error)
	ListAlertRules(ctx context.Context, tenantID string) ([]AlertRule, error)
	UpdateAlertRule(ctx context.Context, r AlertRule) (AlertRule, error)
	DeleteAlertRule(ctx context.Context, tenantID, id string) error
}

// AlertState is the alert poller's cursor and de-duplication surface.
type AlertState interface {
	GetAlertCursor(ctx context.Context, tenantID, clusterID string) (AlertCursor, error)
	// PutAlertCursor upserts the cluster's cursor (ErrNotFound when the cluster is missing).
	PutAlertCursor(ctx context.Context, c AlertCursor) error
	// RecordDelivery inserts d; ErrConflict when (rule, cluster, window) was delivered.
	RecordDelivery(ctx context.Context, d AlertDelivery) error
	// ReleaseDelivery removes the (rule, cluster, window) record again, so a
	// delivery that could not be sent is retried (ErrNotFound when absent).
	ReleaseDelivery(ctx context.Context, tenantID, ruleID, clusterID, windowKey string) error
	// PruneDeliveries deletes deliveries older than the cut-off (system scope).
	PruneDeliveries(ctx context.Context, before time.Time) (int, error)
	// PruneTenantDeliveries deletes tenantID's deliveries older than the
	// cut-off (the teleport:token-gc task).
	PruneTenantDeliveries(ctx context.Context, tenantID string, before time.Time) (int, error)
}

// Drafts is the deployment-draft surface.
type Drafts interface {
	CreateDraft(ctx context.Context, d DeploymentDraft) error
	GetDraft(ctx context.Context, tenantID, id string) (DeploymentDraft, error)
	ListDrafts(ctx context.Context, tenantID string) ([]DeploymentDraft, error)
	UpdateDraft(ctx context.Context, d DeploymentDraft) (DeploymentDraft, error)
	DeleteDraft(ctx context.Context, tenantID, id string) error
}

// Enrollments is the inventory-agent enrollment surface (spec 002).
type Enrollments interface {
	CreateEnrollment(ctx context.Context, e Enrollment) error
	GetEnrollment(ctx context.Context, tenantID, id string) (Enrollment, error)
	// ListEnrollments returns the cluster's enrollments, newest first.
	ListEnrollments(ctx context.Context, tenantID, clusterID string) ([]Enrollment, error)
	// UpdateEnrollment writes state, reason, item, node uuid, link and
	// updated_at (ErrNotFound when absent).
	UpdateEnrollment(ctx context.Context, e Enrollment) (Enrollment, error)
	// AddEnrollmentRender counts one render if fewer than max were made
	// (ErrConflict when the budget is spent, ErrNotFound when absent).
	AddEnrollmentRender(ctx context.Context, tenantID, id string, max int) (Enrollment, error)
	// ListActiveEnrollments returns every tenant's enrollments the sweep
	// still follows: non-final ones, and joined ones not yet linked that
	// have not expired; least recently updated first (system scope).
	ListActiveEnrollments(ctx context.Context, limit int) ([]Enrollment, error)
}

// Store is the full persistence contract.
type Store interface {
	Clusters
	JoinTokens
	Snapshots
	Links
	Mappings
	ManagedUsers
	AlertRules
	AlertState
	Drafts
	Enrollments
	// AppendAudit persists an audit row (system scope).
	AppendAudit(ctx context.Context, row AuditRow) error
	// ListAudit returns one page of the tenant's audit rows and the total
	// matching q.
	ListAudit(ctx context.Context, tenantID string, q AuditQuery) ([]AuditRow, int, error)
}

// AuditQuery filters and pages the module audit trail ("" = any; rows are
// ordered by time, newest first unless Ascending).
type AuditQuery struct {
	ClusterID string
	Action    string
	Outcome   string
	From, To  time.Time // zero = unbounded
	Ascending bool
	Offset    int
	Limit     int // 0 = 50
}
