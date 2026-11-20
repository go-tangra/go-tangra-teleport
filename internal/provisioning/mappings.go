// Package provisioning is US5 (FR-026…029, research D10): per-cluster
// mappings from tangra module roles or groups to Teleport roles and logins,
// and the reconciler that provisions matching tangra members as managed
// Teleport users, keeps their roles and logins in line with the mappings,
// locks them when they leave the tenant or lose every mapped role, and
// deletes them once the grace period (default 7 days) has passed.
//
// Managed users carry the labels tangra.io/managed, tangra.io/tenant and
// tangra.io/user (users.Label*). The module only ever writes a Teleport user
// that carries all three for the expected tenant and tangra user: users it
// did not create (unmanaged users, the management identity) are never
// changed (FR-029). Before any lock or delete the member is re-read from
// auth (SR-006), so a stale or forged removal changes nothing. Invites go to
// the tangra user through notification (teleport.invite); the link exists
// only in that message and is never logged, stored, published or audited.
//
// Auth publishes no membership events (research D10, T010): the periodic
// sync (teleport:sync-provisioning, Phase 9) calls Reconcile, and the purge
// task calls PurgeDeprovisioned. Mapping changes need provisioning:manage
// (administrators only, SR-005); reads need users:read.
package provisioning

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/locks"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/users"
)

// Bounds and defaults (data-model role_mapping, managed_user).
const (
	MaxMappingRoles  = 16
	MaxMappingLogins = 32
	DefaultGrace     = 7 * 24 * time.Hour
	// WorkerName is the actor of runs without a caller (scheduler tasks).
	WorkerName = "provisioning-sync"
	// LockReason is the message of a de-provisioning lock.
	LockReason = "tangra de-provisioned"
	// StateDeleted is the state published when a managed user is removed.
	StateDeleted = "deleted"
)

// loginPattern is a POSIX-style login: no leading dash, no shell metacharacters.
var loginPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]{0,31}$`)

// Service is the provisioning surface. Clusters, Repo, Users and Locks are
// required; a nil Membership is Unavailable; the others may be nil.
type Service struct {
	Clusters   *clusters.Service
	Repo       repo.Store
	Users      *users.Service
	Locks      *locks.Service
	Membership Membership
	Notify     notify.Notifier
	Audit      audit.Recorder
	Events     events.Publisher
	Log        *slog.Logger
	Grace      time.Duration // lock-to-delete period (DefaultGrace)
	Now        func() time.Time

	mu      sync.Mutex
	running map[string]*sync.Mutex // one run per cluster at a time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Log
}

func (s *Service) grace() time.Duration {
	if s.Grace <= 0 {
		return DefaultGrace
	}
	return s.Grace
}

func (s *Service) membership() Membership {
	if s.Membership == nil {
		return Unavailable{}
	}
	return s.Membership
}

// clusterLock serialises runs on one cluster within this replica.
func (s *Service) clusterLock(id string) func() {
	s.mu.Lock()
	if s.running == nil {
		s.running = map[string]*sync.Mutex{}
	}
	m, ok := s.running[id]
	if !ok {
		m = &sync.Mutex{}
		s.running[id] = m
	}
	s.mu.Unlock()
	m.Lock()
	return m.Unlock
}

// ReasonOf is the audit reason of a provisioning failure (closed vocabulary).
func ReasonOf(err error) string {
	switch {
	case errors.Is(err, ErrMembershipUnavailable), errors.Is(err, notify.ErrUnavailable), errors.Is(err, notify.ErrNotDelivered):
		return "dependency_unavailable"
	}
	return clusters.ReasonOf(err)
}

// record audits one action for the caller in ctx with the provisioning reasons.
func (s *Service) record(ctx context.Context, a audit.Action, kind, clusterID, target string, err error, details map[string]any) {
	subj, _ := authz.FromContext(ctx)
	e := audit.FromSubjects(subj, a, kind, target, audit.OutcomeSuccess)
	e.ClusterID, e.Details = clusterID, details
	if err != nil {
		e.Outcome, e.Reason = audit.OutcomeFailure, ReasonOf(err)
	}
	audit.Emit(ctx, s.Audit, e)
}

// ---- mappings

// MappingInput is the POST body.
type MappingInput struct {
	SubjectKind   string   `json:"subject_kind"`
	SubjectRef    string   `json:"subject_ref"`
	TeleportRoles []string `json:"teleport_roles"`
	Logins        []string `json:"logins,omitempty"`
}

// MappingUpdate is the PUT body: the subject of a mapping cannot change.
type MappingUpdate struct {
	TeleportRoles []string `json:"teleport_roles"`
	Logins        []string `json:"logins,omitempty"`
}

// MappingView is a mapping as the API returns it.
type MappingView struct {
	ID            string    `json:"id"`
	ClusterID     string    `json:"cluster_id"`
	SubjectKind   string    `json:"subject_kind"`
	SubjectRef    string    `json:"subject_ref"`
	TeleportRoles []string  `json:"teleport_roles"`
	Logins        []string  `json:"logins"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// MappingPage lists a cluster's mappings.
type MappingPage struct {
	Items []MappingView `json:"items"`
}

func mappingView(m repo.RoleMapping) MappingView {
	v := MappingView{ID: m.ID, ClusterID: m.ClusterID, SubjectKind: m.SubjectKind, SubjectRef: m.SubjectRef,
		TeleportRoles: slices.Clone(m.TeleportRoles), Logins: slices.Clone(m.Logins), CreatedBy: m.CreatedBy,
		CreatedAt: m.CreatedAt.UTC(), UpdatedAt: m.UpdatedAt.UTC()}
	if v.TeleportRoles == nil {
		v.TeleportRoles = []string{}
	}
	if v.Logins == nil {
		v.Logins = []string{}
	}
	return v
}

func validLogins(in []string) ([]string, error) {
	if len(in) > MaxMappingLogins {
		return nil, &clusters.FieldError{Field: "logins", Msg: "must list at most " + strconv.Itoa(MaxMappingLogins) + " entries"}
	}
	out := make([]string, 0, len(in))
	for _, l := range in {
		if !loginPattern.MatchString(l) {
			return nil, &clusters.FieldError{Field: "logins", Msg: "each login must be 1 to 32 letters, digits or . _ - and start with a letter or _"}
		}
		if !slices.Contains(out, l) {
			out = append(out, l)
		}
	}
	return out, nil
}

// validRoles checks the role names and that each exists on the cluster.
func validRoles(ctx context.Context, cl teleportapi.Client, in []string) ([]string, error) {
	rs, err := clusters.ValidNames("teleport_roles", in, 1, MaxMappingRoles)
	if err != nil {
		return nil, err
	}
	if err := users.RolesExist(ctx, cl, rs); err != nil {
		var fe *clusters.FieldError
		if errors.As(err, &fe) {
			return nil, &clusters.FieldError{Field: "teleport_roles", Msg: fe.Msg}
		}
		return nil, err
	}
	return rs, nil
}

func validSubject(kind, ref string) error {
	if kind != repo.SubjectModuleRole && kind != repo.SubjectGroup {
		return &clusters.FieldError{Field: "subject_kind", Msg: "must be module_role or group"}
	}
	if err := clusters.ValidName("subject_ref", ref); err != nil {
		return err
	}
	return nil
}

// writable opens the cluster for a mapping change (provisioning:manage).
func (s *Service) writable(ctx context.Context, clusterID string) (repo.Cluster, teleportapi.Client, error) {
	c, cl, err := s.Clusters.Client(ctx, clusterID, authz.ProvisioningManage)
	if err != nil {
		return c, nil, err
	}
	return c, cl, clusters.Writable(c)
}

// ListMappings returns the cluster's mappings (users:read).
func (s *Service) ListMappings(ctx context.Context, clusterID string) (MappingPage, error) {
	c, err := s.Clusters.Authz.RequireCluster(ctx, clusterID, authz.UsersRead)
	if err != nil {
		return MappingPage{}, err
	}
	ms, err := s.Repo.ListMappings(ctx, c.TenantID, c.ID)
	if err != nil {
		return MappingPage{}, err
	}
	out := MappingPage{Items: make([]MappingView, 0, len(ms))}
	for _, m := range ms {
		out.Items = append(out.Items, mappingView(m))
	}
	return out, nil
}

// CreateMapping adds a mapping; every Teleport role must exist on the
// cluster (provisioning:manage).
func (s *Service) CreateMapping(ctx context.Context, clusterID string, in MappingInput) (v MappingView, err error) {
	c, cl, err := s.writable(ctx, clusterID)
	if c.ID == "" {
		return MappingView{}, err
	}
	defer func() {
		s.record(ctx, audit.MappingCreate, audit.TargetMapping, c.ID, in.SubjectKind+":"+in.SubjectRef, err,
			map[string]any{"teleport_roles": v.TeleportRoles, "logins": v.Logins})
	}()
	if err != nil {
		return MappingView{}, err
	}
	if err := validSubject(in.SubjectKind, in.SubjectRef); err != nil {
		return MappingView{}, err
	}
	logins, err := validLogins(in.Logins)
	if err != nil {
		return MappingView{}, err
	}
	roles, err := validRoles(ctx, cl, in.TeleportRoles)
	if err != nil {
		return MappingView{}, err
	}
	subj, _ := authz.FromContext(ctx)
	now := s.now()
	m := repo.RoleMapping{ID: store.NewID(), TenantID: c.TenantID, ClusterID: c.ID, SubjectKind: in.SubjectKind, SubjectRef: in.SubjectRef,
		TeleportRoles: roles, Logins: logins, CreatedBy: subj.ActorID(), CreatedAt: now, UpdatedAt: now}
	if err := s.Repo.CreateMapping(ctx, m); err != nil {
		return MappingView{}, err
	}
	return mappingView(m), nil
}

// mapping loads a mapping of the cluster (another cluster's id is not found).
func (s *Service) mapping(ctx context.Context, c repo.Cluster, id string) (repo.RoleMapping, error) {
	m, err := s.Repo.GetMapping(ctx, c.TenantID, id)
	if err != nil {
		return repo.RoleMapping{}, err
	}
	if m.ClusterID != c.ID {
		return repo.RoleMapping{}, repo.ErrNotFound
	}
	return m, nil
}

// UpdateMapping replaces a mapping's roles and logins (provisioning:manage).
func (s *Service) UpdateMapping(ctx context.Context, clusterID, id string, in MappingUpdate) (v MappingView, err error) {
	c, cl, err := s.writable(ctx, clusterID)
	if c.ID == "" {
		return MappingView{}, err
	}
	defer func() {
		s.record(ctx, audit.MappingUpdate, audit.TargetMapping, c.ID, id, err, map[string]any{"teleport_roles": v.TeleportRoles, "logins": v.Logins})
	}()
	if err != nil {
		return MappingView{}, err
	}
	m, err := s.mapping(ctx, c, id)
	if err != nil {
		return MappingView{}, err
	}
	if m.Logins, err = validLogins(in.Logins); err != nil {
		return MappingView{}, err
	}
	if m.TeleportRoles, err = validRoles(ctx, cl, in.TeleportRoles); err != nil {
		return MappingView{}, err
	}
	updated, err := s.Repo.UpdateMapping(ctx, m)
	if err != nil {
		return MappingView{}, err
	}
	return mappingView(updated), nil
}

// DeleteMapping removes a mapping (provisioning:manage). Users it provisioned
// are locked at the next sync when no other mapping matches them.
func (s *Service) DeleteMapping(ctx context.Context, clusterID, id string) (err error) {
	c, err := s.Clusters.Authz.RequireCluster(ctx, clusterID, authz.ProvisioningManage)
	if err != nil {
		return err
	}
	defer func() { s.record(ctx, audit.MappingDelete, audit.TargetMapping, c.ID, id, err, nil) }()
	if _, err := s.mapping(ctx, c, id); err != nil {
		return err
	}
	return s.Repo.DeleteMapping(ctx, c.TenantID, id)
}
