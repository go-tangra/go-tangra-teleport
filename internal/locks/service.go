// Package locks is the lock part of US2 (FR-012, FR-013): list a cluster's
// active locks, lock a user, role or server with a mandatory reason and an
// optional expiry, and remove a lock. Locks are the incident-response
// control (Teleport enforces them on live sessions, SC-004); US5
// provisioning reuses Create and Remove to suspend de-provisioned users.
//
// A lock that would cut off the cluster's management identity is refused:
// the identity itself (clusters.GuardSelfIdentity) and any role it holds
// (clusters.GuardManagementRole). The identity's roles are read from
// Teleport at the time of the lock; when they cannot be read the lock is
// refused (fail closed). The reason becomes the Teleport lock message; the
// tangra author is kept in the lock's tangra.io/created-by label. Every
// change and every refused change is audited and published.
package locks

import (
	"context"
	"slices"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// MaxReason bounds a lock reason (contracts/http-api.md).
const MaxReason = 256

// NamePrefix starts the name of every lock tangra creates.
const NamePrefix = "tangra-"

// Service manages a cluster's locks. Clusters is required; the others may
// be nil.
type Service struct {
	Clusters *clusters.Service
	Audit    audit.Recorder
	Events   events.Publisher
	Cache    *teleportapi.Cache
	Now      func() time.Time
	// NewName names a new lock (default NamePrefix + a UUIDv7).
	NewName func() string
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) newName() string {
	if s.NewName != nil {
		return s.NewName()
	}
	return NamePrefix + store.NewID()
}

// Target is what a lock applies to: exactly one field is set.
type Target struct {
	User     string `json:"user,omitempty"`
	Role     string `json:"role,omitempty"`
	ServerID string `json:"server_id,omitempty"`
}

// View is an active lock.
type View struct {
	Name       string     `json:"name"`
	TargetKind string     `json:"target_kind"`
	Target     Target     `json:"target"`
	Message    string     `json:"message"`
	CreatedBy  string     `json:"created_by"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// Page lists the active locks.
type Page struct {
	Items []View `json:"items"`
}

// CreateInput is the POST body.
type CreateInput struct {
	TargetKind string     `json:"target_kind"`
	Target     string     `json:"target"`
	Reason     string     `json:"reason"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

func viewOf(l teleportapi.Lock) View {
	v := View{Name: l.Name, TargetKind: l.TargetKind, Message: l.Message, CreatedBy: l.CreatedBy}
	switch l.TargetKind {
	case teleportapi.LockTargetUser:
		v.Target.User = l.Target
	case teleportapi.LockTargetRole:
		v.Target.Role = l.Target
	case teleportapi.LockTargetServerID:
		v.Target.ServerID = l.Target
	}
	if !l.ExpiresAt.IsZero() {
		t := l.ExpiresAt.UTC()
		v.ExpiresAt = &t
	}
	return v
}

func (s *Service) active(ctx context.Context, c repo.Cluster, cl teleportapi.Client) ([]teleportapi.Lock, error) {
	ls, err := teleportapi.Cached(ctx, s.Cache, c.TenantID, c.ID, "locks", cl.ListLocks)
	if err != nil {
		return nil, err
	}
	now := s.now()
	return slices.DeleteFunc(ls, func(l teleportapi.Lock) bool { return !l.ExpiresAt.IsZero() && !l.ExpiresAt.After(now) }), nil
}

// List returns the cluster's locks in force (locks:read).
func (s *Service) List(ctx context.Context, clusterID string) (Page, error) {
	c, cl, err := s.Clusters.Client(ctx, clusterID, authz.LocksRead)
	if err != nil {
		return Page{}, err
	}
	ls, err := s.active(ctx, c, cl)
	if err != nil {
		return Page{}, err
	}
	out := Page{Items: make([]View, 0, len(ls))}
	for _, l := range ls {
		out.Items = append(out.Items, viewOf(l))
	}
	return out, nil
}

func (s *Service) writable(ctx context.Context, clusterID string) (repo.Cluster, teleportapi.Client, error) {
	c, cl, err := s.Clusters.Client(ctx, clusterID, authz.LocksManage)
	if err != nil {
		return c, nil, err
	}
	return c, cl, clusters.Writable(c)
}

func (s *Service) validate(in CreateInput) (teleportapi.Lock, error) {
	if !slices.Contains(teleportapi.LockTargetKinds, in.TargetKind) {
		return teleportapi.Lock{}, &clusters.FieldError{Field: "target_kind", Msg: "must be user, role or server_id"}
	}
	if err := clusters.ValidName("target", in.Target); err != nil {
		return teleportapi.Lock{}, err
	}
	reason, err := clusters.ValidText("reason", in.Reason, MaxReason)
	if err != nil {
		return teleportapi.Lock{}, err
	}
	l := teleportapi.Lock{TargetKind: in.TargetKind, Target: in.Target, Message: reason}
	if in.ExpiresAt != nil {
		if !in.ExpiresAt.After(s.now()) {
			return teleportapi.Lock{}, &clusters.FieldError{Field: "expires_at", Msg: "must be in the future"}
		}
		l.ExpiresAt = in.ExpiresAt.UTC()
	}
	return l, nil
}

// guard refuses a lock that would affect the management identity.
func guard(ctx context.Context, c repo.Cluster, cl teleportapi.Client, l teleportapi.Lock) error {
	switch l.TargetKind {
	case teleportapi.LockTargetUser:
		if clusters.IsManagementIdentity(c, l.Target) {
			return &clusters.GuardError{Guard: clusters.GuardSelfIdentity,
				Msg: "this is the cluster's management identity; locking it would cut the platform off the cluster"}
		}
	case teleportapi.LockTargetRole:
		mgmt, err := clusters.ManagementIdentity(ctx, c, cl)
		if err != nil {
			return err
		}
		if slices.Contains(mgmt.Roles, l.Target) {
			return &clusters.GuardError{Guard: clusters.GuardManagementRole,
				Msg: "the cluster's management identity holds this role; locking it would cut the platform off the cluster"}
		}
	}
	return nil
}

// Create locks a user, role or server (locks:manage).
func (s *Service) Create(ctx context.Context, clusterID string, in CreateInput) (v View, err error) {
	c, cl, err := s.writable(ctx, clusterID)
	if c.ID == "" {
		return View{}, err
	}
	var l teleportapi.Lock
	defer func() {
		clusters.Audit(ctx, s.Audit, audit.LockCreate, audit.TargetLock, c.ID, l.Name, err,
			map[string]any{"target_kind": in.TargetKind, "target": in.Target})
	}()
	if err != nil {
		return View{}, err
	}
	if l, err = s.validate(in); err != nil {
		return View{}, err
	}
	if err := guard(ctx, c, cl, l); err != nil {
		return View{}, err
	}
	subj, _ := authz.FromContext(ctx)
	l.Name, l.CreatedBy = s.newName(), subj.ActorID()
	if err := cl.UpsertLock(ctx, l); err != nil {
		return View{}, err
	}
	_ = s.Cache.Invalidate(ctx, c.TenantID, c.ID)
	events.Emit(ctx, s.Events, c.TenantID, events.LockCreated, events.Lock{ClusterID: c.ID, LockName: l.Name, TargetKind: l.TargetKind})
	return viewOf(l), nil
}

// Remove deletes a lock (locks:manage). Unlocking is never guarded.
func (s *Service) Remove(ctx context.Context, clusterID, name string) (err error) {
	c, cl, err := s.writable(ctx, clusterID)
	if c.ID == "" {
		return err
	}
	kind := ""
	defer func() {
		clusters.Audit(ctx, s.Audit, audit.LockDelete, audit.TargetLock, c.ID, name, err, map[string]any{"target_kind": kind})
	}()
	if err != nil {
		return err
	}
	if err := clusters.ValidName("name", name); err != nil {
		return err
	}
	ls, err := cl.ListLocks(ctx)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(ls, func(l teleportapi.Lock) bool { return l.Name == name })
	if i < 0 {
		return teleportapi.ErrNotFound
	}
	kind = ls[i].TargetKind
	if err := cl.DeleteLock(ctx, name); err != nil {
		return err
	}
	_ = s.Cache.Invalidate(ctx, c.TenantID, c.ID)
	events.Emit(ctx, s.Events, c.TenantID, events.LockRemoved, events.Lock{ClusterID: c.ID, LockName: name, TargetKind: kind})
	return nil
}
