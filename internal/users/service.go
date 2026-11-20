// Package users is the Teleport-user part of US2 (FR-007, FR-008, FR-013,
// FR-014): list a cluster's users with their managed and locked flags,
// create one with roles and logins and a one-time invite link, update its
// roles and logins against the revision read, issue a reset link and
// delete it. US5 provisioning reuses Create (with labels), Update and
// Delete.
//
// Invite and reset URLs exist only as secrets.OneTime in the result of the
// call that issued them (SR-002): they are not logged, cached, published,
// audited or stored. The cluster's management identity can be neither
// changed, reset nor deleted (clusters.GuardSelfIdentity). Every change and
// every refused change is audited; changes are published as
// teleport.user.* events and invalidate the cluster's read cache.
package users

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// Labels of users tangra provisions (research D8, US5).
const (
	LabelManaged = "tangra.io/managed"
	LabelTenant  = "tangra.io/tenant"
	LabelUser    = "tangra.io/user"
)

// Bounds.
const (
	DefaultPageSize = 100
	MaxPageSize     = 200
	MaxRoles        = 32
	MaxLogins       = 32
	maxQuery        = 128
)

// Service manages a cluster's Teleport users. Clusters is required; the
// others may be nil (nothing is audited, published or cached).
type Service struct {
	Clusters *clusters.Service
	Audit    audit.Recorder
	Events   events.Publisher
	Cache    *teleportapi.Cache
	// InviteTTL and ResetTTL bound the one-time links (0: the cluster's
	// default, 1 hour for invites and 8 hours for resets in Teleport 19).
	InviteTTL time.Duration
	ResetTTL  time.Duration
	Now       func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// View is a Teleport user as the API returns it (never a secret).
type View struct {
	Name         string     `json:"name"`
	Roles        []string   `json:"roles"`
	Logins       []string   `json:"logins"`
	Created      *time.Time `json:"created,omitempty"`
	Managed      bool       `json:"managed"`
	TangraUserID string     `json:"tangra_user_id,omitempty"`
	Locked       bool       `json:"locked"`
	Revision     string     `json:"revision"`
}

// Page is one page of users (opaque Next cursor).
type Page struct {
	Items []View `json:"items"`
	Next  string `json:"next,omitempty"`
}

// ListInput filters and pages a list. Q matches names (case-insensitive)
// within the page read from Teleport.
type ListInput struct {
	Q     string
	Next  string
	Limit int
}

// CreateInput is the POST body. Labels are set by provisioning only.
type CreateInput struct {
	Name   string            `json:"name"`
	Roles  []string          `json:"roles"`
	Logins []string          `json:"logins,omitempty"`
	Labels map[string]string `json:"-"`
}

// UpdateInput is the PUT body; Revision is the one read.
type UpdateInput struct {
	Roles    []string `json:"roles"`
	Logins   []string `json:"logins,omitempty"`
	Revision string   `json:"revision"`
}

// Created is the create result: the invite URL appears here only.
type Created struct {
	User            View            `json:"user"`
	InviteURL       secrets.OneTime `json:"invite_url"`
	InviteExpiresAt time.Time       `json:"invite_expires_at"`
}

// ResetLink is the reset result: the reset URL appears here only.
type ResetLink struct {
	ResetURL  secrets.OneTime `json:"reset_url"`
	ExpiresAt time.Time       `json:"expires_at"`
}

func viewOf(u teleportapi.User, locked bool) View {
	v := View{Name: u.Name, Roles: u.Roles, Logins: u.Logins, Revision: u.Revision, Locked: locked,
		Managed: u.Labels[LabelManaged] == "true", TangraUserID: u.Labels[LabelUser]}
	if v.Roles == nil {
		v.Roles = []string{}
	}
	if v.Logins == nil {
		v.Logins = []string{}
	}
	if !u.Created.IsZero() {
		t := u.Created.UTC()
		v.Created = &t
	}
	return v
}

func (s *Service) record(ctx context.Context, a audit.Action, clusterID, name string, err error, details map[string]any) {
	clusters.Audit(ctx, s.Audit, a, audit.TargetUser, clusterID, name, err, details)
}

func (s *Service) changed(ctx context.Context, c repo.Cluster, eventType, name string) {
	_ = s.Cache.Invalidate(ctx, c.TenantID, c.ID)
	events.Emit(ctx, s.Events, c.TenantID, eventType, events.User{ClusterID: c.ID, Username: name})
}

// lockedUsers names the users with a lock in force.
func (s *Service) lockedUsers(ctx context.Context, c repo.Cluster, cl teleportapi.Client) (map[string]bool, error) {
	ls, err := teleportapi.Cached(ctx, s.Cache, c.TenantID, c.ID, "locks", cl.ListLocks)
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := map[string]bool{}
	for _, l := range ls {
		if l.TargetKind == teleportapi.LockTargetUser && (l.ExpiresAt.IsZero() || l.ExpiresAt.After(now)) {
			out[l.Target] = true
		}
	}
	return out, nil
}

// List returns one page of the cluster's users (users:read).
func (s *Service) List(ctx context.Context, clusterID string, in ListInput) (Page, error) {
	c, cl, err := s.Clusters.Client(ctx, clusterID, authz.UsersRead)
	if err != nil {
		return Page{}, err
	}
	limit := in.Limit
	if limit <= 0 || limit > MaxPageSize {
		limit = DefaultPageSize
	}
	q := strings.ToLower(strings.TrimSpace(in.Q))
	if len(q) > maxQuery {
		return Page{}, &clusters.FieldError{Field: "q", Msg: "must be at most 128 characters"}
	}
	o := teleportapi.ListOptions{Limit: limit, Next: in.Next}
	page, err := teleportapi.Cached(ctx, s.Cache, c.TenantID, c.ID, "users:"+in.Next+":"+strconv.Itoa(limit),
		func(ctx context.Context) (teleportapi.Page[teleportapi.User], error) { return cl.ListUsers(ctx, o) })
	if err != nil {
		return Page{}, err
	}
	locked, err := s.lockedUsers(ctx, c, cl)
	if err != nil {
		return Page{}, err
	}
	out := Page{Items: []View{}, Next: page.Next}
	for _, u := range page.Items {
		if q != "" && !strings.Contains(strings.ToLower(u.Name), q) {
			continue
		}
		out.Items = append(out.Items, viewOf(u, locked[u.Name]))
	}
	return out, nil
}

// writable resolves the cluster for a write (users:manage).
func (s *Service) writable(ctx context.Context, clusterID string) (repo.Cluster, teleportapi.Client, error) {
	c, cl, err := s.Clusters.Client(ctx, clusterID, authz.UsersManage)
	if err != nil {
		return c, nil, err
	}
	return c, cl, clusters.Writable(c)
}

// RolesExist refuses roles the cluster does not have (US5 mappings reuse it).
func RolesExist(ctx context.Context, cl teleportapi.Client, roles []string) error {
	for _, r := range roles {
		if _, err := cl.GetRole(ctx, r); err != nil {
			if teleportapi.Reason(err) == "not_found" {
				return &clusters.FieldError{Field: "roles", Msg: "role " + r + " does not exist on the cluster"}
			}
			return err
		}
	}
	return nil
}

func spec(name string, roles, logins []string) (teleportapi.UserSpec, error) {
	if err := clusters.ValidName("name", name); err != nil {
		return teleportapi.UserSpec{}, err
	}
	rs, err := clusters.ValidNames("roles", roles, 1, MaxRoles)
	if err != nil {
		return teleportapi.UserSpec{}, err
	}
	ls, err := clusters.ValidNames("logins", logins, 0, MaxLogins)
	if err != nil {
		return teleportapi.UserSpec{}, err
	}
	return teleportapi.UserSpec{Name: name, Roles: rs, Logins: ls}, nil
}

// Create creates a user and issues its invite link (users:manage). When the
// invite cannot be issued the user is deleted again.
func (s *Service) Create(ctx context.Context, clusterID string, in CreateInput) (out Created, err error) {
	c, cl, err := s.writable(ctx, clusterID)
	if err != nil {
		if c.ID != "" {
			s.record(ctx, audit.UserCreate, c.ID, in.Name, err, nil)
		}
		return Created{}, err
	}
	sp, err := spec(strings.TrimSpace(in.Name), in.Roles, in.Logins)
	defer func() {
		s.record(ctx, audit.UserCreate, c.ID, sp.Name, err, map[string]any{"roles": sp.Roles, "logins": sp.Logins})
	}()
	if err != nil {
		sp.Name = in.Name
		return Created{}, err
	}
	sp.Labels = in.Labels
	if err := RolesExist(ctx, cl, sp.Roles); err != nil {
		return Created{}, err
	}
	u, err := cl.CreateUser(ctx, sp)
	if err != nil {
		return Created{}, err
	}
	tok, err := cl.CreateUserToken(ctx, u.Name, teleportapi.UserTokenInvite, s.InviteTTL)
	if err != nil {
		_ = cl.DeleteUser(ctx, u.Name)
		_ = s.Cache.Invalidate(ctx, c.TenantID, c.ID)
		return Created{}, err
	}
	s.changed(ctx, c, events.UserCreated, u.Name)
	return Created{User: viewOf(u, false), InviteURL: secrets.NewOneTime(tok.URL), InviteExpiresAt: tok.ExpiresAt.UTC()}, nil
}

// guardSelf refuses any write to the management identity.
func guardSelf(c repo.Cluster, name string) error {
	if clusters.IsManagementIdentity(c, name) {
		return &clusters.GuardError{Guard: clusters.GuardSelfIdentity,
			Msg: "this is the cluster's management identity; change it with tctl on the cluster"}
	}
	return nil
}

// Update replaces a user's roles and logins if the revision is current
// (users:manage); a stale revision is teleportapi.ErrConflict.
func (s *Service) Update(ctx context.Context, clusterID, name string, in UpdateInput) (v View, err error) {
	c, cl, err := s.writable(ctx, clusterID)
	if c.ID == "" {
		return View{}, err
	}
	defer func() { s.record(ctx, audit.UserUpdate, c.ID, name, err, nil) }()
	if err != nil {
		return View{}, err
	}
	if err := guardSelf(c, name); err != nil {
		return View{}, err
	}
	sp, err := spec(name, in.Roles, in.Logins)
	if err != nil {
		return View{}, err
	}
	if strings.TrimSpace(in.Revision) == "" {
		return View{}, &clusters.FieldError{Field: "revision", Msg: "is required: send the revision you read"}
	}
	sp.Revision = in.Revision
	if err := RolesExist(ctx, cl, sp.Roles); err != nil {
		return View{}, err
	}
	u, err := cl.UpdateUser(ctx, sp)
	if err != nil {
		return View{}, err
	}
	s.changed(ctx, c, events.UserUpdated, name)
	locked, err := s.lockedUsers(ctx, c, cl)
	if err != nil {
		return viewOf(u, false), nil
	}
	return viewOf(u, locked[name]), nil
}

// Reset issues a reset link for a user's password and second factors
// (users:manage).
func (s *Service) Reset(ctx context.Context, clusterID, name string) (out ResetLink, err error) {
	c, cl, err := s.writable(ctx, clusterID)
	if c.ID == "" {
		return ResetLink{}, err
	}
	defer func() { s.record(ctx, audit.UserReset, c.ID, name, err, nil) }()
	if err != nil {
		return ResetLink{}, err
	}
	if err := guardSelf(c, name); err != nil {
		return ResetLink{}, err
	}
	if err := clusters.ValidName("name", name); err != nil {
		return ResetLink{}, err
	}
	tok, err := cl.CreateUserToken(ctx, name, teleportapi.UserTokenReset, s.ResetTTL)
	if err != nil {
		return ResetLink{}, err
	}
	s.changed(ctx, c, events.UserUpdated, name)
	return ResetLink{ResetURL: secrets.NewOneTime(tok.URL), ExpiresAt: tok.ExpiresAt.UTC()}, nil
}

// Delete deletes a user (users:manage).
func (s *Service) Delete(ctx context.Context, clusterID, name string) (err error) {
	c, cl, err := s.writable(ctx, clusterID)
	if c.ID == "" {
		return err
	}
	defer func() { s.record(ctx, audit.UserDelete, c.ID, name, err, nil) }()
	if err != nil {
		return err
	}
	if err := guardSelf(c, name); err != nil {
		return err
	}
	if err := clusters.ValidName("name", name); err != nil {
		return err
	}
	if err := cl.DeleteUser(ctx, name); err != nil {
		return err
	}
	s.changed(ctx, c, events.UserDeleted, name)
	return nil
}
