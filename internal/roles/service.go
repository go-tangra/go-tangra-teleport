// Package roles is the role part of US2 (FR-009, FR-010, FR-011, FR-013,
// FR-014): list a cluster's roles, read one as YAML, preview an edit
// (validation and a normalized diff, no side effects), create or update a
// role against the revision read, and delete one.
//
// Definitions are parsed and validated by roleyaml (research D6) before
// anything reaches Teleport. Teleport built-in roles cannot be deleted
// (clusters.GuardPresetRole), nor can a role the cluster's management
// identity holds (clusters.GuardManagementRole; the identity's roles are
// read at the time of the delete, and the guard fails closed). Changes are
// audited with SHA-256 hashes of the normalized definition before and
// after — never the YAML — and published as teleport.role.* events.
package roles

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/gravitational/teleport/api/types"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/roleyaml"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// Page sizes.
const (
	DefaultPageSize = 100
	MaxPageSize     = 200
)

// Service manages a cluster's roles. Clusters is required; the others may
// be nil.
type Service struct {
	Clusters *clusters.Service
	Audit    audit.Recorder
	Events   events.Publisher
	Cache    *teleportapi.Cache
}

// View is a role in a list.
type View struct {
	Name     string `json:"name"`
	Preset   bool   `json:"preset"`
	Revision string `json:"revision"`
}

// Page is one page of roles (opaque Next cursor).
type Page struct {
	Items []View `json:"items"`
	Next  string `json:"next,omitempty"`
}

// ListInput pages a list.
type ListInput struct {
	Next  string
	Limit int
}

// Definition is one role as normalized YAML.
type Definition struct {
	YAML     string `json:"yaml"`
	Revision string `json:"revision"`
	Preset   bool   `json:"preset"`
}

// PreviewInput is the preview body; Revision is the one read ("" for a new role).
type PreviewInput struct {
	YAML     string `json:"yaml"`
	Revision string `json:"revision,omitempty"`
}

// Preview is the validation result and the diff against the current role.
type Preview struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors"`
	Diff   string   `json:"diff"`
}

// PutInput is the PUT body: an empty Revision creates the role.
type PutInput struct {
	YAML     string `json:"yaml"`
	Revision string `json:"revision,omitempty"`
}

func viewOf(r teleportapi.Role) View {
	return View{Name: r.Name, Preset: r.Preset, Revision: r.Revision}
}

// List returns one page of roles (roles:read).
func (s *Service) List(ctx context.Context, clusterID string, in ListInput) (Page, error) {
	c, cl, err := s.Clusters.Client(ctx, clusterID, authz.RolesRead)
	if err != nil {
		return Page{}, err
	}
	limit := in.Limit
	if limit <= 0 || limit > MaxPageSize {
		limit = DefaultPageSize
	}
	o := teleportapi.ListOptions{Limit: limit, Next: in.Next}
	p, err := teleportapi.Cached(ctx, s.Cache, c.TenantID, c.ID, "roles:"+in.Next+":"+strconv.Itoa(limit),
		func(ctx context.Context) (teleportapi.Page[teleportapi.Role], error) { return cl.ListRoles(ctx, o) })
	if err != nil {
		return Page{}, err
	}
	out := Page{Items: make([]View, 0, len(p.Items)), Next: p.Next}
	for _, r := range p.Items {
		out.Items = append(out.Items, viewOf(r))
	}
	return out, nil
}

// Get returns one role as normalized YAML (roles:read).
func (s *Service) Get(ctx context.Context, clusterID, name string) (Definition, error) {
	_, cl, err := s.Clusters.Client(ctx, clusterID, authz.RolesRead)
	if err != nil {
		return Definition{}, err
	}
	if err := clusters.ValidName("name", name); err != nil {
		return Definition{}, err
	}
	r, err := cl.GetRoleDefinition(ctx, name)
	if err != nil {
		return Definition{}, err
	}
	y, err := roleyaml.Normalize(r)
	if err != nil {
		return Definition{}, err
	}
	return Definition{YAML: y, Revision: r.GetRevision(), Preset: roleyaml.IsPreset(r)}, nil
}

// current returns the existing role (nil when there is none).
func current(ctx context.Context, cl teleportapi.Client, name string) (*types.RoleV6, error) {
	r, err := cl.GetRoleDefinition(ctx, name)
	if teleportapi.Reason(err) == "not_found" {
		return nil, nil
	}
	return r, err
}

func normal(r *types.RoleV6) (string, error) {
	if r == nil {
		return "", nil
	}
	return roleyaml.Normalize(r)
}

// Preview validates a definition and diffs it against the current role
// (roles:manage). It changes nothing and records nothing: an invalid
// definition is a result, not a failure.
func (s *Service) Preview(ctx context.Context, clusterID string, in PreviewInput) (Preview, error) {
	_, cl, err := s.Clusters.Client(ctx, clusterID, authz.RolesManage)
	if err != nil {
		return Preview{}, err
	}
	r, err := roleyaml.Parse([]byte(in.YAML))
	if err != nil {
		var e *roleyaml.Error
		if !errors.As(err, &e) {
			return Preview{}, err
		}
		return Preview{Valid: false, Errors: []string{e.Msg}}, nil
	}
	cur, err := current(ctx, cl, r.GetName())
	if err != nil {
		return Preview{}, err
	}
	before, err := normal(cur)
	if err != nil {
		return Preview{}, err
	}
	after, err := roleyaml.Normalize(r)
	if err != nil {
		return Preview{}, err
	}
	out := Preview{Valid: true, Errors: []string{}, Diff: roleyaml.Diff(before, after)}
	switch {
	case cur == nil && in.Revision != "":
		out.Valid, out.Errors = false, []string{"the role no longer exists on the cluster; reload it"}
	case cur != nil && cur.GetRevision() != in.Revision && in.Revision != "":
		out.Valid, out.Errors = false, []string{"the role was changed on the cluster since it was read; reload it"}
	case cur != nil && in.Revision == "":
		out.Valid, out.Errors = false, []string{"a role with this name already exists; reload it to edit it"}
	}
	return out, nil
}

func digest(s string) string {
	if s == "" {
		return ""
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func (s *Service) changed(ctx context.Context, c repo.Cluster, eventType, name string) {
	_ = s.Cache.Invalidate(ctx, c.TenantID, c.ID)
	events.Emit(ctx, s.Events, c.TenantID, eventType, events.Role{ClusterID: c.ID, Role: name})
}

// Put creates the role (empty revision) or updates it if the revision read
// is current (roles:manage); a stale revision or an existing role on create
// is teleportapi.ErrConflict.
func (s *Service) Put(ctx context.Context, clusterID, name string, in PutInput) (v View, err error) {
	c, cl, err := s.Clusters.Client(ctx, clusterID, authz.RolesManage)
	if c.ID == "" {
		return View{}, err
	}
	action := audit.RoleUpdate
	if strings.TrimSpace(in.Revision) == "" {
		action = audit.RoleCreate
	}
	details := map[string]any{}
	defer func() { clusters.Audit(ctx, s.Audit, action, audit.TargetRole, c.ID, name, err, details) }()
	if err != nil {
		return View{}, err
	}
	if err := clusters.Writable(c); err != nil {
		return View{}, err
	}
	if err := clusters.ValidName("name", name); err != nil {
		return View{}, err
	}
	r, err := roleyaml.Parse([]byte(in.YAML))
	if err != nil {
		return View{}, err
	}
	if r.GetName() != name {
		return View{}, &clusters.FieldError{Field: "yaml", Msg: "metadata.name must be " + name}
	}
	after, err := roleyaml.Normalize(r)
	if err != nil {
		return View{}, err
	}
	details["after_sha256"] = digest(after)
	var out teleportapi.Role
	if action == audit.RoleCreate {
		out, err = cl.CreateRole(ctx, r)
	} else {
		cur, gerr := cl.GetRoleDefinition(ctx, name)
		if gerr != nil {
			return View{}, gerr
		}
		if before, nerr := roleyaml.Normalize(cur); nerr == nil {
			details["before_sha256"] = digest(before)
		}
		r.SetRevision(in.Revision)
		out, err = cl.UpdateRole(ctx, r)
	}
	if err != nil {
		return View{}, err
	}
	s.changed(ctx, c, events.RoleChanged, name)
	return viewOf(out), nil
}

// Delete deletes a role (roles:manage) unless it is a Teleport built-in
// role or held by the management identity.
func (s *Service) Delete(ctx context.Context, clusterID, name string) (err error) {
	c, cl, err := s.Clusters.Client(ctx, clusterID, authz.RolesManage)
	if c.ID == "" {
		return err
	}
	defer func() { clusters.Audit(ctx, s.Audit, audit.RoleDelete, audit.TargetRole, c.ID, name, err, nil) }()
	if err != nil {
		return err
	}
	if err := clusters.Writable(c); err != nil {
		return err
	}
	if err := clusters.ValidName("name", name); err != nil {
		return err
	}
	r, err := cl.GetRole(ctx, name)
	if err != nil {
		return err
	}
	if r.Preset {
		return &clusters.GuardError{Guard: clusters.GuardPresetRole, Msg: "Teleport built-in roles cannot be deleted"}
	}
	mgmt, err := clusters.ManagementIdentity(ctx, c, cl)
	if err != nil {
		return err
	}
	if slices.Contains(mgmt.Roles, name) {
		return &clusters.GuardError{Guard: clusters.GuardManagementRole,
			Msg: "the cluster's management identity holds this role; deleting it would cut the platform off the cluster"}
	}
	if err := cl.DeleteRole(ctx, name); err != nil {
		return err
	}
	s.changed(ctx, c, events.RoleDeleted, name)
	return nil
}
