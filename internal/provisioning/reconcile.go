package provisioning

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

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

// ErrCollision refuses a Teleport username that is already taken by a user
// the member does not own (an unmanaged user, the management identity or
// another member). It is a conflict.
var ErrCollision = fmt.Errorf("provisioning: the Teleport username is taken: %w", repo.ErrConflict)

// ErrRetryFailed reports that retrying a failed provisioning failed again
// (the cause is logged and audited; the next sync retries).
var ErrRetryFailed = errors.New("provisioning: the retry failed; see the module audit trail")

// Summary counts what one run changed. Errors counts the members and users
// that could not be brought in line; they are retried on the next run.
type Summary struct {
	Created  int `json:"created"`
	Updated  int `json:"updated"`
	Locked   int `json:"locked"`
	Unlocked int `json:"unlocked"`
	Deleted  int `json:"deleted"`
	Errors   int `json:"errors"`
}

func (s *Summary) add(o Summary) {
	s.Created += o.Created
	s.Updated += o.Updated
	s.Locked += o.Locked
	s.Unlocked += o.Unlocked
	s.Deleted += o.Deleted
	s.Errors += o.Errors
}

func (s Summary) details() map[string]any {
	return map[string]any{"created": s.Created, "updated": s.Updated, "locked": s.Locked, "unlocked": s.Unlocked,
		"deleted": s.Deleted, "errors": s.Errors}
}

// ProvisionInput is the POST /managed-users body.
type ProvisionInput struct {
	TangraUserID string `json:"tangra_user_id"`
}

// ManagedView is a managed user as the API returns it.
type ManagedView struct {
	ID               string     `json:"id"`
	TangraUserID     string     `json:"tangra_user_id"`
	TeleportUsername string     `json:"teleport_username"`
	State            string     `json:"state"`
	AppliedRoles     []string   `json:"applied_roles"`
	AppliedLogins    []string   `json:"applied_logins"`
	Locked           bool       `json:"locked"`
	DeprovisionAfter *time.Time `json:"deprovision_after,omitempty"`
	LastSyncedAt     *time.Time `json:"last_synced_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

// ManagedPage lists a cluster's managed users.
type ManagedPage struct {
	Items []ManagedView `json:"items"`
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func managedView(u repo.ManagedUser) ManagedView {
	v := ManagedView{ID: u.ID, TangraUserID: u.TangraUserID, TeleportUsername: u.TeleportUsername, State: u.State,
		AppliedRoles: slices.Clone(u.AppliedRoles), AppliedLogins: slices.Clone(u.AppliedLogins), Locked: u.LockName != "",
		DeprovisionAfter: timePtr(u.DeprovisionAfter), LastSyncedAt: timePtr(u.LastSyncedAt), CreatedAt: u.CreatedAt.UTC()}
	if v.AppliedRoles == nil {
		v.AppliedRoles = []string{}
	}
	if v.AppliedLogins == nil {
		v.AppliedLogins = []string{}
	}
	return v
}

// Username derives the Teleport username from a tangra login: lower-cased,
// every character other than a letter, digit or . _ @ - becomes "-", leading
// and trailing punctuation is trimmed, and the result is capped at 128
// characters. A login with nothing usable is refused.
func Username(login string) (string, error) {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(login)) {
		switch {
		case r < utf8.RuneSelf && (r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("._@-", r)):
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "._@-")
	if len(out) > clusters.MaxNameLength {
		out = strings.TrimRight(out[:clusters.MaxNameLength], "._@-")
	}
	if clusters.ValidName("login", out) != nil {
		return "", &clusters.FieldError{Field: "login", Msg: "the tangra login cannot be turned into a Teleport username"}
	}
	return out, nil
}

// desired is the union of the roles and logins of every mapping that
// matches m (sorted), or nothing when none does.
func desired(m Member, maps []repo.RoleMapping) (roles, logins []string) {
	for _, mp := range maps {
		if (mp.SubjectKind == repo.SubjectModuleRole && slices.Contains(m.Roles, mp.SubjectRef)) ||
			(mp.SubjectKind == repo.SubjectGroup && slices.Contains(m.Groups, mp.SubjectRef)) {
			roles = append(roles, mp.TeleportRoles...)
			logins = append(logins, mp.Logins...)
		}
	}
	slices.Sort(roles)
	slices.Sort(logins)
	return slices.Compact(roles), slices.Compact(logins)
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

func labels(tenantID, userID string) map[string]string {
	return map[string]string{users.LabelManaged: "true", users.LabelTenant: tenantID, users.LabelUser: userID}
}

// owned reports whether u is the managed user of tangraID in tenant: only
// such a user is ever written.
func owned(u teleportapi.User, tenantID, tangraID string) bool {
	return u.Labels[users.LabelManaged] == "true" && u.Labels[users.LabelTenant] == tenantID && u.Labels[users.LabelUser] == tangraID
}

func notFound(err error) bool { return teleportapi.Reason(err) == "not_found" }

// scope gives a run without a caller the worker identity of tenantID; a
// caller must belong to tenantID.
func (s *Service) scope(ctx context.Context, tenantID string) (context.Context, error) {
	if subj, ok := authz.FromContext(ctx); ok {
		return ctx, authz.RequireTenant(subj, tenantID)
	}
	if tenantID == "" {
		return ctx, fmt.Errorf("%w: tenant required", authz.ErrForbidden)
	}
	return authz.WithSubjects(ctx, authz.Worker(tenantID, WorkerName)), nil
}

// run is the state of one cluster run.
type run struct {
	s     *Service
	c     repo.Cluster
	cl    teleportapi.Client
	maps  []repo.RoleMapping
	names map[string]string // Teleport username -> tangra user id of the rows
}

func (s *Service) open(ctx context.Context, c repo.Cluster, cl teleportapi.Client) (*run, []repo.ManagedUser, error) {
	maps, err := s.Repo.ListMappings(ctx, c.TenantID, c.ID)
	if err != nil {
		return nil, nil, err
	}
	rows, err := s.Repo.ListManagedUsers(ctx, c.TenantID, c.ID)
	if err != nil {
		return nil, nil, err
	}
	r := &run{s: s, c: c, cl: cl, maps: maps, names: map[string]string{}}
	for _, u := range rows {
		r.names[u.TeleportUsername] = u.TangraUserID
	}
	return r, rows, nil
}

func (r *run) changed(ctx context.Context, tangraID, state string) {
	events.Emit(ctx, r.s.Events, r.c.TenantID, events.ProvisioningChanged,
		events.Provisioning{ClusterID: r.c.ID, TangraUserID: tangraID, State: state})
}

func (r *run) warn(ctx context.Context, step, tangraID string, err error) {
	r.s.log().WarnContext(ctx, "provisioning step failed", "cluster_id", r.c.ID, "tangra_user_id", tangraID, "step", step, "reason", ReasonOf(err))
}

// save writes the row; a store failure is an error of the step.
func (r *run) save(ctx context.Context, u repo.ManagedUser) error {
	u.LastSyncedAt = r.s.now()
	_, err := r.s.Repo.UpdateManagedUser(ctx, u)
	return err
}

// Reconcile brings the cluster's managed users in line with the mappings and
// the tenant's membership, then deletes the users whose grace period has
// passed. Without a caller in ctx it runs as the provisioning worker of
// tenantID (the teleport:sync-provisioning task). It fails only when the
// cluster, the mappings or the membership cannot be read
// (ErrMembershipUnavailable); per-user failures are counted in Errors.
func (s *Service) Reconcile(ctx context.Context, tenantID, clusterID string) (sum Summary, err error) {
	if ctx, err = s.scope(ctx, tenantID); err != nil {
		return Summary{}, err
	}
	c, cl, err := s.Clusters.Client(ctx, clusterID, authz.ProvisioningManage)
	if err != nil {
		return Summary{}, err
	}
	defer func() {
		s.record(ctx, audit.ProvisionSync, audit.TargetCluster, c.ID, c.DisplayName, err, sum.details())
	}()
	if err := clusters.Writable(c); err != nil {
		return Summary{}, err
	}
	defer s.clusterLock(c.ID)()
	r, rows, err := s.open(ctx, c, cl)
	if err != nil {
		return Summary{}, err
	}
	members, err := s.membership().Members(ctx, c.TenantID)
	if err != nil {
		return Summary{}, errors.Join(ErrMembershipUnavailable, err)
	}
	byUser := map[string]repo.ManagedUser{}
	for _, u := range rows {
		byUser[u.TangraUserID] = u
	}
	slices.SortFunc(members, func(a, b Member) int { return strings.Compare(a.UserID, b.UserID) })
	entitled := map[string]bool{}
	for _, m := range members {
		roles, logins := desired(m, r.maps)
		if len(roles) == 0 {
			continue
		}
		entitled[m.UserID] = true
		if u, ok := byUser[m.UserID]; ok {
			sum.add(r.converge(ctx, u, m, roles, logins))
		} else {
			_, o, _ := r.create(ctx, m, roles, logins)
			sum.add(o)
		}
	}
	for _, u := range rows {
		if !entitled[u.TangraUserID] && u.State != repo.UserLockedPendingDeletion {
			sum.add(r.revoke(ctx, u))
		}
	}
	purged, err := r.purge(ctx)
	if err != nil {
		return sum, err
	}
	sum.add(purged)
	return sum, nil
}

// Sync runs Reconcile on the caller's cluster now (provisioning:manage).
func (s *Service) Sync(ctx context.Context, clusterID string) (Summary, error) {
	c, err := s.Clusters.Authz.RequireCluster(ctx, clusterID, authz.ProvisioningManage)
	if err != nil {
		return Summary{}, err
	}
	return s.Reconcile(ctx, c.TenantID, c.ID)
}

// PurgeDeprovisioned deletes the managed users of every cluster of tenantID
// whose grace period has passed, and removes their locks (the
// teleport:purge-deprovisioned task). Each user is re-verified with auth
// first (SR-006). A cluster that cannot be reached counts as an error.
func (s *Service) PurgeDeprovisioned(ctx context.Context, tenantID string) (Summary, error) {
	ctx, err := s.scope(ctx, tenantID)
	if err != nil {
		return Summary{}, err
	}
	cs, err := s.Repo.ListClusters(ctx, tenantID)
	if err != nil {
		return Summary{}, err
	}
	var sum Summary
	for _, rc := range cs {
		c, cl, err := s.Clusters.Client(ctx, rc.ID, authz.ProvisioningManage)
		if err == nil {
			err = clusters.Writable(c)
		}
		if err != nil {
			sum.Errors++
			continue
		}
		unlock := s.clusterLock(c.ID)
		r, _, err := s.open(ctx, c, cl)
		var o Summary
		if err == nil {
			o, err = r.purge(ctx)
		}
		unlock()
		if err != nil {
			o.Errors++
		}
		sum.add(o)
	}
	return sum, nil
}

// ListManaged returns the cluster's managed users (users:read).
func (s *Service) ListManaged(ctx context.Context, clusterID string) (ManagedPage, error) {
	c, err := s.Clusters.Authz.RequireCluster(ctx, clusterID, authz.UsersRead)
	if err != nil {
		return ManagedPage{}, err
	}
	rows, err := s.Repo.ListManagedUsers(ctx, c.TenantID, c.ID)
	if err != nil {
		return ManagedPage{}, err
	}
	out := ManagedPage{Items: make([]ManagedView, 0, len(rows))}
	for _, u := range rows {
		out.Items = append(out.Items, managedView(u))
	}
	return out, nil
}

// Provision provisions one tangra member now (provisioning:manage): the
// member is verified with auth (SR-006), a mapping must match, and the
// invite goes out through notification.
func (s *Service) Provision(ctx context.Context, clusterID string, in ProvisionInput) (ManagedView, error) {
	c, cl, err := s.writable(ctx, clusterID)
	if err != nil {
		return ManagedView{}, err
	}
	if clusters.ValidName("tangra_user_id", in.TangraUserID) != nil {
		return ManagedView{}, &clusters.FieldError{Field: "tangra_user_id", Msg: "must be a tangra user id"}
	}
	defer s.clusterLock(c.ID)()
	r, rows, err := s.open(ctx, c, cl)
	if err != nil {
		return ManagedView{}, err
	}
	i := slices.IndexFunc(rows, func(u repo.ManagedUser) bool { return u.TangraUserID == in.TangraUserID })
	if i >= 0 && rows[i].State != repo.UserError {
		return ManagedView{}, repo.ErrConflict
	}
	m, ok, err := s.membership().Member(ctx, c.TenantID, in.TangraUserID)
	if err != nil {
		return ManagedView{}, errors.Join(ErrMembershipUnavailable, err)
	}
	if !ok {
		return ManagedView{}, &clusters.FieldError{Field: "tangra_user_id", Msg: "is not an active member of the tenant"}
	}
	roles, logins := desired(m, r.maps)
	if len(roles) == 0 {
		return ManagedView{}, &clusters.FieldError{Field: "tangra_user_id", Msg: "no role mapping of this cluster matches the user"}
	}
	if i >= 0 { // a failed provisioning is retried
		if _, err := cl.GetUser(ctx, rows[i].TeleportUsername); notFound(err) {
			u, _, err := r.provision(ctx, rows[i], m, roles, logins)
			if err != nil {
				return ManagedView{}, err
			}
			return managedView(u), nil
		}
		if o := r.converge(ctx, rows[i], m, roles, logins); o.Errors > 0 {
			return ManagedView{}, ErrRetryFailed
		}
		u, err := s.Repo.GetManagedUser(ctx, c.TenantID, rows[i].ID)
		if err != nil {
			return ManagedView{}, err
		}
		return managedView(u), nil
	}
	u, _, err := r.create(ctx, m, roles, logins)
	if err != nil {
		return ManagedView{}, err
	}
	return managedView(u), nil
}

// create adds the row of a new member and provisions it.
func (r *run) create(ctx context.Context, m Member, roles, logins []string) (repo.ManagedUser, Summary, error) {
	name, err := Username(m.Login)
	if err == nil {
		err = r.available(ctx, name, m.UserID)
	}
	if err != nil {
		r.s.record(ctx, audit.ProvisionCreate, audit.TargetManagedUser, r.c.ID, m.UserID, err, nil)
		r.warn(ctx, "create", m.UserID, err)
		return repo.ManagedUser{}, Summary{Errors: 1}, err
	}
	u := repo.ManagedUser{ID: store.NewID(), TenantID: r.c.TenantID, ClusterID: r.c.ID, TangraUserID: m.UserID,
		TeleportUsername: name, State: repo.UserProvisioning, CreatedAt: r.s.now()}
	if err := r.s.Repo.CreateManagedUser(ctx, u); err != nil {
		r.s.record(ctx, audit.ProvisionCreate, audit.TargetManagedUser, r.c.ID, name, err, nil)
		r.warn(ctx, "create", m.UserID, err)
		return repo.ManagedUser{}, Summary{Errors: 1}, err
	}
	r.names[name] = m.UserID
	return r.provision(ctx, u, m, roles, logins)
}

// available refuses a username another member's row or an existing Teleport
// user that is not this member's managed user already holds.
func (r *run) available(ctx context.Context, name, tangraID string) error {
	if owner, ok := r.names[name]; ok && owner != tangraID {
		return ErrCollision
	}
	if clusters.IsManagementIdentity(r.c, name) {
		return ErrCollision
	}
	u, err := r.cl.GetUser(ctx, name)
	switch {
	case notFound(err):
		return nil
	case err != nil:
		return err
	case !owned(u, r.c.TenantID, tangraID):
		return ErrCollision
	}
	return nil
}

// provision creates the Teleport user of a row and sends the invite; when the
// invite cannot be sent the user is deleted again and the row is left in
// error for the next run.
func (r *run) provision(ctx context.Context, u repo.ManagedUser, m Member, roles, logins []string) (repo.ManagedUser, Summary, error) {
	err := r.createUser(ctx, u, m, roles, logins)
	r.s.record(ctx, audit.ProvisionCreate, audit.TargetManagedUser, r.c.ID, u.TeleportUsername, err,
		map[string]any{"tangra_user_id": m.UserID, "roles": roles, "logins": logins})
	if err != nil {
		r.warn(ctx, "create", m.UserID, err)
		u.State = repo.UserError
		_ = r.save(ctx, u)
		r.changed(ctx, m.UserID, u.State)
		return u, Summary{Errors: 1}, err
	}
	u.State, u.AppliedRoles, u.AppliedLogins = repo.UserActive, roles, logins
	if err := r.save(ctx, u); err != nil {
		r.warn(ctx, "save", m.UserID, err)
		return u, Summary{Errors: 1}, err
	}
	r.changed(ctx, m.UserID, u.State)
	return u, Summary{Created: 1}, nil
}

func (r *run) createUser(ctx context.Context, u repo.ManagedUser, m Member, roles, logins []string) error {
	created, err := r.s.Users.Create(ctx, r.c.ID, users.CreateInput{Name: u.TeleportUsername, Roles: roles, Logins: logins,
		Labels: labels(r.c.TenantID, m.UserID)})
	if err != nil {
		return err
	}
	if err := r.invite(ctx, u, m, created); err != nil {
		if derr := r.s.Users.Delete(ctx, r.c.ID, u.TeleportUsername); derr != nil {
			r.warn(ctx, "rollback", m.UserID, derr)
		}
		return err
	}
	return nil
}

// invite sends the invite link to the tangra user. The link is in the
// message variables only (the notification module's redaction applies).
func (r *run) invite(ctx context.Context, u repo.ManagedUser, m Member, created users.Created) error {
	if r.s.Notify == nil {
		return notify.ErrUnavailable
	}
	vars := map[string]string{
		"invite_url": string(created.InviteURL.Reveal()), "expires_at": created.InviteExpiresAt.Format(time.RFC3339),
		"teleport_username": u.TeleportUsername, "cluster_id": r.c.ID, "display_name": r.c.DisplayName, "cluster_name": r.c.ClusterName,
	}
	return r.s.Notify.Send(ctx, notify.Message{TenantID: r.c.TenantID, Template: notify.TemplateInvite, To: m.UserID, Vars: vars, CorrelationID: u.ID})
}

// converge brings an entitled member's user in line: a failed or missing
// user is provisioned (again), a locked user is unlocked, and roles and
// logins that differ from the mappings are updated.
func (r *run) converge(ctx context.Context, u repo.ManagedUser, m Member, roles, logins []string) Summary {
	tu, err := r.cl.GetUser(ctx, u.TeleportUsername)
	switch {
	case notFound(err):
		if u.LockName != "" {
			if err := r.unlock(ctx, u); err != nil {
				return Summary{Errors: 1}
			}
			u.LockName, u.DeprovisionAfter = "", time.Time{}
		}
		_, o, _ := r.provision(ctx, u, m, roles, logins)
		return o
	case err != nil:
		r.warn(ctx, "read", m.UserID, err)
		return Summary{Errors: 1}
	case !owned(tu, r.c.TenantID, m.UserID):
		r.warn(ctx, "converge", m.UserID, ErrCollision)
		return Summary{Errors: 1}
	}
	var out Summary
	if u.State == repo.UserLockedPendingDeletion {
		if err := r.unlock(ctx, u); err != nil {
			return Summary{Errors: 1}
		}
		u.LockName, u.DeprovisionAfter = "", time.Time{}
		out.Unlocked = 1
	}
	if !sameSet(tu.Roles, roles) || !sameSet(tu.Logins, logins) {
		if _, err := r.s.Users.Update(ctx, r.c.ID, u.TeleportUsername, users.UpdateInput{Roles: roles, Logins: logins, Revision: tu.Revision}); err != nil {
			r.warn(ctx, "update", m.UserID, err)
			out.Errors++
			if out.Unlocked == 0 {
				return out
			}
			roles, logins = tu.Roles, tu.Logins
		} else if out.Unlocked == 0 {
			out.Updated = 1
		}
	}
	prev := u.State
	u.State, u.AppliedRoles, u.AppliedLogins = repo.UserActive, roles, logins
	if err := r.save(ctx, u); err != nil {
		r.warn(ctx, "save", m.UserID, err)
		return Summary{Errors: out.Errors + 1}
	}
	if prev != u.State || out.Updated > 0 {
		r.changed(ctx, m.UserID, u.State)
	}
	return out
}

// unlock removes the module's lock of a user (an already removed lock is fine).
func (r *run) unlock(ctx context.Context, u repo.ManagedUser) error {
	if u.LockName == "" {
		return nil
	}
	if err := r.s.Locks.Remove(ctx, r.c.ID, u.LockName); err != nil && !notFound(err) {
		r.warn(ctx, "unlock", u.TangraUserID, err)
		return err
	}
	return nil
}

// verify re-reads the member from auth (SR-006): true when the member is
// still entitled on this cluster, so no lock or delete may happen.
func (r *run) verify(ctx context.Context, tangraID string) (bool, error) {
	m, ok, err := r.s.membership().Member(ctx, r.c.TenantID, tangraID)
	if err != nil {
		return false, errors.Join(ErrMembershipUnavailable, err)
	}
	if !ok {
		return false, nil
	}
	roles, _ := desired(m, r.maps)
	return len(roles) > 0, nil
}

// revoke locks the user of a member who is no longer entitled, once auth
// confirms it; the user is deleted after the grace period (purge).
func (r *run) revoke(ctx context.Context, u repo.ManagedUser) Summary {
	still, err := r.verify(ctx, u.TangraUserID)
	if err != nil {
		r.warn(ctx, "verify", u.TangraUserID, err)
		return Summary{Errors: 1}
	}
	if still {
		return Summary{}
	}
	tu, err := r.cl.GetUser(ctx, u.TeleportUsername)
	switch {
	case notFound(err):
		return r.forget(ctx, u)
	case err != nil:
		r.warn(ctx, "read", u.TangraUserID, err)
		return Summary{Errors: 1}
	case !owned(tu, r.c.TenantID, u.TangraUserID):
		r.warn(ctx, "lock", u.TangraUserID, ErrCollision)
		return Summary{Errors: 1}
	}
	l, err := r.s.Locks.Create(ctx, r.c.ID, locks.CreateInput{TargetKind: teleportapi.LockTargetUser, Target: u.TeleportUsername, Reason: LockReason})
	r.s.record(ctx, audit.ProvisionLock, audit.TargetManagedUser, r.c.ID, u.TeleportUsername, err, map[string]any{"tangra_user_id": u.TangraUserID})
	if err != nil {
		r.warn(ctx, "lock", u.TangraUserID, err)
		return Summary{Errors: 1}
	}
	u.State, u.LockName, u.DeprovisionAfter = repo.UserLockedPendingDeletion, l.Name, r.s.now().Add(r.s.grace())
	if err := r.save(ctx, u); err != nil {
		r.warn(ctx, "save", u.TangraUserID, err)
		return Summary{Errors: 1}
	}
	r.changed(ctx, u.TangraUserID, u.State)
	return Summary{Locked: 1}
}

// purge deletes the locked users whose grace period has passed.
func (r *run) purge(ctx context.Context) (Summary, error) {
	rows, err := r.s.Repo.ListManagedUsers(ctx, r.c.TenantID, r.c.ID)
	if err != nil {
		return Summary{}, err
	}
	now := r.s.now()
	var sum Summary
	for _, u := range rows {
		if u.State != repo.UserLockedPendingDeletion || u.DeprovisionAfter.After(now) {
			continue
		}
		sum.add(r.remove(ctx, u))
	}
	return sum, nil
}

func (r *run) remove(ctx context.Context, u repo.ManagedUser) Summary {
	still, err := r.verify(ctx, u.TangraUserID)
	if err != nil {
		r.warn(ctx, "verify", u.TangraUserID, err)
		return Summary{Errors: 1}
	}
	if still {
		return Summary{} // the next sync unlocks it
	}
	tu, err := r.cl.GetUser(ctx, u.TeleportUsername)
	switch {
	case notFound(err):
	case err != nil:
		r.warn(ctx, "read", u.TangraUserID, err)
		return Summary{Errors: 1}
	case !owned(tu, r.c.TenantID, u.TangraUserID):
		r.warn(ctx, "delete", u.TangraUserID, ErrCollision)
		return Summary{Errors: 1}
	default:
		err := r.s.Users.Delete(ctx, r.c.ID, u.TeleportUsername)
		if err != nil && !notFound(err) {
			r.s.record(ctx, audit.ProvisionDelete, audit.TargetManagedUser, r.c.ID, u.TeleportUsername, err, nil)
			r.warn(ctx, "delete", u.TangraUserID, err)
			return Summary{Errors: 1}
		}
	}
	return r.forget(ctx, u)
}

// forget removes the row of a user that no longer exists in Teleport.
func (r *run) forget(ctx context.Context, u repo.ManagedUser) Summary {
	if u.LockName != "" {
		if err := r.unlock(ctx, u); err != nil {
			return Summary{Errors: 1}
		}
	}
	err := r.s.Repo.DeleteManagedUser(ctx, u.TenantID, u.ID)
	r.s.record(ctx, audit.ProvisionDelete, audit.TargetManagedUser, r.c.ID, u.TeleportUsername, err, map[string]any{"tangra_user_id": u.TangraUserID})
	if err != nil {
		r.warn(ctx, "forget", u.TangraUserID, err)
		return Summary{Errors: 1}
	}
	delete(r.names, u.TeleportUsername)
	r.changed(ctx, u.TangraUserID, StateDeleted)
	return Summary{Deleted: 1}
}
