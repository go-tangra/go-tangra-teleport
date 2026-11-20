// Package enroll enrolls inventory hosts as Teleport SSH nodes through their
// inventory agent (spec 002). The module asks inventory to deliver a
// reference-only join command to the host's agent (CreateTeleportJoin); when
// the agent fetches it, inventory calls back RenderTeleportJoin and the
// module mints a single-use Node join token there and then, so no token
// value is ever stored here, in inventory or in a queued command. The
// agent installs Teleport from the release tarball and joins; inventory
// tracks the progress, which the module reads back (GetTeleportJoins, on
// list and in a leased sweep) and turns into a confirmed inventory link
// once the node has joined.
//
// Permissions: resources:enroll creates, cancels and retries; reading the
// list needs resources:read. Render runs as a worker of the enrollment's
// tenant, admitted only for svc/inventory (grpcapi).
package enroll

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	inventoryv1 "github.com/go-tangra/go-tangra-inventory/sdk/v4/api/proto/inventory/v1"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// Bounds (spec 002 FR-002, FR-004).
const (
	MaxHosts        = 50
	DefaultTTLHours = 24
	MinTTLHours     = 1
	MaxTTLHours     = 72
	MaxRenders      = 5
	TokenTTL        = 30 * time.Minute
	MaxTargets      = 200
	DefaultTargets  = 50
	maxQuery        = 64
	getBatch        = 200
)

// ErrUnavailable is inventory being unreachable or enrollment being
// disabled on its side; it is a secrets.ErrUnavailable, so it maps to
// dependency_unavailable like the module's other peers.
var ErrUnavailable = fmt.Errorf("inventory: %w", secrets.ErrUnavailable)

// Refusal reasons inventory may answer CreateTeleportJoin with, plus the
// module's own (a closed set, spec 002).
var refusalReasons = []string{"no_agent", "ambiguous_agent", "not_supported_platform", "upgrade_required", "retired"}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Inventory dials inventory's TeleportJoinDeliveryService (nil result or an
// error: ErrUnavailable).
type Inventory func(ctx context.Context) (inventoryv1.TeleportJoinDeliveryServiceClient, error)

// Service runs enrollments. Clusters, Repo and Inventory are required; the
// others may be nil.
type Service struct {
	Clusters  *clusters.Service
	Repo      repo.Store
	Inventory Inventory
	Audit     audit.Recorder
	Events    events.Publisher
	Now       func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) inventory(ctx context.Context) (inventoryv1.TeleportJoinDeliveryServiceClient, error) {
	if s.Inventory == nil {
		return nil, ErrUnavailable
	}
	c, err := s.Inventory(ctx)
	if err != nil || c == nil {
		return nil, ErrUnavailable
	}
	return c, nil
}

// invErr maps an inventory call error: NotFound stays not found, anything
// else (including disabled_on_server) is ErrUnavailable.
func invErr(err error) error {
	if status.Code(err) == codes.NotFound {
		return repo.ErrNotFound
	}
	return ErrUnavailable
}

// ---- views

// View is one enrollment.
type View struct {
	ID           string    `json:"id"`
	ClusterID    string    `json:"cluster_id"`
	HostID       string    `json:"host_id"`
	Hostname     string    `json:"hostname"`
	State        string    `json:"state"`
	Reason       string    `json:"reason,omitempty"`
	NodeHostUUID string    `json:"node_host_uuid,omitempty"`
	LinkID       string    `json:"link_id,omitempty"`
	AgentOnline  *bool     `json:"agent_online,omitempty"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func viewOf(e repo.Enrollment) View {
	return View{ID: e.ID, ClusterID: e.ClusterID, HostID: e.HostID, Hostname: e.Hostname, State: e.State, Reason: e.Reason,
		NodeHostUUID: e.NodeHostUUID, LinkID: e.LinkID, CreatedBy: e.CreatedBy, CreatedAt: e.CreatedAt.UTC(),
		UpdatedAt: e.UpdatedAt.UTC(), ExpiresAt: e.ExpiresAt.UTC()}
}

// Page lists a cluster's enrollments, newest first. Stale is set when
// inventory could not be asked for fresh states.
type Page struct {
	Items []View `json:"items"`
	Stale bool   `json:"stale"`
}

// Target is an inventory host that may be enrolled.
type Target struct {
	HostID       string            `json:"host_id"`
	Hostname     string            `json:"hostname"`
	OSName       string            `json:"os_name,omitempty"`
	OSVersion    string            `json:"os_version,omitempty"`
	OSArch       string            `json:"os_arch,omitempty"`
	Manufacturer string            `json:"manufacturer,omitempty"`
	Model        string            `json:"model,omitempty"`
	AgentOnline  bool              `json:"agent_online"`
	Capability   string            `json:"capability"`
	Labels       map[string]string `json:"labels"`
	// Enrollment is the host's newest enrollment in this cluster, if any.
	Enrollment *View `json:"enrollment,omitempty"`
}

// Targets is the target search result.
type Targets struct {
	Items     []Target `json:"items"`
	Truncated bool     `json:"truncated"`
}

// Refusal is a host CreateEnrollments could not enroll.
type Refusal struct {
	HostID string `json:"host_id"`
	Reason string `json:"reason"`
}

// Created is the CreateEnrollments result.
type Created struct {
	Items   []View    `json:"items"`
	Refused []Refusal `json:"refused"`
}

// CreateInput is the POST body (nil TTL: the default).
type CreateInput struct {
	HostIDs  []string `json:"host_ids"`
	TTLHours *int     `json:"ttl_hours,omitempty"`
}

func factsOf(h *inventoryv1.TeleportJoinTarget) Facts {
	return Facts{HostID: h.GetHostId(), Hostname: h.GetHostname(), OSName: h.GetOsName(), OSVersion: h.GetOsVersion(),
		OSArch: h.GetOsArch(), Manufacturer: h.GetManufacturer(), Model: h.GetModel(), Tags: h.GetTags()}
}

func (s *Service) record(ctx context.Context, a audit.Action, clusterID, id string, err error, details map[string]any) {
	clusters.Audit(ctx, s.Audit, a, audit.TargetEnrollment, clusterID, id, err, details)
}

func (s *Service) changed(ctx context.Context, e repo.Enrollment) {
	events.Emit(ctx, s.Events, e.TenantID, events.EnrollmentChanged,
		events.Enrollment{ClusterID: e.ClusterID, EnrollmentID: e.ID, HostID: e.HostID, State: e.State})
}

// ---- targets

// ListTargets searches the tenant's inventory hosts that may be enrolled in
// the cluster (resources:enroll), with the labels each would get.
func (s *Service) ListTargets(ctx context.Context, clusterID, query string, limit int) (Targets, error) {
	c, err := s.Clusters.Authz.RequireCluster(ctx, clusterID, authz.ResourcesEnroll)
	if err != nil {
		return Targets{}, err
	}
	if len(query) > maxQuery {
		return Targets{}, &clusters.FieldError{Field: "q", Msg: "must be at most 64 characters"}
	}
	switch {
	case limit == 0:
		limit = DefaultTargets
	case limit < 1 || limit > MaxTargets:
		return Targets{}, &clusters.FieldError{Field: "limit", Msg: "must be 1 to 200"}
	}
	inv, err := s.inventory(ctx)
	if err != nil {
		return Targets{}, err
	}
	resp, err := inv.ListTeleportJoinTargets(ctx, &inventoryv1.ListTeleportJoinTargetsRequest{TenantId: c.TenantID, Query: query, Limit: int32(limit)}) // #nosec G115 -- bounded above
	if err != nil {
		return Targets{}, invErr(err)
	}
	rows, err := s.Repo.ListEnrollments(ctx, c.TenantID, c.ID)
	if err != nil {
		return Targets{}, err
	}
	newest := map[string]repo.Enrollment{}
	for _, r := range rows { // newest first
		if _, ok := newest[r.HostID]; !ok {
			newest[r.HostID] = r
		}
	}
	out := Targets{Items: make([]Target, 0, len(resp.GetHosts())), Truncated: resp.GetTruncated()}
	for _, h := range resp.GetHosts() {
		t := Target{HostID: h.GetHostId(), Hostname: h.GetHostname(), OSName: h.GetOsName(), OSVersion: h.GetOsVersion(),
			OSArch: h.GetOsArch(), Manufacturer: h.GetManufacturer(), Model: h.GetModel(), AgentOnline: h.GetAgentOnline(),
			Capability: h.GetCapability(), Labels: Labels(factsOf(h))}
		if e, ok := newest[t.HostID]; ok {
			v := viewOf(e)
			t.Enrollment = &v
		}
		out.Items = append(out.Items, t)
	}
	return out, nil
}

// ---- create, cancel, retry

func validate(in CreateInput) ([]string, time.Duration, error) {
	if len(in.HostIDs) < 1 || len(in.HostIDs) > MaxHosts {
		return nil, 0, &clusters.FieldError{Field: "host_ids", Msg: "must list 1 to 50 hosts"}
	}
	seen := map[string]bool{}
	var hosts []string
	for _, h := range in.HostIDs {
		if !uuidRE.MatchString(h) {
			return nil, 0, &clusters.FieldError{Field: "host_ids", Msg: "must be uuids"}
		}
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	hours := DefaultTTLHours
	if in.TTLHours != nil {
		hours = *in.TTLHours
	}
	if hours < MinTTLHours || hours > MaxTTLHours {
		return nil, 0, &clusters.FieldError{Field: "ttl_hours", Msg: "must be 1 to 72"}
	}
	return hosts, time.Duration(hours) * time.Hour, nil
}

// Create asks inventory to enroll each host (resources:enroll). Hosts
// inventory refuses are listed with the reason; nothing is stored for them.
func (s *Service) Create(ctx context.Context, clusterID string, in CreateInput) (Created, error) {
	c, err := s.Clusters.Authz.RequireCluster(ctx, clusterID, authz.ResourcesEnroll)
	if err != nil {
		return Created{}, err
	}
	if err := clusters.Writable(c); err != nil {
		return Created{}, err
	}
	hosts, ttl, err := validate(in)
	if err != nil {
		return Created{}, err
	}
	inv, err := s.inventory(ctx)
	if err != nil {
		return Created{}, err
	}
	out := Created{Items: []View{}, Refused: []Refusal{}}
	for _, h := range hosts {
		e, reason, err := s.createOne(ctx, inv, c, h, ttl)
		switch {
		case reason != "":
			out.Refused = append(out.Refused, Refusal{HostID: h, Reason: reason})
		case err != nil:
			if len(out.Items) == 0 && len(out.Refused) == 0 {
				return Created{}, err // nothing done yet: fail the request
			}
			out.Refused = append(out.Refused, Refusal{HostID: h, Reason: clusters.ReasonOf(err)})
		default:
			out.Items = append(out.Items, viewOf(e))
		}
	}
	return out, nil
}

// createOne creates one enrollment; a refusal is returned as its reason.
func (s *Service) createOne(ctx context.Context, inv inventoryv1.TeleportJoinDeliveryServiceClient, c repo.Cluster, host string, ttl time.Duration) (e repo.Enrollment, reason string, err error) {
	id := store.NewID()
	defer func() {
		target := id
		if err != nil || reason != "" {
			target = ""
		}
		d := map[string]any{"host_id": host, "ttl_hours": int(ttl.Hours())}
		if reason != "" {
			d["refused"] = reason
		}
		s.record(ctx, audit.EnrollmentCreate, c.ID, target, err, d)
	}()
	now := s.now()
	exp := now.Add(ttl)
	j, err := inv.CreateTeleportJoin(ctx, &inventoryv1.CreateTeleportJoinRequest{TenantId: c.TenantID, EnrollmentId: id, HostId: host,
		ClusterId: c.ID, ExpiresAt: exp.Unix()})
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.FailedPrecondition && slices.Contains(refusalReasons, st.Message()) {
			return repo.Enrollment{}, st.Message(), nil
		}
		if status.Code(err) == codes.NotFound {
			return repo.Enrollment{}, "not_found", nil
		}
		return repo.Enrollment{}, "", ErrUnavailable
	}
	subj, _ := authz.FromContext(ctx)
	e = repo.Enrollment{ID: id, TenantID: c.TenantID, ClusterID: c.ID, HostID: host, Hostname: trimHostname(j.GetHostname()),
		State: stateOf(j.GetState(), repo.EnrollPending), Reason: reasonOf(j.GetReason()), ItemID: trimID(j.GetItemId()),
		ExpiresAt: exp, CreatedBy: subj.ActorID(), CreatedAt: now, UpdatedAt: now}
	if err := s.Repo.CreateEnrollment(ctx, e); err != nil {
		// An unrecorded enrollment could never be rendered: withdraw it.
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_, _ = inv.CancelTeleportJoin(cctx, &inventoryv1.CancelTeleportJoinRequest{TenantId: c.TenantID, EnrollmentId: id})
		return repo.Enrollment{}, "", err
	}
	s.changed(ctx, e)
	return e, "", nil
}

// enrollment loads one enrollment of the cluster for a route.
func (s *Service) enrollment(ctx context.Context, clusterID, id, perm string) (repo.Cluster, repo.Enrollment, error) {
	c, err := s.Clusters.Authz.RequireCluster(ctx, clusterID, perm)
	if err != nil {
		return repo.Cluster{}, repo.Enrollment{}, err
	}
	e, err := s.Repo.GetEnrollment(ctx, c.TenantID, id)
	if err == nil && e.ClusterID != c.ID {
		err = repo.ErrNotFound
	}
	return c, e, err
}

// Cancel withdraws an enrollment that has not finished (resources:enroll);
// cancelling a finished one changes nothing.
func (s *Service) Cancel(ctx context.Context, clusterID, id string) (v View, err error) {
	c, e, err := s.enrollment(ctx, clusterID, id, authz.ResourcesEnroll)
	if c.ID == "" {
		return View{}, err
	}
	defer func() { s.record(ctx, audit.EnrollmentCancel, c.ID, id, err, map[string]any{"host_id": e.HostID}) }()
	if err != nil {
		return View{}, err
	}
	if !repo.EnrollActive(e.State) {
		return viewOf(e), nil
	}
	inv, err := s.inventory(ctx)
	if err != nil {
		return View{}, err
	}
	if _, err := inv.CancelTeleportJoin(ctx, &inventoryv1.CancelTeleportJoinRequest{TenantId: c.TenantID, EnrollmentId: e.ID}); err != nil && status.Code(err) != codes.NotFound {
		return View{}, invErr(err)
	}
	e.State, e.Reason = repo.EnrollCancelled, ""
	if e, err = s.Repo.UpdateEnrollment(ctx, e); err != nil {
		return View{}, err
	}
	s.changed(ctx, e)
	s.revokeTokens(ctx, c.ID, e)
	return viewOf(e), nil
}

// revokeTokens deletes from Teleport the unexpired tokens minted for e, so
// an agent that already fetched the material cannot join after a cancel.
// Best effort: a token that cannot be deleted still expires within
// TokenTTL, and the agent stops when inventory no longer accepts the item.
func (s *Service) revokeTokens(ctx context.Context, clusterID string, e repo.Enrollment) {
	toks, err := s.Repo.ListJoinTokens(ctx, e.TenantID, clusterID)
	if err != nil {
		return
	}
	now := s.now()
	var cl teleportapi.Client
	for _, t := range toks {
		if t.CreatedBy != "enrollment:"+e.ID || !t.RevokedAt.IsZero() || !now.Before(t.ExpiresAt) {
			continue
		}
		if cl == nil {
			if _, cl, err = s.Clusters.Client(ctx, clusterID, authz.ResourcesEnroll); err != nil {
				return
			}
		}
		if err := cl.DeleteJoinToken(ctx, t.TokenHash); err != nil && !errors.Is(err, teleportapi.ErrNotFound) {
			continue
		}
		if err := s.Repo.RevokeJoinToken(ctx, e.TenantID, t.ID, now); err != nil {
			continue
		}
		events.Emit(ctx, s.Events, e.TenantID, events.TokenRevoked, events.Token{ClusterID: clusterID, TokenID: t.ID, ResourceType: t.ResourceType})
	}
}

// Retry enrolls the host of a finished, unsuccessful enrollment again
// (resources:enroll) with the same lifetime; an enrollment still running or
// joined is a conflict.
func (s *Service) Retry(ctx context.Context, clusterID, id string) (View, error) {
	c, e, err := s.enrollment(ctx, clusterID, id, authz.ResourcesEnroll)
	if err != nil {
		return View{}, err
	}
	if repo.EnrollActive(e.State) || e.State == repo.EnrollJoined {
		s.record(ctx, audit.EnrollmentRetry, c.ID, id, repo.ErrConflict, map[string]any{"host_id": e.HostID})
		return View{}, repo.ErrConflict
	}
	if err := clusters.Writable(c); err != nil {
		s.record(ctx, audit.EnrollmentRetry, c.ID, id, err, map[string]any{"host_id": e.HostID})
		return View{}, err
	}
	inv, err := s.inventory(ctx)
	if err != nil {
		s.record(ctx, audit.EnrollmentRetry, c.ID, id, err, map[string]any{"host_id": e.HostID})
		return View{}, err
	}
	ttl := e.ExpiresAt.Sub(e.CreatedAt).Round(time.Hour)
	if ttl < MinTTLHours*time.Hour || ttl > MaxTTLHours*time.Hour {
		ttl = DefaultTTLHours * time.Hour
	}
	n, reason, err := s.createOne(ctx, inv, c, e.HostID, ttl)
	if reason != "" && err == nil {
		err = &RefusedError{Reason: reason}
	}
	s.record(ctx, audit.EnrollmentRetry, c.ID, id, err, map[string]any{"host_id": e.HostID, "enrollment_id": n.ID})
	if err != nil {
		return View{}, err
	}
	return viewOf(n), nil
}

// RefusedError is a host inventory will not enroll (the reason is from the
// closed refusal set).
type RefusedError struct{ Reason string }

func (e *RefusedError) Error() string { return "enrollment refused: " + e.Reason }

// ---- list and progress

// List returns the cluster's enrollments (resources:read), refreshing the
// unfinished ones from inventory first; when inventory is unreachable the
// stored states are returned with Stale set.
func (s *Service) List(ctx context.Context, clusterID string) (Page, error) {
	c, err := s.Clusters.Authz.RequireCluster(ctx, clusterID, authz.ResourcesRead)
	if err != nil {
		return Page{}, err
	}
	rows, err := s.Repo.ListEnrollments(ctx, c.TenantID, c.ID)
	if err != nil {
		return Page{}, err
	}
	online, stale := s.refresh(ctx, c.TenantID, rows)
	out := Page{Items: make([]View, 0, len(rows)), Stale: stale}
	for _, r := range rows {
		v := viewOf(r)
		if o, ok := online[r.ID]; ok {
			v.AgentOnline = &o
		}
		out.Items = append(out.Items, v)
	}
	return out, nil
}

// followed reports whether the sweep and List still ask inventory about e.
func (s *Service) followed(e repo.Enrollment, now time.Time) bool {
	return repo.EnrollActive(e.State) || e.State == repo.EnrollJoined && e.LinkID == "" && now.Before(e.ExpiresAt)
}

// refresh updates rows in place from inventory (one tenant). It returns the
// agents' online state by enrollment id, and whether inventory could not be
// asked.
func (s *Service) refresh(ctx context.Context, tenantID string, rows []repo.Enrollment) (map[string]bool, bool) {
	now := s.now()
	idx := map[string]int{}
	var ids []string
	for i, r := range rows {
		if s.followed(r, now) {
			idx[r.ID] = i
			ids = append(ids, r.ID)
		}
	}
	online := map[string]bool{}
	if len(ids) == 0 {
		return online, false
	}
	inv, err := s.inventory(ctx)
	if err != nil {
		return online, true
	}
	seen := map[string]bool{}
	stale := false
	for start := 0; start < len(ids); start += getBatch {
		batch := ids[start:min(start+getBatch, len(ids))]
		resp, err := inv.GetTeleportJoins(ctx, &inventoryv1.GetTeleportJoinsRequest{TenantId: tenantID, EnrollmentIds: batch})
		if err != nil {
			stale = true
			continue
		}
		for _, j := range resp.GetItems() {
			i, ok := idx[j.GetEnrollmentId()]
			if !ok || j.GetTenantId() != "" && j.GetTenantId() != tenantID {
				continue
			}
			seen[j.GetEnrollmentId()] = true
			online[j.GetEnrollmentId()] = j.GetAgentOnline()
			rows[i] = s.apply(ctx, rows[i], j)
		}
	}
	// Past its expiry and unknown to inventory: expired here too.
	if !stale {
		for _, id := range ids {
			i := idx[id]
			if !seen[id] && repo.EnrollActive(rows[i].State) && !now.Before(rows[i].ExpiresAt) {
				rows[i] = s.transition(ctx, rows[i], repo.EnrollExpired, "", rows[i].NodeHostUUID)
			}
		}
	}
	return online, stale
}

// apply moves e to inventory's view of it and links a joined node.
func (s *Service) apply(ctx context.Context, e repo.Enrollment, j *inventoryv1.TeleportJoin) repo.Enrollment {
	state := stateOf(j.GetState(), e.State)
	if repo.EnrollActive(state) && rank[state] < rank[e.State] {
		state = e.State // never move back (the render already saw the fetch)
	}
	node := trimID(j.GetNodeHostUuid())
	if node == "" {
		node = e.NodeHostUUID
	}
	if j.GetItemId() != "" && e.ItemID == "" {
		e.ItemID = trimID(j.GetItemId())
	}
	if state != e.State || reasonOf(j.GetReason()) != e.Reason || node != e.NodeHostUUID {
		e = s.transition(ctx, e, state, reasonOf(j.GetReason()), node)
	}
	if e.State == repo.EnrollJoined && e.LinkID == "" {
		e = s.link(ctx, e)
	}
	return e
}

// transition stores a state change, audits it as a report and publishes it.
func (s *Service) transition(ctx context.Context, e repo.Enrollment, state, reason, node string) repo.Enrollment {
	prev := e.State
	e.State, e.Reason, e.NodeHostUUID = state, reason, node
	u, err := s.Repo.UpdateEnrollment(ctx, e)
	s.record(ctx, audit.EnrollmentReport, e.ClusterID, e.ID, err, map[string]any{"from": prev, "to": state, "reason": reason})
	if err != nil {
		return e
	}
	s.changed(ctx, u)
	return u
}

// link confirms the joined node's inventory link once the resource watcher
// has its snapshot (a later sweep retries until the enrollment expires).
func (s *Service) link(ctx context.Context, e repo.Enrollment) repo.Enrollment {
	if e.NodeHostUUID == "" {
		return e
	}
	snaps, err := s.Repo.ListSnapshots(ctx, e.TenantID, e.ClusterID)
	if err != nil {
		return e
	}
	var snap repo.ResourceSnapshot
	for _, sn := range snaps {
		if sn.Kind == repo.KindNode && sn.TeleportName == e.NodeHostUUID {
			snap = sn
			break
		}
	}
	if snap.ID == "" {
		return e
	}
	links, err := s.Repo.ListLinks(ctx, e.TenantID, snap.ID)
	if err != nil {
		return e
	}
	var l repo.ResourceLink
	for _, x := range links {
		if x.TargetModule == repo.TargetInventory && x.TargetID == e.HostID {
			l = x
		}
	}
	switch {
	case l.ID == "":
		l = repo.ResourceLink{ID: store.NewID(), TenantID: e.TenantID, SnapshotID: snap.ID, TargetModule: repo.TargetInventory,
			TargetID: e.HostID, Match: repo.MatchConfirmed, MatchedOn: repo.MatchedOnHostname, CreatedAt: s.now()}
		if err := s.Repo.CreateLink(ctx, l); err != nil {
			return e
		}
	case l.Match != repo.MatchConfirmed:
		l.Match = repo.MatchConfirmed
		if _, err := s.Repo.UpdateLink(ctx, l); err != nil {
			return e
		}
	}
	e.LinkID = l.ID
	u, err := s.Repo.UpdateEnrollment(ctx, e)
	if err != nil {
		return e
	}
	events.Emit(ctx, s.Events, e.TenantID, events.ResourceLinked, events.Link{ResourceID: snap.ID, TargetModule: l.TargetModule, TargetID: l.TargetID})
	return u
}

// ---- render (svc/inventory only)

// RenderInput is inventory's RenderTeleportJoin request.
type RenderInput struct {
	EnrollmentID string
	HostID       string // the verified agent's host
	ItemID       string
}

// Material is what the agent joins with. Token appears here only.
type Material struct {
	EnrollmentID    string
	ItemID          string
	Token           secrets.Secret
	TokenExpiresAt  time.Time
	ProxyAddr       string
	CAPins          []string
	TeleportVersion string
	Labels          map[string]string
}

// Render mints the single-use Node join token of an unfinished, unexpired
// enrollment for the host it was created for, at most MaxRenders times.
// The caller is a worker of the enrollment's tenant (grpcapi admits only
// svc/inventory). Every refusal is repo.ErrNotFound: inventory then fails
// the item.
func (s *Service) Render(ctx context.Context, in RenderInput) (m Material, err error) {
	subj, _ := authz.FromContext(ctx)
	e, err := s.Repo.GetEnrollment(ctx, subj.TenantID, in.EnrollmentID)
	if err != nil {
		return Material{}, err
	}
	defer func() {
		s.record(ctx, audit.EnrollmentRender, e.ClusterID, e.ID, err, map[string]any{"host_id": e.HostID, "renders": e.Renders})
	}()
	now := s.now()
	switch {
	case e.HostID != in.HostID, !repo.EnrollActive(e.State), !now.Before(e.ExpiresAt),
		in.ItemID != "" && e.ItemID != "" && in.ItemID != e.ItemID:
		return Material{}, repo.ErrNotFound
	}
	c, cl, err := s.Clusters.Client(ctx, e.ClusterID, authz.ResourcesEnroll)
	if err != nil {
		return Material{}, err
	}
	if err := clusters.Writable(c); err != nil {
		return Material{}, err
	}
	pins, err := cl.CAPins(ctx)
	if err != nil {
		return Material{}, err
	}
	info, err := cl.Ping(ctx)
	if err != nil {
		return Material{}, err
	}
	labels := s.labels(ctx, e)
	if e, err = s.Repo.AddEnrollmentRender(ctx, e.TenantID, e.ID, MaxRenders); err != nil {
		if errors.Is(err, repo.ErrConflict) {
			return Material{}, repo.ErrNotFound
		}
		return Material{}, err
	}
	exp := now.Add(TokenTTL)
	tok, err := cl.CreateJoinToken(ctx, teleportapi.JoinTokenSpec{Roles: []string{teleportapi.RoleNode}, Expires: exp})
	if err != nil {
		return Material{}, err
	}
	row := repo.JoinToken{ID: store.NewID(), TenantID: e.TenantID, ClusterID: e.ClusterID, TokenHash: teleportapi.TokenHash(tok.Name),
		ResourceType: repo.KindNode, ExpiresAt: tok.Expires, CreatedBy: "enrollment:" + e.ID, CreatedAt: now}
	if err := s.Repo.CreateJoinToken(ctx, row); err != nil {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = cl.DeleteJoinToken(rctx, teleportapi.TokenHash(tok.Name))
		return Material{}, err
	}
	newItem := in.ItemID != "" && e.ItemID == "" && trimID(in.ItemID) != ""
	if newItem {
		e.ItemID = trimID(in.ItemID)
	}
	switch {
	case e.State == repo.EnrollPending || e.State == repo.EnrollDelivered:
		e = s.transition(ctx, e, repo.EnrollFetched, "", e.NodeHostUUID)
	case newItem:
		if u, err := s.Repo.UpdateEnrollment(ctx, e); err == nil {
			e = u
		}
	}
	return Material{EnrollmentID: e.ID, ItemID: e.ItemID, Token: tok.Name, TokenExpiresAt: tok.Expires, ProxyAddr: c.ProxyAddr,
		CAPins: pins, TeleportVersion: info.ServerVersion, Labels: labels}, nil
}

// labels reads the host's current facts; when inventory cannot say, the
// node still gets the host id and the stored hostname.
func (s *Service) labels(ctx context.Context, e repo.Enrollment) map[string]string {
	fallback := Labels(Facts{HostID: e.HostID, Hostname: e.Hostname})
	inv, err := s.inventory(ctx)
	if err != nil {
		return fallback
	}
	resp, err := inv.ListTeleportJoinTargets(ctx, &inventoryv1.ListTeleportJoinTargetsRequest{TenantId: e.TenantID, HostIds: []string{e.HostID}, Limit: 1})
	if err != nil {
		return fallback
	}
	for _, h := range resp.GetHosts() {
		if h.GetHostId() == e.HostID {
			return Labels(factsOf(h))
		}
	}
	return fallback
}

// ---- mapping

var states = map[inventoryv1.TeleportJoinState]string{
	inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_PENDING:     repo.EnrollPending,
	inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_DELIVERED:   repo.EnrollDelivered,
	inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_FETCHED:     repo.EnrollFetched,
	inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_INSTALLING:  repo.EnrollInstalling,
	inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_JOINED:      repo.EnrollJoined,
	inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_FAILED:      repo.EnrollFailed,
	inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_UNSUPPORTED: repo.EnrollUnsupported,
	inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_SUPERSEDED:  repo.EnrollSuperseded,
	inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_EXPIRED:     repo.EnrollExpired,
	inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_CANCELLED:   repo.EnrollCancelled,
}

// rank orders the unfinished states.
var rank = map[string]int{repo.EnrollPending: 1, repo.EnrollDelivered: 2, repo.EnrollFetched: 3, repo.EnrollInstalling: 4}

// stateOf maps inventory's state (unknown: keep).
func stateOf(st inventoryv1.TeleportJoinState, keep string) string {
	if v, ok := states[st]; ok {
		return v
	}
	return keep
}

var reasonRE = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// reasonOf keeps a reason token from inventory's closed set shape only.
func reasonOf(r string) string {
	if reasonRE.MatchString(r) {
		return r
	}
	return ""
}

var idRE = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

func trimID(s string) string {
	if idRE.MatchString(s) {
		return s
	}
	return ""
}

func trimHostname(h string) string {
	if len(h) > 255 {
		h = h[:255]
	}
	return sanitizeValue(h)
}
