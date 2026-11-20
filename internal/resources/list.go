// Package resources is the inventory part of US3 (FR-015, FR-019, FR-020,
// research D7): the live list of a cluster's enrolled resources merged with
// their last-known state (resource_snapshot) and their inventory/asset
// links; the per-cluster watcher that keeps the snapshots current; the sweep
// that flags resources offline past the cluster's threshold; and the linker.
//
// Online resources are read live from Teleport (15 s cache); offline and
// flagged resources exist only as snapshots, because Teleport forgets a
// server once its heartbeat expires. A resource listed before the watcher
// has seen it gets a snapshot on the spot, so it can be linked at once.
package resources

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// Resource statuses.
const (
	StatusOnline  = "online"
	StatusOffline = "offline"
	StatusFlagged = "flagged"
)

// Bounds.
const (
	DefaultPageSize = 100
	MaxPageSize     = 200
	MaxLabels       = 64 // labels kept per snapshot (data-model)
	maxQuery        = 128
	maxLabel        = 256
)

// teleportKinds maps module kinds to Teleport kinds.
var teleportKinds = map[string]string{
	repo.KindNode: teleportapi.KindNode, repo.KindApp: teleportapi.KindApp, repo.KindDB: teleportapi.KindDB,
	repo.KindKube: teleportapi.KindKube, repo.KindDesktop: teleportapi.KindDesktop,
}

// TeleportKind is the Teleport kind of a module kind ("" when unknown).
func TeleportKind(kind string) string { return teleportKinds[kind] }

// ModuleKind is the module kind of a Teleport server kind ("" when unknown).
func ModuleKind(tk string) string {
	for k, v := range teleportKinds {
		if v == tk {
			return k
		}
	}
	return ""
}

// Store is the storage the resource services need (repo.Store satisfies it).
type Store interface {
	repo.Clusters
	repo.Snapshots
	repo.Links
}

// Service lists resources and manages their links. Clusters and Repo are
// required; the others may be nil (a nil Linker reports links unavailable).
type Service struct {
	Clusters *clusters.Service
	Repo     Store
	Linker   *Linker
	Cache    *teleportapi.Cache
	Audit    audit.Recorder
	Events   events.Publisher
	Now      func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// LinkView is a link as the API returns it.
type LinkView struct {
	ID           string    `json:"id"`
	TargetModule string    `json:"target_module"`
	TargetID     string    `json:"target_id"`
	Match        string    `json:"match"`
	MatchedOn    string    `json:"matched_on"`
	CreatedAt    time.Time `json:"created_at"`
}

func linkView(l repo.ResourceLink) LinkView {
	return LinkView{ID: l.ID, TargetModule: l.TargetModule, TargetID: l.TargetID, Match: l.Match, MatchedOn: l.MatchedOn, CreatedAt: l.CreatedAt.UTC()}
}

// Item is one resource of the list. ID is its snapshot id (the {rid} of the
// link routes).
type Item struct {
	ID           string            `json:"id"`
	Kind         string            `json:"kind"`
	Name         string            `json:"name"`
	Hostname     string            `json:"hostname,omitempty"`
	Addr         string            `json:"addr,omitempty"`
	Labels       map[string]string `json:"labels"`
	AgentVersion string            `json:"agent_version"`
	Status       string            `json:"status"`
	LastSeenAt   *time.Time        `json:"last_seen_at,omitempty"`
	OfflineSince *time.Time        `json:"offline_since,omitempty"`
	FlaggedAt    *time.Time        `json:"flagged_at,omitempty"`
	Links        []LinkView        `json:"links"`
}

// Page is one page of resources. LinkStatus says whether automatic
// inventory/asset matching is available.
type Page struct {
	Items      []Item `json:"items"`
	Next       string `json:"next,omitempty"`
	LinkStatus string `json:"link_status"`
}

// ListInput filters and pages the list. Label is "key=value".
type ListInput struct {
	Kind   string
	Label  string
	Q      string
	Status string
	Next   string
	Limit  int
}

// cursor is the opaque list position: the live phase walks kinds in order
// through Teleport pages, then the offline phase walks offline snapshots.
type cursor struct {
	Kind    int    `json:"k"`
	Next    string `json:"t,omitempty"`
	Offline bool   `json:"o,omitempty"`
	Offset  int    `json:"n,omitempty"`
}

func (c cursor) encode() string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (cursor, error) {
	var c cursor
	if s == "" {
		return c, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || json.Unmarshal(b, &c) != nil || c.Kind < 0 || c.Offset < 0 {
		return cursor{}, &clusters.FieldError{Field: "next", Msg: "is not a cursor of this list"}
	}
	return c, nil
}

func ptr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}

// statusOf is the status of a snapshot.
func statusOf(s repo.ResourceSnapshot) string {
	switch {
	case s.Online:
		return StatusOnline
	case !s.FlaggedAt.IsZero():
		return StatusFlagged
	}
	return StatusOffline
}

func itemOf(s repo.ResourceSnapshot, links []repo.ResourceLink) Item {
	it := Item{ID: s.ID, Kind: s.Kind, Name: s.TeleportName, Hostname: s.Hostname, Addr: s.Addr, Labels: s.Labels,
		AgentVersion: s.AgentVersion, Status: statusOf(s), LastSeenAt: ptr(s.LastSeenAt), OfflineSince: ptr(s.OfflineSince),
		FlaggedAt: ptr(s.FlaggedAt), Links: make([]LinkView, 0, len(links))}
	if it.Labels == nil {
		it.Labels = map[string]string{}
	}
	for _, l := range links {
		it.Links = append(it.Links, linkView(l))
	}
	return it
}

// BoundLabels keeps at most MaxLabels labels (the first by key).
func BoundLabels(in map[string]string) map[string]string {
	if len(in) <= MaxLabels {
		return maps.Clone(in)
	}
	keys := slices.Sorted(maps.Keys(in))[:MaxLabels]
	out := make(map[string]string, MaxLabels)
	for _, k := range keys {
		out[k] = in[k]
	}
	return out
}

// SnapshotOf is the online snapshot of a live resource seen at now.
func SnapshotOf(c repo.Cluster, kind string, r teleportapi.Resource, now time.Time) repo.ResourceSnapshot {
	return repo.ResourceSnapshot{TenantID: c.TenantID, ClusterID: c.ID, Kind: kind, TeleportName: r.Name, Hostname: r.Hostname,
		Addr: r.Addr, Labels: BoundLabels(r.Labels), AgentVersion: r.Version, Online: true, LastSeenAt: now}
}

func validText(field, s string, maxLen int) error {
	if len(s) > maxLen {
		return &clusters.FieldError{Field: field, Msg: "must be at most " + strconv.Itoa(maxLen) + " characters"}
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return &clusters.FieldError{Field: field, Msg: "must not contain control characters"}
		}
	}
	return nil
}

// filter is a validated ListInput.
type filter struct {
	kinds         []string
	labels        map[string]string
	q             string
	status        string
	limit         int
	at            cursor
	liveOnly      bool
	snapshotsOnly bool
}

func parse(in ListInput) (filter, error) {
	f := filter{kinds: repo.ResourceKinds, q: strings.TrimSpace(in.Q), status: in.Status, limit: in.Limit}
	if in.Kind != "" {
		if TeleportKind(in.Kind) == "" {
			return f, &clusters.FieldError{Field: "kind", Msg: "must be node, app, db, kube or desktop"}
		}
		f.kinds = []string{in.Kind}
	}
	if in.Label != "" {
		k, v, ok := strings.Cut(in.Label, "=")
		if !ok || k == "" || validText("label", in.Label, maxLabel) != nil {
			return f, &clusters.FieldError{Field: "label", Msg: "must be key=value"}
		}
		f.labels = map[string]string{k: v}
	}
	if err := validText("q", f.q, maxQuery); err != nil {
		return f, err
	}
	switch in.Status {
	case "":
	case StatusOnline:
		f.liveOnly = true
	case StatusOffline, StatusFlagged:
		f.snapshotsOnly = true
	default:
		return f, &clusters.FieldError{Field: "status", Msg: "must be online, offline or flagged"}
	}
	if f.limit <= 0 {
		f.limit = DefaultPageSize
	}
	f.limit = min(f.limit, MaxPageSize)
	var err error
	f.at, err = decodeCursor(in.Next)
	if f.snapshotsOnly {
		f.at.Offline = true
	}
	return f, err
}

// matches applies the filter to a snapshot (the offline phase).
func (f filter) matches(s repo.ResourceSnapshot) bool {
	if s.Online || !slices.Contains(f.kinds, s.Kind) || (f.status == StatusFlagged && s.FlaggedAt.IsZero()) ||
		(f.status == StatusOffline && !s.FlaggedAt.IsZero()) {
		return false
	}
	for k, v := range f.labels {
		if s.Labels[k] != v {
			return false
		}
	}
	if f.q == "" {
		return true
	}
	q := strings.ToLower(f.q)
	hit := strings.Contains(strings.ToLower(s.TeleportName), q) || strings.Contains(strings.ToLower(s.Hostname), q)
	for k, v := range s.Labels {
		hit = hit || strings.Contains(strings.ToLower(k), q) || strings.Contains(strings.ToLower(v), q)
	}
	return hit
}

func key(kind, name string) string { return kind + "/" + name }

// List returns one page of the cluster's resources (resources:read).
func (s *Service) List(ctx context.Context, clusterID string, in ListInput) (Page, error) {
	c, cl, err := s.Clusters.Client(ctx, clusterID, authz.ResourcesRead)
	if err != nil {
		return Page{}, err
	}
	f, err := parse(in)
	if err != nil {
		return Page{}, err
	}
	snaps, err := s.Repo.ListSnapshots(ctx, c.TenantID, c.ID)
	if err != nil {
		return Page{}, err
	}
	links, err := s.Repo.ListClusterLinks(ctx, c.TenantID, c.ID)
	if err != nil {
		return Page{}, err
	}
	byKey := make(map[string]repo.ResourceSnapshot, len(snaps))
	for _, sn := range snaps {
		byKey[key(sn.Kind, sn.TeleportName)] = sn
	}
	bySnap := map[string][]repo.ResourceLink{}
	for _, l := range links {
		bySnap[l.SnapshotID] = append(bySnap[l.SnapshotID], l)
	}
	page := Page{Items: []Item{}, LinkStatus: s.Linker.Status()}
	var created []int // items whose snapshot was created now (to match)
	at := f.at
	now := s.now()
	// Live phase.
	for !at.Offline && at.Kind < len(f.kinds) && len(page.Items) < f.limit {
		kind := f.kinds[at.Kind]
		o := teleportapi.ListOptions{Limit: f.limit - len(page.Items), Next: at.Next, Labels: f.labels}
		if f.q != "" {
			o.Search = []string{f.q}
		}
		op := "resources:" + kind + ":" + strconv.Itoa(o.Limit) + ":" + o.Next + ":" + in.Label + ":" + f.q
		p, err := teleportapi.Cached(ctx, s.Cache, c.TenantID, c.ID, op, func(ctx context.Context) (teleportapi.Page[teleportapi.Resource], error) {
			return cl.ListResources(ctx, TeleportKind(kind), o)
		})
		if err != nil {
			return Page{}, err
		}
		for _, r := range p.Items {
			sn, known := byKey[key(kind, r.Name)]
			if !known {
				if sn, err = s.Repo.UpsertSnapshot(ctx, SnapshotOf(c, kind, r, now)); err != nil {
					return Page{}, err
				}
				created = append(created, len(page.Items))
			}
			it := itemOf(sn, bySnap[sn.ID])
			// Teleport lists it, so it is online whatever the snapshot says.
			it.Status, it.Hostname, it.Addr, it.AgentVersion, it.Labels = StatusOnline, r.Hostname, r.Addr, r.Version, BoundLabels(r.Labels)
			if it.Labels == nil {
				it.Labels = map[string]string{}
			}
			it.OfflineSince, it.FlaggedAt = nil, nil
			page.Items = append(page.Items, it)
		}
		if p.Next != "" {
			at.Next = p.Next
			continue
		}
		at.Kind, at.Next = at.Kind+1, ""
	}
	if !at.Offline && at.Kind >= len(f.kinds) {
		if f.liveOnly {
			return s.finish(ctx, c, page, created, cursor{}), nil
		}
		at = cursor{Offline: true}
	}
	// Offline phase.
	if at.Offline && len(page.Items) < f.limit {
		var off []repo.ResourceSnapshot
		for _, sn := range snaps {
			if f.matches(sn) {
				off = append(off, sn)
			}
		}
		i := min(at.Offset, len(off))
		for ; i < len(off) && len(page.Items) < f.limit; i++ {
			page.Items = append(page.Items, itemOf(off[i], bySnap[off[i].ID]))
		}
		if i >= len(off) {
			return s.finish(ctx, c, page, created, cursor{}), nil
		}
		at.Offset = i
	}
	return s.finish(ctx, c, page, created, at), nil
}

// finish matches the snapshots created by this list and sets the cursor.
func (s *Service) finish(ctx context.Context, c repo.Cluster, page Page, created []int, next cursor) Page {
	if next != (cursor{}) {
		page.Next = next.encode()
	}
	if s.Linker == nil {
		return page
	}
	for _, i := range created {
		it := page.Items[i]
		snap := repo.ResourceSnapshot{ID: it.ID, TenantID: c.TenantID, ClusterID: c.ID, Hostname: it.Hostname, Addr: it.Addr}
		ls, err := s.Linker.Match(ctx, snap)
		if errors.Is(err, ErrDirectoryUnavailable) {
			page.LinkStatus = LinkStatusUnavailable
			break
		}
		if err != nil {
			continue
		}
		page.Items[i].Links = make([]LinkView, 0, len(ls))
		for _, l := range ls {
			page.Items[i].Links = append(page.Items[i].Links, linkView(l))
		}
	}
	if len(created) > 0 && page.LinkStatus != LinkStatusUnavailable {
		page.LinkStatus = s.Linker.Status()
	}
	return page
}
