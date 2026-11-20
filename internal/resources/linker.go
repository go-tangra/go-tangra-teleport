package resources

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
)

// Inventory and asset links (FR-019, research D11). The Linker matches a
// resource snapshot's hostname and address against host records of the
// tangra inventory and asset modules, through a HostDirectory:
//
//   - exactly one record of a module matches: an `auto` link;
//   - several match: one `candidate` link each, for manual confirmation;
//   - none: no link (stale auto and candidate links are removed);
//   - a `confirmed` link (manual) is never touched by matching.
//
// Matching runs when a snapshot first appears or its hostname or address
// changes, so removing an automatic link is not undone until the host
// changes. Confirming a candidate promotes it and removes the module's other
// candidates; an operator may also confirm a record that was never offered
// (manual linking), and remove any link.
//
// NEEDS CROSS-REPO (research D11, T079): inventory-v4 and asset-v4 have no
// read RPC that finds a host by hostname or IP, so production wires
// UnavailableDirectory: automatic matching reports dependency_unavailable and
// manual links still work. The real adapter waits on that RPC.

// Link-status values of a resource list.
const (
	LinkStatusOK          = "ok"
	LinkStatusUnavailable = "dependency_unavailable"
)

// ErrDirectoryUnavailable reports that inventory and asset cannot be asked.
var ErrDirectoryUnavailable = errors.New("resources: inventory and asset host lookup unavailable")

// HostRecord is one inventory or asset record that may be a resource's host.
type HostRecord struct {
	Module   string // repo.TargetInventory | repo.TargetAsset
	ID       string
	Hostname string
	IPs      []string
}

// HostDirectory finds a tenant's host records by hostname or IP.
type HostDirectory interface {
	LookupHosts(ctx context.Context, tenantID, hostname string, ips []string) ([]HostRecord, error)
}

// UnavailableDirectory is the production directory until inventory and
// asset offer a host lookup: every lookup is ErrDirectoryUnavailable.
type UnavailableDirectory struct{}

// LookupHosts implements HostDirectory.
func (UnavailableDirectory) LookupHosts(context.Context, string, string, []string) ([]HostRecord, error) {
	return nil, ErrDirectoryUnavailable
}

// FakeDirectory is an in-memory HostDirectory for tests: Records are
// matched case-insensitively by hostname and exactly by IP; Err fails every
// lookup.
type FakeDirectory struct {
	mu      sync.Mutex
	Records []HostRecord
	Err     error
	calls   int
}

// LookupHosts implements HostDirectory.
func (f *FakeDirectory) LookupHosts(_ context.Context, _, hostname string, ips []string) ([]HostRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.Err != nil {
		return nil, f.Err
	}
	var out []HostRecord
	for _, r := range f.Records {
		hit := hostname != "" && strings.EqualFold(r.Hostname, hostname)
		for _, ip := range ips {
			hit = hit || slices.Contains(r.IPs, ip)
		}
		if hit {
			out = append(out, r)
		}
	}
	return out, nil
}

// Set replaces the records and the error.
func (f *FakeDirectory) Set(records []HostRecord, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Records, f.Err = records, err
}

// Calls is the number of lookups.
func (f *FakeDirectory) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// Modules are the link targets, in matching order.
var Modules = []string{repo.TargetInventory, repo.TargetAsset}

// LinkStore is the storage the linker needs.
type LinkStore interface {
	CreateLink(ctx context.Context, l repo.ResourceLink) error
	ListLinks(ctx context.Context, tenantID, snapshotID string) ([]repo.ResourceLink, error)
	UpdateLink(ctx context.Context, l repo.ResourceLink) (repo.ResourceLink, error)
	DeleteLink(ctx context.Context, tenantID, id string) error
}

// Linker runs automatic matching. Repo is required; a nil Directory is
// UnavailableDirectory.
type Linker struct {
	Repo      LinkStore
	Directory HostDirectory
	Events    events.Publisher
	Now       func() time.Time

	failed atomic.Bool // the last lookup failed
}

func (l *Linker) now() time.Time {
	if l.Now != nil {
		return l.Now().UTC()
	}
	return time.Now().UTC()
}

func (l *Linker) directory() HostDirectory {
	if l.Directory == nil {
		return UnavailableDirectory{}
	}
	return l.Directory
}

// Status is the link status a resource list reports: unavailable while no
// directory is wired or the last lookup failed.
func (l *Linker) Status() string {
	if l == nil || l.failed.Load() {
		return LinkStatusUnavailable
	}
	if _, ok := l.directory().(UnavailableDirectory); ok {
		return LinkStatusUnavailable
	}
	return LinkStatusOK
}

// AddrIP is the IP of a resource address ("ip", "ip:port", "[ip]:port"), or "".
func AddrIP(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	return ip.Unmap().String()
}

type wanted struct {
	match, on string
}

// Match reconciles the snapshot's automatic links with the directory and
// returns its links. A lookup failure is ErrDirectoryUnavailable and leaves
// the links as they are.
func (l *Linker) Match(ctx context.Context, snap repo.ResourceSnapshot) ([]repo.ResourceLink, error) {
	ip := AddrIP(snap.Addr)
	var ips []string
	if ip != "" {
		ips = []string{ip}
	}
	if snap.Hostname == "" && ip == "" {
		return l.Repo.ListLinks(ctx, snap.TenantID, snap.ID)
	}
	recs, err := l.directory().LookupHosts(ctx, snap.TenantID, snap.Hostname, ips)
	if err != nil {
		l.failed.Store(true)
		return nil, ErrDirectoryUnavailable
	}
	l.failed.Store(false)
	have, err := l.Repo.ListLinks(ctx, snap.TenantID, snap.ID)
	if err != nil {
		return nil, err
	}
	for _, module := range Modules {
		if slices.ContainsFunc(have, func(x repo.ResourceLink) bool { return x.TargetModule == module && x.Match == repo.MatchConfirmed }) {
			continue
		}
		want := map[string]wanted{}
		for _, r := range recs {
			if r.Module != module || r.ID == "" {
				continue
			}
			on := repo.MatchedOnIP
			if snap.Hostname != "" && strings.EqualFold(r.Hostname, snap.Hostname) {
				on = repo.MatchedOnHostname
			}
			want[r.ID] = wanted{on: on}
		}
		kind := repo.MatchCandidate
		if len(want) == 1 {
			kind = repo.MatchAuto
		}
		for id, w := range want {
			want[id] = wanted{match: kind, on: w.on}
		}
		if err := l.reconcile(ctx, snap, module, have, want); err != nil {
			return nil, err
		}
	}
	return l.Repo.ListLinks(ctx, snap.TenantID, snap.ID)
}

// reconcile makes the module's automatic links equal want.
func (l *Linker) reconcile(ctx context.Context, snap repo.ResourceSnapshot, module string, have []repo.ResourceLink, want map[string]wanted) error {
	for _, x := range have {
		if x.TargetModule != module {
			continue
		}
		w, keep := want[x.TargetID]
		switch {
		case !keep:
			if err := l.Repo.DeleteLink(ctx, snap.TenantID, x.ID); err != nil && !errors.Is(err, repo.ErrNotFound) {
				return err
			}
			if x.Match == repo.MatchAuto {
				events.Emit(ctx, l.Events, snap.TenantID, events.ResourceUnlinked, events.Link{ResourceID: snap.ID, TargetModule: module, TargetID: x.TargetID})
			}
		case x.Match != w.match || x.MatchedOn != w.on:
			x.Match, x.MatchedOn = w.match, w.on
			if _, err := l.Repo.UpdateLink(ctx, x); err != nil {
				return err
			}
			if w.match == repo.MatchAuto {
				events.Emit(ctx, l.Events, snap.TenantID, events.ResourceLinked, events.Link{ResourceID: snap.ID, TargetModule: module, TargetID: x.TargetID})
			}
		}
		delete(want, x.TargetID)
	}
	for id, w := range want {
		link := repo.ResourceLink{ID: store.NewID(), TenantID: snap.TenantID, SnapshotID: snap.ID, TargetModule: module, TargetID: id,
			Match: w.match, MatchedOn: w.on, CreatedAt: l.now()}
		if err := l.Repo.CreateLink(ctx, link); err != nil && !errors.Is(err, repo.ErrConflict) {
			return err
		}
		if w.match == repo.MatchAuto {
			events.Emit(ctx, l.Events, snap.TenantID, events.ResourceLinked, events.Link{ResourceID: snap.ID, TargetModule: module, TargetID: id})
		}
	}
	return nil
}

// ---- confirm and remove (resources:link)

// maxTargetID bounds a target record id (schema: 1–128 characters).
const maxTargetID = 128

// LinkInput is the POST body that confirms a candidate (or links manually).
type LinkInput struct {
	TargetModule string `json:"target_module"`
	TargetID     string `json:"target_id"`
}

func validTarget(in LinkInput) error {
	if !slices.Contains(Modules, in.TargetModule) {
		return &clusters.FieldError{Field: "target_module", Msg: "must be inventory or asset"}
	}
	if in.TargetID == "" || len(in.TargetID) > maxTargetID {
		return &clusters.FieldError{Field: "target_id", Msg: "must be 1 to 128 characters"}
	}
	for _, r := range in.TargetID {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.:", r)) {
			return &clusters.FieldError{Field: "target_id", Msg: "may contain only letters, digits and - _ . :"}
		}
	}
	return nil
}

// snapshot loads a snapshot of the cluster for a link route.
func (s *Service) snapshot(ctx context.Context, clusterID, rid string) (repo.Cluster, repo.ResourceSnapshot, error) {
	c, err := s.Clusters.Authz.RequireCluster(ctx, clusterID, authz.ResourcesLink)
	if err != nil {
		return repo.Cluster{}, repo.ResourceSnapshot{}, err
	}
	snap, err := s.Repo.GetSnapshot(ctx, c.TenantID, rid)
	if err == nil && snap.ClusterID != c.ID {
		err = repo.ErrNotFound
	}
	return c, snap, err
}

// ConfirmLink confirms a candidate, or links a record manually, and removes
// the module's other automatic links (resources:link).
func (s *Service) ConfirmLink(ctx context.Context, clusterID, rid string, in LinkInput) (v LinkView, err error) {
	c, snap, err := s.snapshot(ctx, clusterID, rid)
	if c.ID == "" {
		return LinkView{}, err
	}
	defer func() {
		clusters.Audit(ctx, s.Audit, audit.LinkConfirm, audit.TargetLink, c.ID, v.ID, err,
			map[string]any{"resource_id": rid, "target_module": in.TargetModule, "target_id": in.TargetID})
	}()
	if err != nil {
		return LinkView{}, err
	}
	if err := validTarget(in); err != nil {
		return LinkView{}, err
	}
	have, err := s.Repo.ListLinks(ctx, c.TenantID, snap.ID)
	if err != nil {
		return LinkView{}, err
	}
	var out repo.ResourceLink
	for _, x := range have {
		if x.TargetModule != in.TargetModule {
			continue
		}
		if x.TargetID == in.TargetID {
			x.Match = repo.MatchConfirmed
			if out, err = s.Repo.UpdateLink(ctx, x); err != nil {
				return LinkView{}, err
			}
			continue
		}
		if x.Match != repo.MatchConfirmed {
			if err := s.Repo.DeleteLink(ctx, c.TenantID, x.ID); err != nil && !errors.Is(err, repo.ErrNotFound) {
				return LinkView{}, err
			}
		}
	}
	if out.ID == "" {
		on := repo.MatchedOnHostname
		if snap.Hostname == "" {
			on = repo.MatchedOnIP
		}
		out = repo.ResourceLink{ID: store.NewID(), TenantID: c.TenantID, SnapshotID: snap.ID, TargetModule: in.TargetModule,
			TargetID: in.TargetID, Match: repo.MatchConfirmed, MatchedOn: on, CreatedAt: s.now()}
		if err := s.Repo.CreateLink(ctx, out); err != nil {
			return LinkView{}, err
		}
	}
	events.Emit(ctx, s.Events, c.TenantID, events.ResourceLinked, events.Link{ResourceID: snap.ID, TargetModule: out.TargetModule, TargetID: out.TargetID})
	return linkView(out), nil
}

// RemoveLink removes one link of the resource (resources:link).
func (s *Service) RemoveLink(ctx context.Context, clusterID, rid, lid string) (err error) {
	c, snap, err := s.snapshot(ctx, clusterID, rid)
	if c.ID == "" {
		return err
	}
	var l repo.ResourceLink
	defer func() {
		clusters.Audit(ctx, s.Audit, audit.LinkRemove, audit.TargetLink, c.ID, lid, err,
			map[string]any{"resource_id": rid, "target_module": l.TargetModule, "target_id": l.TargetID})
	}()
	if err != nil {
		return err
	}
	if l, err = s.Repo.GetLink(ctx, c.TenantID, lid); err != nil {
		return err
	}
	if l.SnapshotID != snap.ID {
		l = repo.ResourceLink{}
		return repo.ErrNotFound
	}
	if err := s.Repo.DeleteLink(ctx, c.TenantID, lid); err != nil {
		return err
	}
	events.Emit(ctx, s.Events, c.TenantID, events.ResourceUnlinked, events.Link{ResourceID: snap.ID, TargetModule: l.TargetModule, TargetID: l.TargetID})
	return nil
}
