package resources_test

import (
	"context"
	"errors"
	"testing"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/resources"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

var (
	admin    = ct.As(ct.TenantA, ct.Admin)
	operator = ct.As(ct.TenantA, ct.Operator)
	viewer   = ct.As(ct.TenantA, ct.Viewer)
)

func clustersRecipients(e *ct.Env) clusters.RecipientsFunc { return clusters.RuleRecipients(e.Repo) }

func setup(t *testing.T, dir resources.HostDirectory) (*ct.Env, *resources.Service, string) {
	t.Helper()
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	e.Teleport.Resources = []teleportapi.Resource{
		{Kind: teleportapi.KindNode, Name: "n1", Hostname: "web-1", Addr: "10.0.0.5:3022", Version: "19.0.1", Labels: map[string]string{"env": "prod"}},
		{Kind: teleportapi.KindNode, Name: "n2", Hostname: "db-1", Addr: "10.0.0.6:3022", Version: "19.0.1", Labels: map[string]string{"env": "dev"}},
		{Kind: teleportapi.KindApp, Name: "grafana", Hostname: "apps-1"},
	}
	l := &resources.Linker{Repo: e.Repo, Directory: dir, Events: e.Events, Now: e.Now}
	return e, &resources.Service{Clusters: e.Service, Repo: e.Repo, Linker: l, Audit: e.Audit, Events: e.Events, Now: e.Now}, c.ID
}

func item(t *testing.T, p resources.Page, name string) resources.Item {
	t.Helper()
	for _, it := range p.Items {
		if it.Name == name {
			return it
		}
	}
	t.Fatalf("%s not listed in %+v", name, p.Items)
	return resources.Item{}
}

func matches(it resources.Item, module string) map[string]string {
	out := map[string]string{}
	for _, l := range it.Links {
		if l.TargetModule == module {
			out[l.TargetID] = l.Match
		}
	}
	return out
}

// A unique hostname or IP match is an auto link; several matches are
// candidates; confirming one removes the other candidates.
func TestLinking(t *testing.T) {
	dir := &resources.FakeDirectory{Records: []resources.HostRecord{
		{Module: repo.TargetInventory, ID: "inv-1", Hostname: "WEB-1"},
		{Module: repo.TargetAsset, ID: "as-1", IPs: []string{"10.0.0.5"}},
		{Module: repo.TargetInventory, ID: "inv-2", Hostname: "db-1"},
		{Module: repo.TargetInventory, ID: "inv-3", IPs: []string{"10.0.0.6"}},
	}}
	e, s, id := setup(t, dir)
	p, err := s.List(viewer, id, resources.ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if p.LinkStatus != resources.LinkStatusOK {
		t.Fatalf("link status %q", p.LinkStatus)
	}
	n1 := item(t, p, "n1")
	if m := matches(n1, repo.TargetInventory); m["inv-1"] != repo.MatchAuto || len(m) != 1 {
		t.Fatalf("n1 inventory %v", m)
	}
	if m := matches(n1, repo.TargetAsset); m["as-1"] != repo.MatchAuto {
		t.Fatalf("n1 asset %v", m)
	}
	for _, l := range n1.Links {
		if want := map[string]string{"inv-1": repo.MatchedOnHostname, "as-1": repo.MatchedOnIP}[l.TargetID]; l.MatchedOn != want {
			t.Fatalf("matched on %+v", l)
		}
	}
	n2 := item(t, p, "n2")
	if m := matches(n2, repo.TargetInventory); m["inv-2"] != repo.MatchCandidate || m["inv-3"] != repo.MatchCandidate {
		t.Fatalf("n2 candidates %v", m)
	}
	if got := len(e.Events.OfType(events.ResourceLinked)); got != 2 {
		t.Fatalf("%d linked events (auto links only)", got)
	}

	// Confirming one candidate removes the other.
	v, err := s.ConfirmLink(operator, id, n2.ID, resources.LinkInput{TargetModule: repo.TargetInventory, TargetID: "inv-3"})
	if err != nil || v.Match != repo.MatchConfirmed || v.MatchedOn != repo.MatchedOnIP {
		t.Fatalf("confirm %+v %v", v, err)
	}
	p, _ = s.List(viewer, id, resources.ListInput{})
	if m := matches(item(t, p, "n2"), repo.TargetInventory); len(m) != 1 || m["inv-3"] != repo.MatchConfirmed {
		t.Fatalf("after confirm %v", m)
	}
	// A confirmed link survives re-matching.
	snap, _ := e.Repo.GetSnapshot(context.Background(), ct.TenantA, n2.ID)
	if _, err := s.Linker.Match(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	ls, _ := e.Repo.ListLinks(context.Background(), ct.TenantA, n2.ID)
	if len(ls) != 1 || ls[0].Match != repo.MatchConfirmed {
		t.Fatalf("re-match touched the confirmed link: %+v", ls)
	}
	// A record that disappears drops its auto link; ambiguity collapsing to
	// one promotes the candidate to auto.
	dir.Set([]resources.HostRecord{{Module: repo.TargetInventory, ID: "inv-9", Hostname: "web-1"}}, nil)
	snap1, _ := e.Repo.GetSnapshot(context.Background(), ct.TenantA, n1.ID)
	got, err := s.Linker.Match(context.Background(), snap1)
	if err != nil || len(got) != 1 || got[0].TargetID != "inv-9" || got[0].Match != repo.MatchAuto {
		t.Fatalf("re-match %+v %v", got, err)
	}
	if len(e.Events.OfType(events.ResourceUnlinked)) != 2 {
		t.Fatalf("unlinked events %d", len(e.Events.OfType(events.ResourceUnlinked)))
	}
	dir.Set([]resources.HostRecord{{Module: repo.TargetInventory, ID: "inv-9", Hostname: "web-1"},
		{Module: repo.TargetInventory, ID: "inv-10", Hostname: "web-1"}}, nil)
	got, _ = s.Linker.Match(context.Background(), snap1)
	if len(got) != 2 || got[0].Match != repo.MatchCandidate || got[1].Match != repo.MatchCandidate {
		t.Fatalf("auto to candidates %+v", got)
	}
	dir.Set([]resources.HostRecord{{Module: repo.TargetInventory, ID: "inv-10", Hostname: "web-1"}}, nil)
	got, _ = s.Linker.Match(context.Background(), snap1)
	if len(got) != 1 || got[0].Match != repo.MatchAuto || got[0].TargetID != "inv-10" {
		t.Fatalf("candidate to auto %+v", got)
	}
	// Nothing to match on: no lookup.
	before := dir.Calls()
	if _, err := s.Linker.Match(context.Background(), repo.ResourceSnapshot{ID: snap1.ID, TenantID: ct.TenantA}); err != nil || dir.Calls() != before {
		t.Fatalf("empty match: %v (%d lookups)", err, dir.Calls()-before)
	}
}

// Manual links work without a directory (production until the cross-repo
// lookup exists); the list reports dependency_unavailable and does not fail.
func TestDirectoryUnavailable(t *testing.T) {
	e, s, id := setup(t, resources.UnavailableDirectory{})
	p, err := s.List(viewer, id, resources.ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if p.LinkStatus != resources.LinkStatusUnavailable || len(p.Items) != 3 {
		t.Fatalf("list %+v", p)
	}
	n1 := item(t, p, "n1")
	v, err := s.ConfirmLink(operator, id, n1.ID, resources.LinkInput{TargetModule: repo.TargetAsset, TargetID: "asset-42"})
	if err != nil || v.Match != repo.MatchConfirmed || v.MatchedOn != repo.MatchedOnHostname {
		t.Fatalf("manual link %+v %v", v, err)
	}
	p, _ = s.List(viewer, id, resources.ListInput{})
	if m := matches(item(t, p, "n1"), repo.TargetAsset); m["asset-42"] != repo.MatchConfirmed {
		t.Fatalf("manual link not listed: %v", m)
	}
	if p.LinkStatus != resources.LinkStatusUnavailable {
		t.Fatal("status")
	}
	if err := s.RemoveLink(operator, id, n1.ID, v.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveLink(operator, id, n1.ID, v.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("second remove %v", err)
	}
	e.Audit.Flush(context.Background())
	var confirms, removes int
	for _, r := range e.Repo.Audit() {
		switch r.Action {
		case "teleport.link.confirm":
			confirms++
		case "teleport.link.remove":
			removes++
		}
	}
	if confirms != 1 || removes != 2 {
		t.Fatalf("audited confirms %d removes %d", confirms, removes)
	}
	// A failing directory also degrades to unavailable.
	e2, s2, id2 := setup(t, &resources.FakeDirectory{Err: errors.New("inventory down")})
	p, err = s2.List(viewer, id2, resources.ListInput{})
	if err != nil || p.LinkStatus != resources.LinkStatusUnavailable {
		t.Fatalf("failing directory %+v %v", p.LinkStatus, err)
	}
	_ = e2
	// No linker at all.
	s.Linker = nil
	if p, _ := s.List(viewer, id, resources.ListInput{}); p.LinkStatus != resources.LinkStatusUnavailable {
		t.Fatal("nil linker")
	}
}

// Link routes validate input, need resources:link and stay in the cluster.
func TestLinkRefusals(t *testing.T) {
	e, s, id := setup(t, resources.UnavailableDirectory{})
	p, _ := s.List(viewer, id, resources.ListInput{})
	rid := item(t, p, "n1").ID
	for _, in := range []resources.LinkInput{{TargetModule: "cmdb", TargetID: "x"}, {TargetModule: repo.TargetAsset},
		{TargetModule: repo.TargetAsset, TargetID: "a b"}, {TargetModule: repo.TargetAsset, TargetID: string(make([]byte, 129))}} {
		var fe *clusters.FieldError
		if _, err := s.ConfirmLink(operator, id, rid, in); !errors.As(err, &fe) {
			t.Fatalf("%+v: %v", in, err)
		}
	}
	if _, err := s.ConfirmLink(viewer, id, rid, resources.LinkInput{TargetModule: repo.TargetAsset, TargetID: "a"}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer: %v", err)
	}
	if err := s.RemoveLink(viewer, id, rid, "x"); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer remove: %v", err)
	}
	other := e.Register(t, ct.TenantA, "staging")
	if _, err := s.ConfirmLink(admin, other.ID, rid, resources.LinkInput{TargetModule: repo.TargetAsset, TargetID: "a"}); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("other cluster's resource: %v", err)
	}
	if _, err := s.ConfirmLink(ct.As(ct.TenantB, ct.Admin), id, rid, resources.LinkInput{TargetModule: repo.TargetAsset, TargetID: "a"}); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("cross-tenant: %v", err)
	}
	v, _ := s.ConfirmLink(admin, id, rid, resources.LinkInput{TargetModule: repo.TargetAsset, TargetID: "a"})
	p, _ = s.List(viewer, id, resources.ListInput{})
	if err := s.RemoveLink(admin, id, item(t, p, "n2").ID, v.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("link of another resource: %v", err)
	}
}

func TestAddrIP(t *testing.T) {
	for in, want := range map[string]string{"10.0.0.5:3022": "10.0.0.5", "10.0.0.5": "10.0.0.5", "[2001:db8::1]:22": "2001:db8::1",
		"[::ffff:10.0.0.1]:22": "10.0.0.1", "web-1:3022": "", "": "", "@tunnel:node": ""} {
		if got := resources.AddrIP(in); got != want {
			t.Errorf("AddrIP(%q) = %q, want %q", in, got, want)
		}
	}
}
