package resources_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gravitational/trace"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/resources"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

func names(p resources.Page) []string {
	var out []string
	for _, it := range p.Items {
		out = append(out, it.Name)
	}
	return out
}

// The list merges live resources with offline snapshots, filters by kind,
// label, query and status, and pages with an opaque cursor.
func TestListFiltersAndPages(t *testing.T) {
	e, s, id := setup(t, resources.UnavailableDirectory{})
	ctx := context.Background()
	// An offline and a flagged snapshot (not in Teleport any more).
	off, _ := e.Repo.UpsertSnapshot(ctx, repo.ResourceSnapshot{TenantID: ct.TenantA, ClusterID: id, Kind: repo.KindNode, TeleportName: "old-1",
		Hostname: "old-1", Labels: map[string]string{"env": "prod"}, OfflineSince: e.Now().Add(-time.Minute), LastSeenAt: e.Now().Add(-time.Minute)})
	_, _ = e.Repo.UpsertSnapshot(ctx, repo.ResourceSnapshot{TenantID: ct.TenantA, ClusterID: id, Kind: repo.KindDB, TeleportName: "pg",
		OfflineSince: e.Now().Add(-time.Hour), FlaggedAt: e.Now()})

	p, err := s.List(viewer, id, resources.ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if got := names(p); len(got) != 5 || p.Next != "" {
		t.Fatalf("all: %v next %q", got, p.Next)
	}
	n1 := item(t, p, "n1")
	if n1.Status != resources.StatusOnline || n1.AgentVersion != "19.0.1" || n1.Hostname != "web-1" || n1.ID == "" || n1.LastSeenAt == nil {
		t.Fatalf("n1 %+v", n1)
	}
	if o := item(t, p, "old-1"); o.Status != resources.StatusOffline || o.OfflineSince == nil || o.ID != off.ID {
		t.Fatalf("old-1 %+v", o)
	}
	if f := item(t, p, "pg"); f.Status != resources.StatusFlagged || f.FlaggedAt == nil {
		t.Fatalf("pg %+v", f)
	}
	for _, c := range []struct {
		in   resources.ListInput
		want []string
	}{
		{resources.ListInput{Kind: repo.KindApp}, []string{"grafana"}},
		{resources.ListInput{Label: "env=prod"}, []string{"n1", "old-1"}},
		{resources.ListInput{Q: "db"}, []string{"n2"}},
		{resources.ListInput{Status: resources.StatusOnline}, []string{"n1", "n2", "grafana"}},
		{resources.ListInput{Status: resources.StatusOffline}, []string{"old-1"}},
		{resources.ListInput{Status: resources.StatusFlagged}, []string{"pg"}},
		{resources.ListInput{Status: resources.StatusOffline, Q: "OLD"}, []string{"old-1"}},
		{resources.ListInput{Kind: repo.KindNode, Status: resources.StatusOffline, Label: "env=dev"}, nil},
	} {
		p, err := s.List(viewer, id, c.in)
		if err != nil {
			t.Fatalf("%+v: %v", c.in, err)
		}
		if got := names(p); len(got) != len(c.want) || (len(got) > 0 && !equal(got, c.want)) {
			t.Errorf("%+v: %v, want %v", c.in, got, c.want)
		}
	}
	// Paging two at a time walks every resource once.
	var seen []string
	next := ""
	for i := 0; i < 10; i++ {
		p, err := s.List(viewer, id, resources.ListInput{Limit: 2, Next: next})
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, names(p)...)
		if next = p.Next; next == "" {
			break
		}
	}
	if len(seen) != 5 {
		t.Fatalf("paged %v", seen)
	}
	pages := 0
	next = ""
	for {
		p, _ := s.List(viewer, id, resources.ListInput{Limit: 1, Next: next, Status: resources.StatusOffline})
		pages++
		if next = p.Next; next == "" {
			break
		}
	}
	if pages != 1 {
		t.Fatalf("offline pages %d", pages)
	}
}

func equal(a, b []string) bool {
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestListRefusals(t *testing.T) {
	e, s, id := setup(t, nil)
	for _, in := range []resources.ListInput{{Kind: "server"}, {Label: "novalue"}, {Label: "=x"}, {Status: "dead"},
		{Q: string(make([]byte, 129))}, {Q: "a\x00b"}, {Next: "!!"}, {Next: "e30"}} {
		_, err := s.List(viewer, id, in)
		var fe *clusters.FieldError
		if in.Next == "e30" { // "{}" decodes to the start
			if err != nil {
				t.Fatalf("empty cursor: %v", err)
			}
			continue
		}
		if !errors.As(err, &fe) {
			t.Errorf("%+v: %v", in, err)
		}
	}
	if _, err := s.List(ct.As(ct.TenantA, ct.Nobody), id, resources.ListInput{}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("no permission: %v", err)
	}
	if _, err := s.List(ct.As(ct.TenantB, ct.Admin), id, resources.ListInput{}); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("cross-tenant: %v", err)
	}
	e.Teleport.FailNext("ListResources", trace.ConnectionProblem(nil, "down"))
	if _, err := s.List(viewer, id, resources.ListInput{}); !errors.Is(err, teleportapi.ErrUnreachable) {
		t.Fatalf("outage: %v", err)
	}
	e.Repo.FailNext("ListSnapshots")
	if _, err := s.List(viewer, id, resources.ListInput{}); err == nil {
		t.Fatal("store failure ignored")
	}
	e.Repo.FailNext("ListClusterLinks")
	if _, err := s.List(viewer, id, resources.ListInput{}); err == nil {
		t.Fatal("store failure ignored")
	}
}

func TestBoundLabelsAndKinds(t *testing.T) {
	in := map[string]string{}
	for i := 0; i < 100; i++ {
		in[string(rune('A'+i%26))+string(rune('a'+i/26))] = "v"
	}
	if got := resources.BoundLabels(in); len(got) != resources.MaxLabels {
		t.Fatalf("%d labels kept", len(got))
	}
	if got := resources.BoundLabels(map[string]string{"a": "b"}); got["a"] != "b" {
		t.Fatal("small label set changed")
	}
	for _, k := range repo.ResourceKinds {
		if resources.ModuleKind(resources.TeleportKind(k)) != k {
			t.Fatalf("kind %s does not round-trip", k)
		}
	}
	if resources.ModuleKind("lock") != "" || resources.TeleportKind("x") != "" {
		t.Fatal("unknown kinds map")
	}
}
