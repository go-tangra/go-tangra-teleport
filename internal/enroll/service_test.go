package enroll_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	inventoryv1 "github.com/go-tangra/go-tangra-inventory/sdk/v4/api/proto/inventory/v1"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/enroll"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/enroll/enrolltest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

const (
	host1 = "a1a1a1a1-1111-7111-8111-111111111111"
	host2 = "a2a2a2a2-2222-7222-8222-222222222222"
	host3 = "a3a3a3a3-3333-7333-8333-333333333333"
)

var (
	admin    = ct.As(ct.TenantA, ct.Admin)
	operator = ct.As(ct.TenantA, ct.Operator)
	viewer   = ct.As(ct.TenantA, ct.Viewer)
)

func worker(tenant string) context.Context {
	return authz.WithSubjects(context.Background(), authz.Worker(tenant, "enrollment-render"))
}

type env struct {
	*ct.Env
	inv *enrolltest.Inventory
	svc *enroll.Service
	cid string
}

func setup(t *testing.T) env {
	t.Helper()
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	inv := enrolltest.New()
	inv.AddHost(ct.TenantA, &inventoryv1.TeleportJoinTarget{HostId: host1, Hostname: "web-1", OsName: "ubuntu", OsVersion: "24.04",
		OsArch: "amd64", Manufacturer: "Dell", Model: "R650", AgentOnline: true, Tags: map[string]string{"env": "prod", "team a": "ops"}})
	inv.AddHost(ct.TenantA, &inventoryv1.TeleportJoinTarget{HostId: host2, Hostname: "web-2"})
	inv.AddHost(ct.TenantB, &inventoryv1.TeleportJoinTarget{HostId: host3, Hostname: "other"})
	e.Teleport.Info.ServerVersion = "17.4.2"
	return env{Env: e, inv: inv, cid: c.ID, svc: &enroll.Service{Clusters: e.Service, Repo: e.Repo, Inventory: inv.Dial(), Audit: e.Audit,
		Events: e.Events, Now: e.Now}}
}

func one(t *testing.T, e env, host string) enroll.View {
	t.Helper()
	out, err := e.svc.Create(operator, e.cid, enroll.CreateInput{HostIDs: []string{host}})
	if err != nil || len(out.Items) != 1 {
		t.Fatalf("create: %+v %v", out, err)
	}
	return out.Items[0]
}

func TestLabels(t *testing.T) {
	l := enroll.Labels(enroll.Facts{HostID: host1, Hostname: "web-1", OSName: "ubuntu", OSArch: "amd64",
		Tags: map[string]string{"env": "prod", "team a": "ops\x01", "": "x", "blank": "  ", strings.Repeat("k", 80): "long"}})
	want := map[string]string{"tangra.io/inventory-host": host1, "tangra.io/hostname": "web-1", "tangra.io/os": "ubuntu",
		"tangra.io/arch": "amd64", "tangra.io/tag.env": "prod", "tangra.io/tag.team_a": "ops"}
	if len(l) != len(want) {
		t.Fatalf("labels %v", l)
	}
	for k, v := range want {
		if l[k] != v {
			t.Errorf("%s = %q, want %q", k, l[k], v)
		}
	}
	tags := map[string]string{}
	for i := range 100 {
		tags[strings.Repeat("t", 3)+string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
	}
	if n := len(enroll.Labels(enroll.Facts{HostID: host1, Tags: tags})); n != enroll.MaxLabels {
		t.Fatalf("%d labels", n)
	}
	long := enroll.Labels(enroll.Facts{Hostname: strings.Repeat("é", 200)})["tangra.io/hostname"]
	if len(long) > 255 || !strings.HasPrefix(long, "é") || strings.ContainsRune(long, '�') {
		t.Fatalf("long value %d bytes", len(long))
	}
}

func TestTargets(t *testing.T) {
	e := setup(t)
	got, err := e.svc.ListTargets(operator, e.cid, "web", 0)
	if err != nil || len(got.Items) != 2 || got.Truncated {
		t.Fatalf("targets %+v %v", got, err)
	}
	if got.Items[0].Labels["tangra.io/tag.env"] != "prod" || got.Items[0].Enrollment != nil || !got.Items[0].AgentOnline {
		t.Fatalf("target %+v", got.Items[0])
	}
	one(t, e, host1)
	got, _ = e.svc.ListTargets(operator, e.cid, "web-1", 1)
	if len(got.Items) != 1 || got.Items[0].Enrollment == nil || got.Items[0].Enrollment.State != repo.EnrollDelivered {
		t.Fatalf("enrolled target %+v", got.Items)
	}
	if got, _ := e.svc.ListTargets(operator, e.cid, "", 1); !got.Truncated {
		t.Fatal("not truncated")
	}
	if _, err := e.svc.ListTargets(viewer, e.cid, "", 0); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer: %v", err)
	}
	var fe *clusters.FieldError
	for _, c := range []struct {
		q string
		n int
	}{{strings.Repeat("q", 65), 0}, {"", -1}, {"", 201}} {
		if _, err := e.svc.ListTargets(operator, e.cid, c.q, c.n); !errors.As(err, &fe) {
			t.Errorf("%d: %v", c.n, err)
		}
	}
	e.inv.SetDown(true)
	if _, err := e.svc.ListTargets(operator, e.cid, "", 0); !errors.Is(err, enroll.ErrUnavailable) || !errors.Is(err, secrets.ErrUnavailable) {
		t.Fatalf("down: %v", err)
	}
	none := &enroll.Service{Clusters: e.Service, Repo: e.Repo}
	if _, err := none.ListTargets(operator, e.cid, "", 0); !errors.Is(err, enroll.ErrUnavailable) {
		t.Fatalf("no inventory: %v", err)
	}
	failing := &enroll.Service{Clusters: e.Service, Repo: e.Repo, Inventory: func(context.Context) (inventoryv1.TeleportJoinDeliveryServiceClient, error) {
		return nil, errors.New("dial")
	}}
	if _, err := failing.ListTargets(operator, e.cid, "", 0); !errors.Is(err, enroll.ErrUnavailable) {
		t.Fatalf("dial failure: %v", err)
	}
}

func TestCreate(t *testing.T) {
	e := setup(t)
	e.inv.Refuse(host2, "no_agent")
	out, err := e.svc.Create(operator, e.cid, enroll.CreateInput{HostIDs: []string{host1, host2, host3, host1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Items) != 1 || len(out.Refused) != 2 || out.Refused[0] != (enroll.Refusal{HostID: host2, Reason: "no_agent"}) ||
		out.Refused[1] != (enroll.Refusal{HostID: host3, Reason: "not_found"}) {
		t.Fatalf("created %+v", out)
	}
	v := out.Items[0]
	if v.State != repo.EnrollDelivered || v.Hostname != "web-1" || v.HostID != host1 || !v.ExpiresAt.Equal(e.Now().Add(24*time.Hour)) {
		t.Fatalf("view %+v", v)
	}
	req := e.inv.LastCreate()
	if req.GetTenantId() != ct.TenantA || req.GetClusterId() != e.cid || req.GetEnrollmentId() == "" {
		t.Fatalf("request %+v", req)
	}
	if ev := e.Events.OfType(events.EnrollmentChanged); len(ev) != 1 || ev[0].Payload.(events.Enrollment).EnrollmentID != v.ID {
		t.Fatalf("events %+v", ev)
	}
	n := 72
	if out, err := e.svc.Create(admin, e.cid, enroll.CreateInput{HostIDs: []string{host2}, TTLHours: &n}); err != nil || len(out.Refused) != 1 {
		t.Fatalf("refused only: %+v %v", out, err)
	}
	var fe *clusters.FieldError
	zero, big := 0, 73
	for _, in := range []enroll.CreateInput{{}, {HostIDs: []string{"x"}}, {HostIDs: make([]string, 51)}, {HostIDs: []string{host1}, TTLHours: &zero},
		{HostIDs: []string{host1}, TTLHours: &big}} {
		if _, err := e.svc.Create(operator, e.cid, in); !errors.As(err, &fe) {
			t.Errorf("%+v: %v", in, err)
		}
	}
	if _, err := e.svc.Create(viewer, e.cid, enroll.CreateInput{HostIDs: []string{host1}}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer: %v", err)
	}
	if _, err := e.svc.Create(ct.As(ct.TenantB, ct.Admin), e.cid, enroll.CreateInput{HostIDs: []string{host1}}); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("other tenant: %v", err)
	}
	e.inv.SetDown(true)
	if _, err := e.svc.Create(operator, e.cid, enroll.CreateInput{HostIDs: []string{host1}}); !errors.Is(err, enroll.ErrUnavailable) {
		t.Fatalf("down: %v", err)
	}
	e.inv.SetDown(false)
	// A store failure withdraws the item at inventory.
	e.Repo.FailNext("CreateEnrollment")
	out, err = e.svc.Create(operator, e.cid, enroll.CreateInput{HostIDs: []string{host1}})
	if err == nil {
		t.Fatalf("store failure: %+v", out)
	}
	if e.inv.Calls("CancelTeleportJoin") != 1 {
		t.Fatal("not withdrawn")
	}
	// Partly done: a later failure is a refusal.
	e.Repo.FailNext("CreateEnrollment")
	out, err = e.svc.Create(operator, e.cid, enroll.CreateInput{HostIDs: []string{host2, host1}})
	if err != nil || len(out.Refused) != 2 || out.Refused[1].Reason != "error" {
		t.Fatalf("partial: %+v %v", out, err)
	}
}

func TestRenderAndProgress(t *testing.T) {
	e := setup(t)
	v := one(t, e, host1)
	m, err := e.svc.Render(worker(ct.TenantA), enroll.RenderInput{EnrollmentID: v.ID, HostID: host1, ItemID: "item-" + v.ID[:8]})
	if err != nil {
		t.Fatal(err)
	}
	if m.ProxyAddr != ct.ProxyAddr || len(m.CAPins) != 1 || m.TeleportVersion != "17.4.2" || m.Labels["tangra.io/model"] != "R650" ||
		!m.TokenExpiresAt.Equal(e.Now().Add(enroll.TokenTTL)) {
		t.Fatalf("material %+v", m)
	}
	if err := e.Teleport.Join(string(m.Token.Reveal()), teleportapi.RoleNode, e.Now()); err != nil {
		t.Fatalf("token does not join: %v", err)
	}
	toks, _ := e.Repo.ListJoinTokens(context.Background(), ct.TenantA, e.cid)
	if len(toks) != 1 || toks[0].CreatedBy != "enrollment:"+v.ID || toks[0].ResourceType != repo.KindNode {
		t.Fatalf("tokens %+v", toks)
	}
	p, err := e.svc.List(viewer, e.cid)
	if err != nil || len(p.Items) != 1 || p.Items[0].State != repo.EnrollFetched || p.Stale {
		t.Fatalf("list %+v %v", p, err)
	}

	// Refusals: wrong host, wrong item, wrong tenant, unknown, past the budget.
	for _, in := range []enroll.RenderInput{{EnrollmentID: v.ID, HostID: host2}, {EnrollmentID: v.ID, HostID: host1, ItemID: "other"}} {
		if _, err := e.svc.Render(worker(ct.TenantA), in); !errors.Is(err, repo.ErrNotFound) {
			t.Errorf("%+v: %v", in, err)
		}
	}
	if _, err := e.svc.Render(worker(ct.TenantB), enroll.RenderInput{EnrollmentID: v.ID, HostID: host1}); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("other tenant: %v", err)
	}
	for range enroll.MaxRenders - 1 {
		if _, err := e.svc.Render(worker(ct.TenantA), enroll.RenderInput{EnrollmentID: v.ID, HostID: host1}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.Render(worker(ct.TenantA), enroll.RenderInput{EnrollmentID: v.ID, HostID: host1}); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("budget: %v", err)
	}

	// Joined: the node's snapshot appears, the link is confirmed.
	e.inv.Set(v.ID, inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_JOINED, "", "node-uuid-1")
	p, _ = e.svc.List(viewer, e.cid)
	if p.Items[0].State != repo.EnrollJoined || p.Items[0].NodeHostUUID != "node-uuid-1" || p.Items[0].LinkID != "" {
		t.Fatalf("joined %+v", p.Items[0])
	}
	snap, err := e.Repo.UpsertSnapshot(context.Background(), repo.ResourceSnapshot{ID: "b1b1b1b1-1111-7111-8111-111111111111", TenantID: ct.TenantA,
		ClusterID: e.cid, Kind: repo.KindNode, TeleportName: "node-uuid-1", Hostname: "web-1", Online: true})
	if err != nil {
		t.Fatal(err)
	}
	sweep := &enroll.Sweep{Service: e.svc}
	sweep.Once(context.Background())
	got, _ := e.Repo.GetEnrollment(context.Background(), ct.TenantA, v.ID)
	links, _ := e.Repo.ListLinks(context.Background(), ct.TenantA, snap.ID)
	if got.LinkID == "" || len(links) != 1 || links[0].TargetID != host1 || links[0].Match != repo.MatchConfirmed {
		t.Fatalf("link %+v %+v", got, links)
	}
	if ev := e.Events.OfType(events.ResourceLinked); len(ev) != 1 {
		t.Fatalf("linked events %+v", ev)
	}
	// Rendering a joined enrollment is refused.
	if _, err := e.svc.Render(worker(ct.TenantA), enroll.RenderInput{EnrollmentID: v.ID, HostID: host1}); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("joined render: %v", err)
	}
}

func TestLinkConfirmsCandidate(t *testing.T) {
	e := setup(t)
	v := one(t, e, host1)
	snap, _ := e.Repo.UpsertSnapshot(context.Background(), repo.ResourceSnapshot{ID: "b1b1b1b1-1111-7111-8111-111111111111", TenantID: ct.TenantA,
		ClusterID: e.cid, Kind: repo.KindNode, TeleportName: "n1", Hostname: "web-1", Online: true})
	_ = e.Repo.CreateLink(context.Background(), repo.ResourceLink{ID: "c1c1c1c1-1111-7111-8111-111111111111", TenantID: ct.TenantA, SnapshotID: snap.ID,
		TargetModule: repo.TargetInventory, TargetID: host1, Match: "candidate", MatchedOn: repo.MatchedOnHostname})
	e.inv.Set(v.ID, inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_JOINED, "", "n1")
	p, _ := e.svc.List(viewer, e.cid)
	links, _ := e.Repo.ListLinks(context.Background(), ct.TenantA, snap.ID)
	if p.Items[0].LinkID != "c1c1c1c1-1111-7111-8111-111111111111" || len(links) != 1 || links[0].Match != repo.MatchConfirmed {
		t.Fatalf("%+v %+v", p.Items[0], links)
	}
}

func TestRenderFailures(t *testing.T) {
	e := setup(t)
	v := one(t, e, host1)
	w := worker(ct.TenantA)
	in := enroll.RenderInput{EnrollmentID: v.ID, HostID: host1}
	for _, m := range []string{"CAPins", "Ping", "CreateJoinToken"} {
		e.Teleport.FailNext(m, teleportapi.ErrUnreachable)
		if _, err := e.svc.Render(w, in); err == nil {
			t.Errorf("%s failure ignored", m)
		}
	}
	e.Repo.FailNext("CreateJoinToken")
	if _, err := e.svc.Render(w, in); err == nil {
		t.Fatal("store failure ignored")
	}
	if n := e.Teleport.TokenCount(); n != 0 {
		t.Fatalf("%d tokens left after rollback", n)
	}
	e.Repo.FailNext("AddEnrollmentRender")
	if _, err := e.svc.Render(w, in); err == nil || errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("render count failure: %v", err)
	}
	// Labels fall back to the stored facts while inventory is down.
	e.inv.SetDown(true)
	m, err := e.svc.Render(w, in)
	if err != nil || len(m.Labels) != 2 || m.Labels["tangra.io/hostname"] != "web-1" {
		t.Fatalf("fallback labels %+v %v", m.Labels, err)
	}
	e.inv.SetDown(false)
	if _, err := e.svc.Render(w, enroll.RenderInput{EnrollmentID: "d1d1d1d1-1111-7111-8111-111111111111", HostID: host1}); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	e.Advance(25 * time.Hour)
	if _, err := e.svc.Render(w, in); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("expired: %v", err)
	}
}

func TestCancelAndRetry(t *testing.T) {
	e := setup(t)
	v := one(t, e, host1)
	if _, err := e.svc.Retry(operator, e.cid, v.ID); !errors.Is(err, repo.ErrConflict) {
		t.Fatalf("retry running: %v", err)
	}
	if _, err := e.svc.Cancel(viewer, e.cid, v.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer cancel: %v", err)
	}
	c, err := e.svc.Cancel(operator, e.cid, v.ID)
	if err != nil || c.State != repo.EnrollCancelled {
		t.Fatalf("cancel %+v %v", c, err)
	}
	if j := e.inv.Join(v.ID); j.GetState() != inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_CANCELLED {
		t.Fatalf("inventory join %v", j.GetState())
	}
	if c, err := e.svc.Cancel(operator, e.cid, v.ID); err != nil || c.State != repo.EnrollCancelled || e.inv.Calls("CancelTeleportJoin") != 1 {
		t.Fatalf("cancel again %+v %v", c, err)
	}
	if _, err := e.svc.Cancel(operator, e.cid, "e1e1e1e1-1111-7111-8111-111111111111"); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	r, err := e.svc.Retry(operator, e.cid, v.ID)
	if err != nil || r.ID == v.ID || r.HostID != host1 || r.State != repo.EnrollDelivered {
		t.Fatalf("retry %+v %v", r, err)
	}
	e.inv.SetDown(true)
	if _, err := e.svc.Cancel(operator, e.cid, r.ID); !errors.Is(err, enroll.ErrUnavailable) {
		t.Fatalf("cancel down: %v", err)
	}
	if _, err := e.svc.Retry(operator, e.cid, v.ID); !errors.Is(err, enroll.ErrUnavailable) {
		t.Fatalf("retry down: %v", err)
	}
	e.inv.SetDown(false)
	e.inv.Refuse(host1, "retired")
	var re *enroll.RefusedError
	if _, err := e.svc.Retry(operator, e.cid, v.ID); !errors.As(err, &re) || re.Reason != "retired" || err.Error() == "" {
		t.Fatalf("retry refused: %v", err)
	}
	// Cancelled at inventory already (unknown there): still cancelled here.
	e.inv.Forget(r.ID)
	if c, err := e.svc.Cancel(operator, e.cid, r.ID); err != nil || c.State != repo.EnrollCancelled {
		t.Fatalf("forgotten cancel %+v %v", c, err)
	}
	e.Repo.FailNext("UpdateEnrollment")
	v2 := one(t, e, host2)
	e.Repo.FailNext("UpdateEnrollment")
	if _, err := e.svc.Cancel(operator, e.cid, v2.ID); err == nil {
		t.Fatal("store failure ignored")
	}
}

func TestProgressStatesAndExpiry(t *testing.T) {
	e := setup(t)
	v := one(t, e, host1)
	w := one(t, e, host2)
	e.inv.Set(v.ID, inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_FAILED, "install_failed", "")
	e.inv.Set(w.ID, inventoryv1.TeleportJoinState(99), "Bad Reason!", "")
	p, _ := e.svc.List(viewer, e.cid)
	byID := map[string]enroll.View{}
	for _, x := range p.Items {
		byID[x.ID] = x
	}
	if byID[v.ID].State != repo.EnrollFailed || byID[v.ID].Reason != "install_failed" || byID[v.ID].AgentOnline == nil {
		t.Fatalf("failed %+v", byID[v.ID])
	}
	if byID[w.ID].State != repo.EnrollPending || byID[w.ID].Reason != "" {
		t.Fatalf("unknown state kept %+v", byID[w.ID])
	}
	// Inventory down: stale, stored states.
	e.inv.SetDown(true)
	if p, err := e.svc.List(viewer, e.cid); err != nil || !p.Stale {
		t.Fatalf("stale %+v %v", p, err)
	}
	e.inv.SetDown(false)
	// Unknown to inventory after its expiry: expired.
	e.inv.Forget(w.ID)
	e.Advance(25 * time.Hour)
	(&enroll.Sweep{Service: e.svc}).Once(context.Background())
	got, _ := e.Repo.GetEnrollment(context.Background(), ct.TenantA, w.ID)
	if got.State != repo.EnrollExpired {
		t.Fatalf("expired %+v", got)
	}
	// Retry of a long-lived enrollment keeps its lifetime.
	r, err := e.svc.Retry(operator, e.cid, w.ID)
	if err != nil || !r.ExpiresAt.Equal(e.Now().Add(24*time.Hour)) {
		t.Fatalf("retry %+v %v", r, err)
	}
	if _, err := e.svc.List(ct.As(ct.TenantA, ct.Nobody), e.cid); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("nobody: %v", err)
	}
	e.Repo.FailNext("ListEnrollments")
	if _, err := e.svc.List(viewer, e.cid); err == nil {
		t.Fatal("store failure ignored")
	}
}

// flaky fails GetTeleportJoins once.
type flaky struct {
	inventoryv1.TeleportJoinDeliveryServiceClient
	failed bool
}

func (f *flaky) GetTeleportJoins(ctx context.Context, in *inventoryv1.GetTeleportJoinsRequest, o ...grpc.CallOption) (*inventoryv1.GetTeleportJoinsResponse, error) {
	if !f.failed {
		f.failed = true
		return nil, errors.New("boom")
	}
	return f.TeleportJoinDeliveryServiceClient.GetTeleportJoins(ctx, in, o...)
}

func TestSweepRun(t *testing.T) {
	e := setup(t)
	v := one(t, e, host1)
	e.inv.Set(v.ID, inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_INSTALLING, "", "")
	fl := &flaky{TeleportJoinDeliveryServiceClient: e.inv}
	e.svc.Inventory = func(context.Context) (inventoryv1.TeleportJoinDeliveryServiceClient, error) { return fl, nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		(&enroll.Sweep{Service: e.svc, Interval: time.Millisecond, Log: slog.New(slog.DiscardHandler)}).Run(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, _ := e.Repo.GetEnrollment(context.Background(), ct.TenantA, v.ID)
		if got.State == repo.EnrollInstalling {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	got, _ := e.Repo.GetEnrollment(context.Background(), ct.TenantA, v.ID)
	if got.State != repo.EnrollInstalling {
		t.Fatalf("sweep did not progress: %+v", got)
	}
	e.Repo.FailNext("ListActiveEnrollments")
	(&enroll.Sweep{Service: e.svc, Log: slog.New(slog.DiscardHandler)}).Once(context.Background())
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	(&enroll.Sweep{Service: e.svc}).Once(cctx)
}
