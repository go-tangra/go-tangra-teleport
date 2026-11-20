package teleportapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/trace"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
)

// stubEnroll records what the real adapter sends for tokens, watches and
// event searches.
type stubEnroll struct {
	created  types.ProvisionToken
	tokens   []types.ProvisionToken
	pages    int
	deleted  string
	watch    types.Watch
	watcher  types.Watcher
	from, to time.Time
	types    []string
	order    types.EventOrder
	evs      []apievents.AuditEvent
	err      error
}

func (s *stubEnroll) CreateToken(_ context.Context, t types.ProvisionToken) error {
	s.created = t
	return s.err
}

func (s *stubEnroll) ListProvisionTokens(_ context.Context, _ int, next string, _ types.SystemRoles, _ string) ([]types.ProvisionToken, string, error) {
	s.pages++
	if s.err != nil {
		return nil, "", s.err
	}
	// Two pages: the first token, then the rest.
	if next == "" && len(s.tokens) > 1 {
		return s.tokens[:1], "p2", nil
	}
	if next == "p2" {
		return s.tokens[1:], "", nil
	}
	return s.tokens, "", nil
}

func (s *stubEnroll) DeleteToken(_ context.Context, name string) error {
	s.deleted = name
	return s.err
}

func (s *stubEnroll) GetClusterCACert(context.Context) (*proto.GetClusterCACertResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &proto.GetClusterCACertResponse{TLSCA: fakeCA()}, nil
}

func (s *stubEnroll) NewWatcher(_ context.Context, w types.Watch) (types.Watcher, error) {
	s.watch = w
	return s.watcher, s.err
}

func (s *stubEnroll) SearchEvents(_ context.Context, from, to time.Time, _ string, ts []string, _ int, o types.EventOrder, _, _ string) ([]apievents.AuditEvent, string, error) {
	s.from, s.to, s.types, s.order = from, to, ts, o
	return s.evs, "next-key", s.err
}

func (s *stubEnroll) SearchSessionEvents(_ context.Context, from, to time.Time, _ int, o types.EventOrder, _ string) ([]apievents.AuditEvent, string, error) {
	s.from, s.to, s.order = from, to, o
	return s.evs, "", s.err
}

func provToken(t *testing.T, name string) types.ProvisionToken {
	t.Helper()
	tok, err := types.NewProvisionToken(name, types.SystemRoles{types.RoleNode}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestRealCreateJoinToken(t *testing.T) {
	st := &stubEnroll{}
	r := &real{e: st}
	exp := time.Now().Add(30 * time.Minute).Truncate(time.Second)
	tok, err := r.CreateJoinToken(context.Background(), JoinTokenSpec{Roles: []string{RoleNode}, Expires: exp})
	if err != nil {
		t.Fatal(err)
	}
	name := string(tok.Name.Reveal())
	if len(name) != 2*tokenBytes || st.created.GetName() != name {
		t.Fatalf("token name %q, sent %q", name, st.created.GetName())
	}
	if st.created.GetJoinMethod() != types.JoinMethodToken || !st.created.GetRoles().Include(types.RoleNode) {
		t.Fatalf("sent %v %v", st.created.GetJoinMethod(), st.created.GetRoles())
	}
	if !st.created.Expiry().Equal(exp.UTC()) || !tok.Expires.Equal(exp.UTC()) {
		t.Fatalf("expiry %v / %v", st.created.Expiry(), tok.Expires)
	}
	if _, err := r.CreateJoinToken(context.Background(), JoinTokenSpec{Expires: exp}); err == nil {
		t.Fatal("a token without a role was created")
	}
	st.err = trace.AlreadyExists("token %s exists", name)
	_, err = r.CreateJoinToken(context.Background(), JoinTokenSpec{Roles: []string{RoleNode}, Expires: exp})
	if !errors.Is(err, ErrConflict) || strings.Contains(err.Error(), name) {
		t.Fatalf("create error %v", err)
	}
}

func TestRealDeleteJoinTokenFindsByHash(t *testing.T) {
	st := &stubEnroll{tokens: []types.ProvisionToken{provToken(t, "aaaa"), provToken(t, "bbbb")}}
	r := &real{e: st}
	if err := r.DeleteJoinToken(context.Background(), TokenHash(secrets.NewSecret([]byte("bbbb")))); err != nil {
		t.Fatal(err)
	}
	if st.deleted != "bbbb" || st.pages != 2 {
		t.Fatalf("deleted %q after %d pages", st.deleted, st.pages)
	}
	st.deleted = ""
	err := r.DeleteJoinToken(context.Background(), TokenHash(secrets.NewSecret([]byte("cccc"))))
	if !trace.IsNotFound(err) || st.deleted != "" {
		t.Fatalf("unknown token: %v, deleted %q", err, st.deleted)
	}
	st.err = trace.AccessDenied("cannot list token bbbb")
	err = r.DeleteJoinToken(context.Background(), TokenHash(secrets.NewSecret([]byte("bbbb"))))
	if !errors.Is(err, ErrRejected) || strings.Contains(err.Error(), "bbbb") {
		t.Fatalf("list error %v", err)
	}
}

// tWatcher is a scriptable teleport/api watcher.
type tWatcher struct {
	ch   chan types.Event
	done chan struct{}
	err  error
}

func (w *tWatcher) Events() <-chan types.Event { return w.ch }
func (w *tWatcher) Done() <-chan struct{}      { return w.done }
func (w *tWatcher) Close() error               { close(w.done); return nil }
func (w *tWatcher) Error() error               { return w.err }

func TestRealWatchTranslatesEvents(t *testing.T) {
	tw := &tWatcher{ch: make(chan types.Event, 8), done: make(chan struct{})}
	st := &stubEnroll{watcher: tw}
	c := Limit(&real{e: st}, Limits{})
	w, err := c.Watch(context.Background(), WatchKinds)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.watch.Kinds) != len(WatchKinds) || !st.watch.AllowPartialSuccess {
		t.Fatalf("watch %+v", st.watch)
	}
	node, err := types.NewServerWithLabels("n-1", types.KindNode, types.ServerSpecV2{Hostname: "web-1", Addr: "10.0.0.5:3022", Version: "19.0.1"},
		map[string]string{"env": "prod"})
	if err != nil {
		t.Fatal(err)
	}
	tw.ch <- types.Event{Type: types.OpInit}
	tw.ch <- types.Event{Type: types.OpPut, Resource: node}
	tw.ch <- types.Event{Type: types.OpPut} // no resource: dropped
	tw.ch <- types.Event{Type: types.OpUnreliable}
	tw.ch <- types.Event{Type: types.OpDelete, Resource: &types.ResourceHeader{Kind: types.KindNode, Metadata: types.Metadata{Name: "n-1"}}}
	var got []WatchEvent
	for len(got) < 3 {
		got = append(got, <-w.Events())
	}
	if got[0].Op != OpInit || got[1].Op != OpPut || got[2].Op != OpDelete {
		t.Fatalf("ops %+v", got)
	}
	r := got[1].Resource
	if r.Name != "n-1" || r.Hostname != "web-1" || r.Addr != "10.0.0.5:3022" || r.Version != "19.0.1" || r.Labels["env"] != "prod" {
		t.Fatalf("resource %+v", r)
	}
	if got[2].Kind != KindNode || got[2].Name != "n-1" {
		t.Fatalf("delete %+v", got[2])
	}
	tw.err = trace.ConnectionProblem(nil, "stream closed")
	_ = w.Close()
	if _, ok := <-w.Events(); ok {
		t.Fatal("events not closed after Close")
	}
	if !errors.Is(w.Error(), ErrUnreachable) {
		t.Fatalf("watch error %v", w.Error())
	}
	<-w.Done()

	st.err = trace.AccessDenied("no")
	if _, err := c.Watch(context.Background(), WatchKinds); !errors.Is(err, ErrRejected) {
		t.Fatalf("open error %v", err)
	}
}

func TestResourceOfServerKinds(t *testing.T) {
	app, err := types.NewAppV3(types.Metadata{Name: "grafana"}, types.AppSpecV3{URI: "http://localhost:3000"})
	if err != nil {
		t.Fatal(err)
	}
	as, err := types.NewAppServerV3(types.Metadata{Name: "grafana"}, types.AppServerSpecV3{Hostname: "apps-1", HostID: "h1", Version: "19.0.0", App: app})
	if err != nil {
		t.Fatal(err)
	}
	r := resourceOf(as)
	if r.Kind != KindApp || r.Name != "grafana" || r.Hostname != "apps-1" || r.Version != "19.0.0" {
		t.Fatalf("app server %+v", r)
	}
}

func TestRealSearchEvents(t *testing.T) {
	login := &apievents.UserLogin{Metadata: apievents.Metadata{ID: "e1", Type: "user.login", Code: "T1000W", Time: time.Unix(1700000000, 0)},
		UserMetadata: apievents.UserMetadata{User: "alice"}, Status: apievents.Status{Success: false, Error: "bad password"}}
	st := &stubEnroll{evs: []apievents.AuditEvent{login}}
	c := Limit(&real{e: st}, Limits{})
	from, to := time.Now().Add(-time.Hour), time.Now()
	p, err := c.SearchEvents(context.Background(), EventQuery{From: from, To: to, Types: []string{"user.login"}, Limit: 10, Ascending: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.Next != "next-key" || len(p.Items) != 1 || st.order != types.EventOrderAscending || st.types[0] != "user.login" {
		t.Fatalf("page %+v order %v", p, st.order)
	}
	e := p.Items[0]
	var raw map[string]any
	if err := json.Unmarshal(e.Raw, &raw); err != nil {
		t.Fatal(err)
	}
	if e.ID != "e1" || e.Type != "user.login" || e.Code != "T1000W" || raw["user"] != "alice" || raw["success"] != false {
		t.Fatalf("event %+v raw %v", e, raw)
	}
	if _, err := c.SearchSessions(context.Background(), EventQuery{From: from, To: to}); err != nil || st.order != types.EventOrderDescending {
		t.Fatalf("sessions: %v order %v", err, st.order)
	}
	if _, err := c.SearchEvents(context.Background(), EventQuery{To: to}); !errors.Is(err, ErrRejected) {
		t.Fatalf("no window: %v", err)
	}
	if _, err := c.SearchSessions(context.Background(), EventQuery{From: to, To: from}); !errors.Is(err, ErrRejected) {
		t.Fatalf("reversed window: %v", err)
	}
	st.err = trace.ConnectionProblem(nil, "down")
	if _, err := c.SearchEvents(context.Background(), EventQuery{From: from, To: to}); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("outage: %v", err)
	}
	if _, err := c.SearchSessions(context.Background(), EventQuery{From: from, To: to}); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("outage: %v", err)
	}
}

func TestFakeJoinTokens(t *testing.T) {
	f := NewFake()
	c := Limit(f, Limits{})
	ctx := context.Background()
	now := time.Now()
	tok, err := c.CreateJoinToken(ctx, JoinTokenSpec{Roles: []string{RoleNode}, Expires: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	name := string(tok.Name.Reveal())
	if f.Join(name, RoleNode, now) != nil || f.Join(name, RoleApp, now) == nil || f.Join(name, RoleNode, now.Add(2*time.Minute)) == nil {
		t.Fatal("join checks")
	}
	if got := f.IssuedTokens(); len(got) != 1 || got[0] != name || f.TokenCount() != 1 {
		t.Fatalf("issued %v", got)
	}
	if _, err := c.CreateJoinToken(ctx, JoinTokenSpec{Roles: []string{"Admin"}, Expires: now}); !errors.Is(err, ErrRejected) {
		t.Fatalf("admin role: %v", err)
	}
	if _, err := c.CreateJoinToken(ctx, JoinTokenSpec{Expires: now}); !errors.Is(err, ErrRejected) {
		t.Fatalf("no role: %v", err)
	}
	if err := c.DeleteJoinToken(ctx, TokenHash(tok.Name)); err != nil {
		t.Fatal(err)
	}
	if f.Join(name, RoleNode, now) == nil || f.TokenCount() != 0 {
		t.Fatal("a revoked token still joins")
	}
	err = c.DeleteJoinToken(ctx, TokenHash(tok.Name))
	if !errors.Is(err, ErrNotFound) || Detail(err) != "" {
		t.Fatalf("second delete: %v (detail %q)", err, Detail(err))
	}
	f.FailNext("CreateJoinToken", trace.ConnectionProblem(nil, "x"))
	if _, err := c.CreateJoinToken(ctx, JoinTokenSpec{Roles: []string{RoleNode}, Expires: now}); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("outage: %v", err)
	}
}

func TestFakeWatch(t *testing.T) {
	f := NewFake()
	c := Limit(f, Limits{})
	w, err := c.Watch(context.Background(), []string{KindNode})
	if err != nil {
		t.Fatal(err)
	}
	if ev := <-w.Events(); ev.Op != OpInit {
		t.Fatalf("first event %+v", ev)
	}
	if n := f.Emit(WatchEvent{Op: OpPut, Kind: KindApp, Name: "x"}); n != 0 {
		t.Fatal("an unwatched kind was delivered")
	}
	if n := f.Emit(WatchEvent{Op: OpPut, Kind: KindNode, Name: "n1"}); n != 1 || f.Watchers() != 1 {
		t.Fatalf("delivered %d", n)
	}
	if ev := <-w.Events(); ev.Name != "n1" {
		t.Fatalf("event %+v", ev)
	}
	f.EndWatches(trace.ConnectionProblem(nil, "gone"))
	<-w.Done()
	if !errors.Is(w.Error(), ErrUnreachable) || f.Watchers() != 0 {
		t.Fatalf("ended: %v, %d open", w.Error(), f.Watchers())
	}
	w2, _ := c.Watch(context.Background(), []string{KindNode})
	_ = w2.Close()
	if f.Watchers() != 0 || w2.Error() != nil {
		t.Fatal("closed watcher still open")
	}
	f.FailNext("Watch", trace.AccessDenied("no"))
	if _, err := c.Watch(context.Background(), nil); !errors.Is(err, ErrRejected) {
		t.Fatalf("watch error %v", err)
	}
}

func TestFakeSearch(t *testing.T) {
	f := NewFake()
	base := time.Unix(1700000000, 0).UTC()
	for i, typ := range []string{"user.login", "session.start", "user.login"} {
		f.AuditEvents = append(f.AuditEvents, AuditEvent{ID: string(rune('a' + i)), Type: typ, Time: base.Add(time.Duration(i) * time.Minute)})
	}
	f.SessionEvents = f.AuditEvents[1:2]
	q := EventQuery{From: base, To: base.Add(time.Hour), Types: []string{"user.login"}, Limit: 1}
	p, err := f.SearchEvents(context.Background(), q)
	if err != nil || len(p.Items) != 1 || p.Items[0].ID != "c" || p.Next == "" {
		t.Fatalf("newest first: %+v %v", p, err)
	}
	q.Next, q.Ascending = "", true
	if p, _ = f.SearchEvents(context.Background(), q); p.Items[0].ID != "a" {
		t.Fatalf("oldest first: %+v", p)
	}
	q.From = base.Add(30 * time.Second)
	if p, _ = f.SearchEvents(context.Background(), q); p.Items[0].ID != "c" {
		t.Fatalf("window: %+v", p)
	}
	if p, err = f.SearchSessions(context.Background(), EventQuery{From: base, To: base.Add(time.Hour)}); err != nil || len(p.Items) != 1 {
		t.Fatalf("sessions %+v %v", p, err)
	}
	f.SetErr(trace.ConnectionProblem(nil, "x"))
	if _, err := f.SearchSessions(context.Background(), q); err == nil {
		t.Fatal("outage")
	}
	if _, err := f.SearchEvents(context.Background(), q); err == nil {
		t.Fatal("outage")
	}
}

func TestFakeListResourcesFilters(t *testing.T) {
	f := NewFake()
	f.Resources = []Resource{{Kind: KindNode, Name: "n1", Hostname: "web-1", Labels: map[string]string{"env": "prod"}},
		{Kind: KindNode, Name: "n2", Hostname: "db-1", Labels: map[string]string{"env": "dev"}}}
	p, _ := f.ListResources(context.Background(), KindNode, ListOptions{Labels: map[string]string{"env": "prod"}})
	if len(p.Items) != 1 || p.Items[0].Name != "n1" {
		t.Fatalf("labels %+v", p)
	}
	p, _ = f.ListResources(context.Background(), KindNode, ListOptions{Search: []string{"DB"}})
	if len(p.Items) != 1 || p.Items[0].Name != "n2" {
		t.Fatalf("search %+v", p)
	}
	p, _ = f.ListResources(context.Background(), KindNode, ListOptions{Search: []string{"dev"}})
	if len(p.Items) != 1 {
		t.Fatalf("label value search %+v", p)
	}
}

func TestOpaqueDropsDetail(t *testing.T) {
	if opaque(nil) != nil {
		t.Fatal("nil")
	}
	err := opaque(MapError(trace.NotFound("token abc not found")))
	if !errors.Is(err, ErrNotFound) || strings.Contains(err.Error(), "abc") {
		t.Fatalf("%v", err)
	}
	if err := opaque(ErrUnreachable); err != ErrUnreachable {
		t.Fatalf("a bare reason changed: %v", err)
	}
	if err := opaque(trace.AccessDenied("x")); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("denial lost: %v", err)
	}
}

func TestRealCAPins(t *testing.T) {
	st := &stubEnroll{}
	c := Limit(&real{e: st}, Limits{})
	pins, err := c.CAPins(context.Background())
	if err != nil || len(pins) != 1 {
		t.Fatalf("pins %v %v", pins, err)
	}
	st.err = trace.AccessDenied("denied")
	if _, err := c.CAPins(context.Background()); err == nil {
		t.Fatal("error ignored")
	}
}
