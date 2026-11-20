package users_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/trace"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/users"
)

var (
	admin  = ct.As(ct.TenantA, ct.Admin)
	viewer = ct.As(ct.TenantA, ct.Viewer)
)

func setup(t *testing.T) (*ct.Env, *users.Service, string) {
	t.Helper()
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	return e, &users.Service{Clusters: e.Service, Audit: e.Audit, Events: e.Events, Cache: &teleportapi.Cache{KV: teleportapi.NewMemoryKV()}}, c.ID
}

func guard(err error) string {
	var g *clusters.GuardError
	if errors.As(err, &g) {
		return g.Guard
	}
	return ""
}

// lastAudit returns the newest audit row of action.
func lastAudit(t *testing.T, e *ct.Env, action string) repo.AuditRow {
	t.Helper()
	e.Audit.Flush(context.Background())
	rows := e.Repo.Audit()
	for i := len(rows) - 1; i >= 0; i-- {
		if rows[i].Action == action {
			return rows[i]
		}
	}
	t.Fatalf("no %s audit row in %v", action, e.AuditRows())
	return repo.AuditRow{}
}

func TestList(t *testing.T) {
	e, s, id := setup(t)
	e.Teleport.Users = append(e.Teleport.Users, teleportapi.User{Name: "bob", Roles: []string{"access"},
		Labels: map[string]string{users.LabelManaged: "true", users.LabelUser: "018f3a2b-0000-7000-8000-0000000000aa"}, Revision: "u3"})
	e.Teleport.Locks = []teleportapi.Lock{{Name: "l1", TargetKind: "user", Target: "alice"},
		{Name: "l2", TargetKind: "user", Target: "bob", ExpiresAt: e.Now().Add(-time.Hour)}}
	p, err := s.List(viewer, id, users.ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]users.View{}
	for _, u := range p.Items {
		byName[u.Name] = u
	}
	if len(p.Items) != 3 || !byName["alice"].Locked || byName["bob"].Locked || !byName["bob"].Managed ||
		byName["bob"].TangraUserID != "018f3a2b-0000-7000-8000-0000000000aa" || byName["alice"].Managed || byName["alice"].Revision != "u2" ||
		byName["alice"].Logins[0] != "ubuntu" {
		t.Fatalf("list %+v", p.Items)
	}
	if p, _ := s.List(viewer, id, users.ListInput{Q: "ALI"}); len(p.Items) != 1 || p.Items[0].Name != "alice" {
		t.Fatalf("q filter %+v", p.Items)
	}
	if p, _ := s.List(viewer, id, users.ListInput{Limit: 1}); len(p.Items) != 1 || p.Next == "" {
		t.Fatalf("paging %+v", p)
	}
	if _, err := s.List(ct.As(ct.TenantA, ct.Nobody), id, users.ListInput{}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("nobody %v", err)
	}
	if _, err := s.List(ct.As(ct.TenantB, ct.Admin), id, users.ListInput{}); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("other tenant %v", err)
	}
}

// The invite URL is returned once, in the create result only: never in the
// audit row, the event or a later read.
func TestCreateReturnsTheInviteOnce(t *testing.T) {
	e, s, id := setup(t)
	out, err := s.Create(admin, id, users.CreateInput{Name: "carol", Roles: []string{"access", "access"}, Logins: []string{"ubuntu"}})
	if err != nil {
		t.Fatal(err)
	}
	if out.User.Name != "carol" || !slices.Equal(out.User.Roles, []string{"access"}) || out.InviteURL.IsZero() || !out.InviteExpiresAt.After(time.Now()) {
		t.Fatalf("created %+v", out)
	}
	b, _ := json.Marshal(out)
	urls := e.Teleport.IssuedURLs()
	if len(urls) != 1 || !strings.Contains(string(b), urls[0]) {
		t.Fatalf("the response lacks the invite: %s", b)
	}
	row := lastAudit(t, e, "teleport.user.create")
	ev := e.Events.OfType(events.UserCreated)
	if row.Outcome != "success" || row.TargetName != "carol" || row.ClusterID != id || len(ev) != 1 ||
		ev[0].Payload != (events.User{ClusterID: id, Username: "carol"}) {
		t.Fatalf("audit %+v events %+v", row, ev)
	}
	rows, _ := json.Marshal(e.Repo.Audit())
	all, _ := json.Marshal(e.Events.All())
	p, _ := s.List(admin, id, users.ListInput{})
	listed, _ := json.Marshal(p)
	for name, out := range map[string]string{"audit": string(rows), "events": string(all), "list": string(listed)} {
		if strings.Contains(out, urls[0]) || strings.Contains(out, "/web/invite/") {
			t.Errorf("%s carry the invite URL", name)
		}
	}
}

func TestCreateValidatesBeforeWriting(t *testing.T) {
	e, s, id := setup(t)
	for name, in := range map[string]users.CreateInput{
		"empty name":   {Name: "", Roles: []string{"access"}},
		"bad name":     {Name: "a b", Roles: []string{"access"}},
		"long name":    {Name: strings.Repeat("a", 129), Roles: []string{"access"}},
		"no roles":     {Name: "dave"},
		"bad role":     {Name: "dave", Roles: []string{"ac cess"}},
		"unknown role": {Name: "dave", Roles: []string{"nope"}},
		"bad login":    {Name: "dave", Roles: []string{"access"}, Logins: []string{"ro ot"}},
	} {
		if _, err := s.Create(admin, id, in); !errors.Is(err, clusters.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if e.Teleport.Calls("CreateUser") != 0 {
		t.Fatal("an invalid user reached Teleport")
	}
	if row := lastAudit(t, e, "teleport.user.create"); row.Outcome != "failure" || row.Reason != "validation_failed" {
		t.Fatalf("audit %+v", row)
	}
	if _, err := s.Create(admin, id, users.CreateInput{Name: "alice", Roles: []string{"access"}}); !errors.Is(err, teleportapi.ErrConflict) {
		t.Fatalf("duplicate %v", err)
	}
	if _, err := s.Create(viewer, id, users.CreateInput{Name: "dave", Roles: []string{"access"}}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer %v", err)
	}
}

// An invite that cannot be issued undoes the creation: no user is left
// behind without a way to sign in.
func TestCreateRollsBackWithoutInvite(t *testing.T) {
	e, s, id := setup(t)
	e.Teleport.FailNext("CreateUserToken", trace.AccessDenied("denied"))
	if _, err := s.Create(admin, id, users.CreateInput{Name: "dave", Roles: []string{"access"}}); !errors.Is(err, teleportapi.ErrRejected) {
		t.Fatalf("create %v", err)
	}
	if _, err := e.Teleport.GetUser(context.Background(), "dave"); err == nil {
		t.Fatal("the user without an invite is left behind")
	}
	if row := lastAudit(t, e, "teleport.user.create"); row.Outcome != "failure" || row.Reason != "teleport_rejected" {
		t.Fatalf("audit %+v", row)
	}
	if len(e.Events.OfType(events.UserCreated)) != 0 {
		t.Fatal("an event for a rolled-back user")
	}
}

func TestUpdateChecksTheRevision(t *testing.T) {
	e, s, id := setup(t)
	if _, err := s.Update(admin, id, "alice", users.UpdateInput{Roles: []string{"editor"}, Revision: "stale"}); !errors.Is(err, teleportapi.ErrConflict) {
		t.Fatalf("stale %v", err)
	}
	if row := lastAudit(t, e, "teleport.user.update"); row.Outcome != "failure" || row.Reason != "conflict" {
		t.Fatalf("audit %+v", row)
	}
	v, err := s.Update(admin, id, "alice", users.UpdateInput{Roles: []string{"editor"}, Logins: []string{"root"}, Revision: "u2"})
	if err != nil || v.Roles[0] != "editor" || v.Logins[0] != "root" || v.Revision == "u2" {
		t.Fatalf("update %+v %v", v, err)
	}
	if ev := e.Events.OfType(events.UserUpdated); len(ev) != 1 || lastAudit(t, e, "teleport.user.update").Outcome != "success" {
		t.Fatalf("events %+v", ev)
	}
	if _, err := s.Update(admin, id, "alice", users.UpdateInput{Roles: []string{"editor"}}); !errors.Is(err, clusters.ErrInvalid) {
		t.Fatalf("no revision %v", err)
	}
	e.Teleport.FailNext("UpdateUser", trace.AccessDenied("denied"))
	if _, err := s.Update(admin, id, "alice", users.UpdateInput{Roles: []string{"access"}, Revision: v.Revision}); !errors.Is(err, teleportapi.ErrRejected) {
		t.Fatalf("rejected %v", err)
	}
	if row := lastAudit(t, e, "teleport.user.update"); row.Reason != "teleport_rejected" {
		t.Fatalf("audit %+v", row)
	}
}

func TestReset(t *testing.T) {
	e, s, id := setup(t)
	out, err := s.Reset(admin, id, "alice")
	if err != nil || out.ResetURL.IsZero() || out.ExpiresAt.IsZero() {
		t.Fatalf("reset %+v %v", out, err)
	}
	row := lastAudit(t, e, "teleport.user.reset")
	b, _ := json.Marshal(row)
	if row.Outcome != "success" || strings.Contains(string(b), e.Teleport.IssuedURLs()[0]) {
		t.Fatalf("audit %s", b)
	}
	if _, err := s.Reset(admin, id, "nobody"); !errors.Is(err, teleportapi.ErrNotFound) {
		t.Fatalf("missing %v", err)
	}
}

// The management identity can be neither changed, reset nor deleted.
func TestManagementIdentityIsGuarded(t *testing.T) {
	e, s, id := setup(t)
	before := slices.Clone(e.Teleport.Users)
	_, err := s.Update(admin, id, ct.Management, users.UpdateInput{Roles: []string{"access"}, Revision: "u1"})
	if guard(err) != clusters.GuardSelfIdentity {
		t.Fatalf("update %v", err)
	}
	if _, err := s.Reset(admin, id, ct.Management); guard(err) != clusters.GuardSelfIdentity {
		t.Fatalf("reset %v", err)
	}
	if err := s.Delete(admin, id, ct.Management); guard(err) != clusters.GuardSelfIdentity {
		t.Fatalf("delete %v", err)
	}
	if len(e.Teleport.Users) != len(before) || e.Teleport.Users[0].Roles[0] != ct.ManagerRole || e.Teleport.Calls("DeleteUser") != 0 {
		t.Fatalf("the management identity changed: %+v", e.Teleport.Users)
	}
	if row := lastAudit(t, e, "teleport.user.delete"); row.Outcome != "failure" || row.Reason != clusters.GuardSelfIdentity {
		t.Fatalf("audit %+v", row)
	}
}

func TestDelete(t *testing.T) {
	e, s, id := setup(t)
	if err := s.Delete(admin, id, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(admin, id, "alice"); !errors.Is(err, teleportapi.ErrNotFound) {
		t.Fatalf("twice %v", err)
	}
	if ev := e.Events.OfType(events.UserDeleted); len(ev) != 1 {
		t.Fatalf("events %+v", ev)
	}
	if p, _ := s.List(admin, id, users.ListInput{}); len(p.Items) != 1 {
		t.Fatalf("a cached list survives the delete: %+v", p.Items)
	}
	if err := s.Delete(viewer, id, "alice"); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer %v", err)
	}
}

func TestWritesBlockedOnUnsupportedVersion(t *testing.T) {
	e, s, id := setup(t)
	c, _ := e.Repo.GetCluster(context.Background(), ct.TenantA, id)
	c.Status = repo.StatusUnsupportedVersion
	if _, err := e.Repo.UpdateCluster(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(admin, id, users.CreateInput{Name: "dave", Roles: []string{"access"}}); !errors.Is(err, clusters.ErrUnsupportedVersion) {
		t.Fatalf("create %v", err)
	}
	if err := s.Delete(admin, id, "alice"); !errors.Is(err, clusters.ErrUnsupportedVersion) {
		t.Fatalf("delete %v", err)
	}
	if _, err := s.List(admin, id, users.ListInput{}); err != nil {
		t.Fatalf("reads stay open: %v", err)
	}
}
