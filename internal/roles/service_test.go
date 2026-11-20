package roles_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/gravitational/trace"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/roles"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/roleyaml"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

var (
	admin    = ct.As(ct.TenantA, ct.Admin)
	operator = ct.As(ct.TenantA, ct.Operator)
	viewer   = ct.As(ct.TenantA, ct.Viewer)
)

const devRole = `kind: role
version: v7
metadata: { name: dev }
spec:
  allow:
    logins: [secret-login-marker]
`

func setup(t *testing.T) (*ct.Env, *roles.Service, string) {
	t.Helper()
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	return e, &roles.Service{Clusters: e.Service, Audit: e.Audit, Events: e.Events}, c.ID
}

func guard(err error) string {
	var g *clusters.GuardError
	if errors.As(err, &g) {
		return g.Guard
	}
	return ""
}

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

func TestListAndGet(t *testing.T) {
	_, s, id := setup(t)
	p, err := s.List(viewer, id, roles.ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Items) != 3 || p.Items[0].Name != "access" || !p.Items[0].Preset || p.Items[2].Preset || p.Items[0].Revision != "r1" {
		t.Fatalf("list %+v", p.Items)
	}
	d, err := s.Get(viewer, id, "editor")
	if err != nil || !d.Preset || d.Revision != "r2" || !strings.HasPrefix(d.YAML, "kind: role\n") || strings.Contains(d.YAML, "revision") {
		t.Fatalf("get %+v %v", d, err)
	}
	if _, err := s.Get(viewer, id, "nope"); !errors.Is(err, teleportapi.ErrNotFound) {
		t.Fatalf("missing %v", err)
	}
	if _, err := s.Get(ct.As(ct.TenantB, ct.Admin), id, "editor"); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("other tenant %v", err)
	}
}

// Preview validates and diffs without any side effect.
func TestPreview(t *testing.T) {
	e, s, id := setup(t)
	p, err := s.Preview(admin, id, roles.PreviewInput{YAML: devRole})
	if err != nil || !p.Valid || len(p.Errors) != 0 || !strings.HasPrefix(p.Diff, "--- current\n+++ proposed\n@@ -0,0 ") {
		t.Fatalf("new role %+v %v", p, err)
	}
	p, err = s.Preview(admin, id, roles.PreviewInput{YAML: "kind: user\nversion: v2\nmetadata: {name: x}\n"})
	if err != nil || p.Valid || len(p.Errors) != 1 || p.Diff != "" {
		t.Fatalf("invalid %+v %v", p, err)
	}
	cur, _ := s.Get(admin, id, "editor")
	edited := strings.Replace(cur.YAML, "max_session_ttl: 30h0m0s", "max_session_ttl: 8h0m0s", 1)
	p, _ = s.Preview(admin, id, roles.PreviewInput{YAML: edited, Revision: cur.Revision})
	if !p.Valid || !strings.Contains(p.Diff, "-    max_session_ttl: 30h0m0s\n") || !strings.Contains(p.Diff, "+    max_session_ttl: 8h0m0s\n") {
		t.Fatalf("edit %+v", p)
	}
	p, _ = s.Preview(admin, id, roles.PreviewInput{YAML: edited, Revision: "stale"})
	if p.Valid || len(p.Errors) != 1 || !strings.Contains(p.Errors[0], "reload") || p.Diff == "" {
		t.Fatalf("stale %+v", p)
	}
	if _, err := s.Preview(operator, id, roles.PreviewInput{YAML: devRole}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("operator %v", err)
	}
	if n := e.Teleport.Calls("CreateRole") + e.Teleport.Calls("UpdateRole") + len(e.Events.OfType(events.RoleChanged)); n != 0 {
		t.Fatal("preview had a side effect")
	}
	if _, err := s.Preview(admin, id, roles.PreviewInput{YAML: devRole + strings.Repeat("#", roleyaml.MaxBytes)}); err != nil {
		t.Fatalf("oversized is a preview error, not a failure: %v", err)
	}
}

func TestPutCreatesAndUpdates(t *testing.T) {
	e, s, id := setup(t)
	v, err := s.Put(admin, id, "dev", roles.PutInput{YAML: devRole})
	if err != nil || v.Name != "dev" || v.Revision == "" || v.Preset {
		t.Fatalf("create %+v %v", v, err)
	}
	row := lastAudit(t, e, "teleport.role.create")
	if row.Outcome != "success" || row.TargetName != "dev" || row.Detail["after_sha256"] == nil {
		t.Fatalf("audit %+v", row)
	}
	if _, err := s.Put(admin, id, "dev", roles.PutInput{YAML: devRole}); !errors.Is(err, teleportapi.ErrConflict) {
		t.Fatalf("create over an existing role: %v", err)
	}
	edited := strings.Replace(devRole, "[secret-login-marker]", "[secret-login-marker, ops]", 1)
	if _, err := s.Put(admin, id, "dev", roles.PutInput{YAML: edited, Revision: "stale"}); !errors.Is(err, teleportapi.ErrConflict) {
		t.Fatalf("stale %v", err)
	}
	if row := lastAudit(t, e, "teleport.role.update"); row.Outcome != "failure" || row.Reason != "conflict" {
		t.Fatalf("audit %+v", row)
	}
	u, err := s.Put(admin, id, "dev", roles.PutInput{YAML: edited, Revision: v.Revision})
	if err != nil || u.Revision == v.Revision {
		t.Fatalf("update %+v %v", u, err)
	}
	row = lastAudit(t, e, "teleport.role.update")
	if row.Outcome != "success" || row.Detail["before_sha256"] == row.Detail["after_sha256"] || row.Detail["before_sha256"] == nil {
		t.Fatalf("audit %+v", row)
	}
	if ev := e.Events.OfType(events.RoleChanged); len(ev) != 2 || ev[1].Payload != (events.Role{ClusterID: id, Role: "dev"}) {
		t.Fatalf("events %+v", ev)
	}
	// Audit and events never carry the definition.
	b, _ := json.Marshal(e.Repo.Audit())
	ev, _ := json.Marshal(e.Events.All())
	if strings.Contains(string(b)+string(ev), "secret-login-marker") {
		t.Fatal("the role definition reached audit or events")
	}
}

func TestPutRefusals(t *testing.T) {
	e, s, id := setup(t)
	if _, err := s.Put(admin, id, "other", roles.PutInput{YAML: devRole}); !errors.Is(err, clusters.ErrInvalid) {
		t.Fatalf("name mismatch %v", err)
	}
	if _, err := s.Put(admin, id, "dev", roles.PutInput{YAML: "kind: role\nversion: v6\nmetadata: {name: dev}\n"}); !errors.Is(err, roleyaml.ErrInvalid) {
		t.Fatalf("invalid %v", err)
	}
	if row := lastAudit(t, e, "teleport.role.create"); row.Outcome != "failure" || row.Reason != "validation_failed" {
		t.Fatalf("audit %+v", row)
	}
	if _, err := s.Put(operator, id, "dev", roles.PutInput{YAML: devRole}); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("operator %v", err)
	}
	e.Teleport.FailNext("CreateRole", trace.BadParameter("role dev: unsupported option"))
	if _, err := s.Put(admin, id, "dev", roles.PutInput{YAML: devRole}); !errors.Is(err, teleportapi.ErrRejected) ||
		!strings.Contains(err.Error(), "unsupported option") {
		t.Fatalf("teleport rejects %v", err)
	}
	if e.Teleport.Calls("UpdateRole") != 0 {
		t.Fatal("a refused write reached Teleport")
	}
}

func TestDeleteGuards(t *testing.T) {
	e, s, id := setup(t)
	if err := s.Delete(admin, id, "editor"); guard(err) != clusters.GuardPresetRole {
		t.Fatalf("preset %v", err)
	}
	if err := s.Delete(admin, id, ct.ManagerRole); guard(err) != clusters.GuardManagementRole {
		t.Fatalf("held by the identity %v", err)
	}
	if row := lastAudit(t, e, "teleport.role.delete"); row.Outcome != "failure" || row.Reason != clusters.GuardManagementRole {
		t.Fatalf("audit %+v", row)
	}
	if e.Teleport.Calls("DeleteRole") != 0 {
		t.Fatal("a guarded delete reached Teleport")
	}
	if _, err := s.Put(admin, id, "dev", roles.PutInput{YAML: devRole}); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(operator, id, "dev"); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("operator %v", err)
	}
	if err := s.Delete(admin, id, "dev"); err != nil {
		t.Fatal(err)
	}
	if ev := e.Events.OfType(events.RoleDeleted); len(ev) != 1 {
		t.Fatalf("events %+v", ev)
	}
	if err := s.Delete(admin, id, "dev"); !errors.Is(err, teleportapi.ErrNotFound) {
		t.Fatalf("twice %v", err)
	}
}
