package provisioning_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/provisioning"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

func fieldOf(err error) string {
	var fe *clusters.FieldError
	if errors.As(err, &fe) {
		return fe.Field
	}
	return ""
}

func TestMappingValidation(t *testing.T) {
	e := setup(t)
	ok := provisioning.MappingInput{SubjectKind: repo.SubjectGroup, SubjectRef: "devs", TeleportRoles: []string{"access"}, Logins: []string{"ubuntu"}}
	for name, c := range map[string]struct {
		mut   func(*provisioning.MappingInput)
		field string
	}{
		"kind":          {func(m *provisioning.MappingInput) { m.SubjectKind = "team" }, "subject_kind"},
		"ref":           {func(m *provisioning.MappingInput) { m.SubjectRef = "a b" }, "subject_ref"},
		"empty ref":     {func(m *provisioning.MappingInput) { m.SubjectRef = "" }, "subject_ref"},
		"no roles":      {func(m *provisioning.MappingInput) { m.TeleportRoles = nil }, "teleport_roles"},
		"too many":      {func(m *provisioning.MappingInput) { m.TeleportRoles = make([]string, 17) }, "teleport_roles"},
		"missing role":  {func(m *provisioning.MappingInput) { m.TeleportRoles = []string{"nope"} }, "teleport_roles"},
		"bad role name": {func(m *provisioning.MappingInput) { m.TeleportRoles = []string{"{{x}}"} }, "teleport_roles"},
		"login":         {func(m *provisioning.MappingInput) { m.Logins = []string{"root;id"} }, "logins"},
		"login dash":    {func(m *provisioning.MappingInput) { m.Logins = []string{"-x"} }, "logins"},
		"logins":        {func(m *provisioning.MappingInput) { m.Logins = make([]string, 33) }, "logins"},
	} {
		in := ok
		c.mut(&in)
		if _, err := e.svc.CreateMapping(admin, e.id, in); fieldOf(err) != c.field {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(e.Teleport.Users) != 2 {
		t.Fatal("validation wrote to Teleport")
	}
}

func TestMappingLifecycle(t *testing.T) {
	e := setup(t)
	m := e.mapping(t, repo.SubjectGroup, "devs", []string{"editor", "access", "editor"}, []string{"dev", "ubuntu"})
	if !slices.Equal(m.TeleportRoles, []string{"editor", "access"}) || m.CreatedBy != ct.Admin || m.ClusterID != e.id {
		t.Fatalf("mapping %+v", m)
	}
	if _, err := e.svc.CreateMapping(admin, e.id, provisioning.MappingInput{SubjectKind: repo.SubjectGroup, SubjectRef: "devs",
		TeleportRoles: []string{"access"}}); !errors.Is(err, repo.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	p, err := e.svc.ListMappings(viewer, e.id)
	if err != nil || len(p.Items) != 2 {
		t.Fatalf("list %+v %v", p, err)
	}
	u, err := e.svc.UpdateMapping(admin, e.id, m.ID, provisioning.MappingUpdate{TeleportRoles: []string{"access"}})
	if err != nil || !slices.Equal(u.TeleportRoles, []string{"access"}) || len(u.Logins) != 0 || u.SubjectRef != "devs" {
		t.Fatalf("update %+v %v", u, err)
	}
	if _, err := e.svc.UpdateMapping(admin, e.id, m.ID, provisioning.MappingUpdate{TeleportRoles: []string{"nope"}}); fieldOf(err) != "teleport_roles" {
		t.Fatalf("update missing role: %v", err)
	}
	if _, err := e.svc.UpdateMapping(admin, e.id, "018f3a2b-0000-7000-8000-0000000000ff", provisioning.MappingUpdate{TeleportRoles: []string{"access"}}); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("update unknown: %v", err)
	}
	if err := e.svc.DeleteMapping(admin, e.id, m.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteMapping(admin, e.id, m.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	rows := e.AuditRows()
	for _, a := range []string{"teleport.mapping.create:success", "teleport.mapping.create:failure", "teleport.mapping.update:success", "teleport.mapping.delete:success"} {
		if !slices.Contains(rows, a) {
			t.Errorf("no %s in %v", a, rows)
		}
	}
}

// SR-005: mappings are administrator-only; operators and viewers read them.
func TestMappingPermissions(t *testing.T) {
	e := setup(t)
	p, _ := e.svc.ListMappings(viewer, e.id)
	id := p.Items[0].ID
	in := provisioning.MappingInput{SubjectKind: repo.SubjectGroup, SubjectRef: "ops", TeleportRoles: []string{"access"}}
	for _, ctx := range []context.Context{operator, viewer} {
		if _, err := e.svc.CreateMapping(ctx, e.id, in); !errors.Is(err, authz.ErrForbidden) {
			t.Errorf("create: %v", err)
		}
		if _, err := e.svc.UpdateMapping(ctx, e.id, id, provisioning.MappingUpdate{TeleportRoles: []string{"access"}}); !errors.Is(err, authz.ErrForbidden) {
			t.Errorf("update: %v", err)
		}
		if err := e.svc.DeleteMapping(ctx, e.id, id); !errors.Is(err, authz.ErrForbidden) {
			t.Errorf("delete: %v", err)
		}
	}
	if _, err := e.svc.ListMappings(ct.As(ct.TenantA, ct.Nobody), e.id); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("nobody: %v", err)
	}
	// Another tenant's cluster is not found.
	other := e.Register(t, ct.TenantB, "theirs")
	if _, err := e.svc.ListMappings(viewer, other.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("cross-tenant: %v", err)
	}
	// A mapping id of another cluster is not found through this one.
	mine := e.Register(t, ct.TenantA, "second")
	if err := e.svc.DeleteMapping(admin, mine.ID, id); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("mapping of another cluster: %v", err)
	}
	e.Repo.FailNext("ListMappings")
	if _, err := e.svc.ListMappings(viewer, e.id); err == nil {
		t.Fatal("store failure ignored")
	}
}

func TestFakeMembership(t *testing.T) {
	f := provisioning.NewFakeMembership(bob)
	ms, err := f.Members(context.Background(), ct.TenantA)
	if err != nil || len(ms) != 1 {
		t.Fatalf("members %v %v", ms, err)
	}
	ms[0].Roles[0] = "changed"
	if m, ok, _ := f.Member(context.Background(), ct.TenantA, bobID); !ok || m.Roles[0] != "operator" {
		t.Fatal("the fake shares its slices")
	}
	if _, ok, _ := f.Member(context.Background(), ct.TenantA, carolID); ok {
		t.Fatal("unknown member")
	}
}
