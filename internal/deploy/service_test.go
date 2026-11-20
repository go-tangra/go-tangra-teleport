package deploy_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/deploy"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

var (
	admin    = ct.As(ct.TenantA, ct.Admin)
	operator = ct.As(ct.TenantA, ct.Operator)
	draft    = deploy.DraftInput{Domain: "tp.example.test", CertMode: repo.CertACME, ACMEEmail: "ops@example.test",
		TeleportVersion: "19.1.2", AdminUsername: "admin", AdminLogins: []string{"root"}}
)

func service(t *testing.T) (*ct.Env, *deploy.Service, *time.Time) {
	t.Helper()
	e := ct.New(t, nil)
	now := e.Now()
	clock := func() time.Time { return now }
	srv := newTLSServer(t, []string{"tp.example.test", "*.tp.example.test"}, time.Now().Add(30*24*time.Hour))
	p := prober(t, resolver{"tp.example.test": public, deploy.WildcardProbe + ".tp.example.test": public}, srv, netguard.Policy{})
	p.Now = clock
	s := &deploy.Service{Repo: e.Repo, Authz: e.Service.Authz, Prober: p, Limiter: &deploy.Limiter{Now: clock}, Audit: e.Audit, Now: clock}
	return e, s, &now
}

func TestDraftLifecycle(t *testing.T) {
	e, s, now := service(t)
	v, err := s.Create(admin, draft)
	if err != nil || v.Domain != "tp.example.test" || v.ProxyAddr != "tp.example.test:443" || len(v.Checks) != 0 || v.CreatedBy != ct.Admin {
		t.Fatalf("create %+v %v", v, err)
	}
	if _, err := s.Create(admin, deploy.DraftInput{Domain: "bad domain"}); err == nil {
		t.Fatal("invalid draft stored")
	}
	p, err := s.List(admin)
	if err != nil || len(p.Items) != 1 {
		t.Fatalf("list %+v %v", p, err)
	}
	upd := draft
	upd.CertMode, upd.ACMEEmail, upd.TeleportVersion = repo.CertOwn, "", "19.2.0"
	if v, err = s.Update(admin, v.ID, upd); err != nil || v.CertMode != repo.CertOwn || v.TeleportVersion != "19.2.0" {
		t.Fatalf("update %+v %v", v, err)
	}
	art, err := s.Artifact(admin, v.ID, "install.sh")
	if err != nil || !strings.Contains(string(art), "bash -s 19.2.0") {
		t.Fatalf("artifact %v", err)
	}
	if _, err := s.Artifact(admin, v.ID, "../etc/passwd"); !errors.Is(err, deploy.ErrUnknownArtifact) {
		t.Fatalf("unknown artifact: %v", err)
	}
	// Checks are stored with the draft; a second run within 10 s is refused.
	if v, err = s.Check(admin, v.ID); err != nil || len(v.Checks) != 3 || !v.Checks[2].OK {
		t.Fatalf("check %+v %v", v, err)
	}
	if _, err := s.Check(admin, v.ID); !errors.Is(err, deploy.ErrRateLimited) {
		t.Fatalf("second check: %v", err)
	}
	*now = now.Add(10 * time.Second)
	if _, err := s.Check(admin, v.ID); err != nil {
		t.Fatalf("check after 10 s: %v", err)
	}
	if got, _ := s.Get(admin, v.ID); len(got.Checks) != 3 {
		t.Fatalf("stored checks %+v", got)
	}
	// Handover: the registered cluster is recorded.
	c := e.Register(t, ct.TenantA, "new")
	upd.RegisteredClusterID = c.ID
	if v, err = s.Update(admin, v.ID, upd); err != nil || v.RegisteredClusterID != c.ID {
		t.Fatalf("handover %+v %v", v, err)
	}
	other := e.Register(t, ct.TenantB, "theirs")
	upd.RegisteredClusterID = other.ID
	if _, err := s.Update(admin, v.ID, upd); fieldOf(err) != "registered_cluster_id" {
		t.Fatalf("another tenant's cluster: %v", err)
	}
	if err := s.Delete(admin, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(admin, v.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
	rows := e.AuditRows()
	for _, a := range []string{"teleport.deployment.create:success", "teleport.deployment.create:failure", "teleport.deployment.update:success",
		"teleport.deployment.check:success", "teleport.deployment.check:failure", "teleport.deployment.artifact:success", "teleport.deployment.delete:success"} {
		if !slices.Contains(rows, a) {
			t.Errorf("no %s in %v", a, rows)
		}
	}
}

// Deployments are human-only and administrator-only; other tenants' drafts
// are not found.
func TestDraftAccess(t *testing.T) {
	e, s, _ := service(t)
	v, _ := s.Create(admin, draft)
	worker := authz.WithSubjects(context.Background(), authz.Worker(ct.TenantA, "x"))
	for _, ctx := range []context.Context{operator, worker, ct.As(ct.TenantA, ct.Viewer)} {
		if _, err := s.List(ctx); !errors.Is(err, authz.ErrForbidden) {
			t.Errorf("list: %v", err)
		}
		if _, err := s.Create(ctx, draft); !errors.Is(err, authz.ErrForbidden) {
			t.Errorf("create: %v", err)
		}
		if _, err := s.Check(ctx, v.ID); !errors.Is(err, authz.ErrForbidden) {
			t.Errorf("check: %v", err)
		}
		if _, err := s.Artifact(ctx, v.ID, "install.sh"); !errors.Is(err, authz.ErrForbidden) {
			t.Errorf("artifact: %v", err)
		}
	}
	b := ct.As(ct.TenantB, ct.Admin)
	if _, err := s.Get(b, v.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if _, err := s.Update(b, v.ID, draft); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("cross-tenant update: %v", err)
	}
	if err := s.Delete(b, v.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	if _, err := s.Check(b, v.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("cross-tenant check: %v", err)
	}
	if _, err := s.List(context.Background()); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("no caller: %v", err)
	}
	e.Repo.FailNext("ListDrafts")
	if _, err := s.List(admin); err == nil {
		t.Fatal("store failure ignored")
	}
	e.Repo.FailNext("UpdateDraft")
	if _, err := s.Check(admin, v.ID); err == nil {
		t.Fatal("store failure ignored")
	}
}
