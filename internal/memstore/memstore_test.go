package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repotest"
)

func TestConformance(t *testing.T) {
	repotest.Run(t, func(*testing.T) repo.Store { return New() })
}

func TestFailNextEveryMethod(t *testing.T) {
	ctx := context.Background()
	m := New()
	tn, now := repotest.TenantA, time.Now()
	calls := map[string]func() error{
		"CreateCluster":     func() error { return m.CreateCluster(ctx, repo.Cluster{}) },
		"GetCluster":        func() error { _, err := m.GetCluster(ctx, tn, "x"); return err },
		"ListClusters":      func() error { _, err := m.ListClusters(ctx, tn); return err },
		"UpdateCluster":     func() error { _, err := m.UpdateCluster(ctx, repo.Cluster{}); return err },
		"DeleteCluster":     func() error { return m.DeleteCluster(ctx, tn, "x") },
		"AllClusters":       func() error { _, err := m.AllClusters(ctx); return err },
		"CreateJoinToken":   func() error { return m.CreateJoinToken(ctx, repo.JoinToken{}) },
		"GetJoinToken":      func() error { _, err := m.GetJoinToken(ctx, tn, "x"); return err },
		"ListJoinTokens":    func() error { _, err := m.ListJoinTokens(ctx, tn, "x"); return err },
		"RevokeJoinToken":   func() error { return m.RevokeJoinToken(ctx, tn, "x", now) },
		"PruneJoinTokens":   func() error { _, err := m.PruneJoinTokens(ctx, now); return err },
		"UpsertSnapshot":    func() error { _, err := m.UpsertSnapshot(ctx, repo.ResourceSnapshot{}); return err },
		"GetSnapshot":       func() error { _, err := m.GetSnapshot(ctx, tn, "x"); return err },
		"ListSnapshots":     func() error { _, err := m.ListSnapshots(ctx, tn, "x"); return err },
		"DeleteSnapshot":    func() error { return m.DeleteSnapshot(ctx, tn, "x") },
		"CreateLink":        func() error { return m.CreateLink(ctx, repo.ResourceLink{}) },
		"GetLink":           func() error { _, err := m.GetLink(ctx, tn, "x"); return err },
		"ListLinks":         func() error { _, err := m.ListLinks(ctx, tn, "x"); return err },
		"UpdateLink":        func() error { _, err := m.UpdateLink(ctx, repo.ResourceLink{}); return err },
		"DeleteLink":        func() error { return m.DeleteLink(ctx, tn, "x") },
		"CreateMapping":     func() error { return m.CreateMapping(ctx, repo.RoleMapping{}) },
		"GetMapping":        func() error { _, err := m.GetMapping(ctx, tn, "x"); return err },
		"ListMappings":      func() error { _, err := m.ListMappings(ctx, tn, "x"); return err },
		"UpdateMapping":     func() error { _, err := m.UpdateMapping(ctx, repo.RoleMapping{}); return err },
		"DeleteMapping":     func() error { return m.DeleteMapping(ctx, tn, "x") },
		"CreateManagedUser": func() error { return m.CreateManagedUser(ctx, repo.ManagedUser{}) },
		"GetManagedUser":    func() error { _, err := m.GetManagedUser(ctx, tn, "x"); return err },
		"ListManagedUsers":  func() error { _, err := m.ListManagedUsers(ctx, tn, "x"); return err },
		"UpdateManagedUser": func() error { _, err := m.UpdateManagedUser(ctx, repo.ManagedUser{}); return err },
		"DeleteManagedUser": func() error { return m.DeleteManagedUser(ctx, tn, "x") },
		"CreateAlertRule":   func() error { return m.CreateAlertRule(ctx, repo.AlertRule{}) },
		"GetAlertRule":      func() error { _, err := m.GetAlertRule(ctx, tn, "x"); return err },
		"ListAlertRules":    func() error { _, err := m.ListAlertRules(ctx, tn); return err },
		"UpdateAlertRule":   func() error { _, err := m.UpdateAlertRule(ctx, repo.AlertRule{}); return err },
		"DeleteAlertRule":   func() error { return m.DeleteAlertRule(ctx, tn, "x") },
		"GetAlertCursor":    func() error { _, err := m.GetAlertCursor(ctx, tn, "x"); return err },
		"PutAlertCursor":    func() error { return m.PutAlertCursor(ctx, repo.AlertCursor{}) },
		"RecordDelivery":    func() error { return m.RecordDelivery(ctx, repo.AlertDelivery{}) },
		"ReleaseDelivery":   func() error { return m.ReleaseDelivery(ctx, tn, "r", "c", "w") },
		"PruneDeliveries":   func() error { _, err := m.PruneDeliveries(ctx, now); return err },
		"CreateDraft":       func() error { return m.CreateDraft(ctx, repo.DeploymentDraft{}) },
		"GetDraft":          func() error { _, err := m.GetDraft(ctx, tn, "x"); return err },
		"ListDrafts":        func() error { _, err := m.ListDrafts(ctx, tn); return err },
		"UpdateDraft":       func() error { _, err := m.UpdateDraft(ctx, repo.DeploymentDraft{}); return err },
		"DeleteDraft":       func() error { return m.DeleteDraft(ctx, tn, "x") },
		"AppendAudit":       func() error { return m.AppendAudit(ctx, repo.AuditRow{}) },
	}
	for name, call := range calls {
		m.FailNext(name)
		err := call()
		var inj injectedErr
		if !errors.As(err, &inj) || inj.method != name {
			t.Errorf("%s: err = %v, want injected", name, err)
		}
	}
}

func TestAuditCopiesAndIsolation(t *testing.T) {
	ctx := context.Background()
	m := New()
	if err := m.AppendAudit(ctx, repo.AuditRow{ID: "1", TenantID: repotest.TenantA, Action: "teleport.cluster.register", Detail: map[string]any{"k": "v"}}); err != nil {
		t.Fatal(err)
	}
	rows := m.Audit()
	rows[0].Action = "mutated"
	if m.Audit()[0].Action != "teleport.cluster.register" {
		t.Fatal("Audit returned the internal slice")
	}
	c := repotest.NewCluster(repotest.TenantA, "c")
	if err := m.CreateCluster(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, _ := m.GetCluster(ctx, repotest.TenantA, c.ID)
	got.MissingPermissions = append(got.MissingPermissions, "x")
	again, _ := m.GetCluster(ctx, repotest.TenantA, c.ID)
	if len(again.MissingPermissions) != 0 {
		t.Fatal("GetCluster shares slices with the store")
	}
}
