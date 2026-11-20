package alerts_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/alerts"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/auditlog"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

func rules(e *ct.Env) *alerts.Rules {
	return &alerts.Rules{Repo: e.Repo, Authz: e.Service.Authz, Audit: e.Audit, Now: e.Now}
}

func valid(clusterID string) alerts.RuleInput {
	return alerts.RuleInput{ClusterID: clusterID, Name: "failed logins", ConditionKind: repo.ConditionTeleportEvent,
		EventTypes: []string{auditlog.TypeLoginFailure}, ThresholdCount: 3, WindowMinutes: 5,
		Recipients: alerts.Recipients{UserIDs: []string{"u-sec"}}}
}

func fieldOf(err error) string {
	var fe *clusters.FieldError
	if errors.As(err, &fe) {
		return fe.Field
	}
	return ""
}

func TestRuleValidation(t *testing.T) {
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	theirs := e.Register(t, ct.TenantB, "theirs")
	s := rules(e)
	ctx := ct.As(ct.TenantA, ct.Admin)
	for _, tc := range []struct {
		mut   func(*alerts.RuleInput)
		field string
	}{
		{func(in *alerts.RuleInput) { in.Name = "" }, "name"},
		{func(in *alerts.RuleInput) { in.Name = strings.Repeat("n", 65) }, "name"},
		{func(in *alerts.RuleInput) { in.Name = "a\nb" }, "name"},
		{func(in *alerts.RuleInput) { in.ConditionKind = "anything" }, "condition_kind"},
		{func(in *alerts.RuleInput) { in.EventTypes = nil }, "event_types"},
		{func(in *alerts.RuleInput) { in.EventTypes = []string{"session.print"} }, "event_types"},
		{func(in *alerts.RuleInput) { in.EventTypes = []string{"user.login", "user.login"} }, "event_types"},
		{func(in *alerts.RuleInput) {
			in.ConditionKind, in.ThresholdCount, in.WindowMinutes = repo.ConditionResourceOffline, 0, 0
		}, "event_types"},
		{func(in *alerts.RuleInput) {
			in.ConditionKind, in.EventTypes = repo.ConditionResourceOffline, nil
		}, "threshold_count"},
		{func(in *alerts.RuleInput) { in.ThresholdCount = 1001 }, "threshold_count"},
		{func(in *alerts.RuleInput) { in.ThresholdCount = 0 }, "threshold_count"},
		{func(in *alerts.RuleInput) { in.WindowMinutes = 1441 }, "window_minutes"},
		{func(in *alerts.RuleInput) { in.Recipients.UserIDs = nil }, "recipients"},
		{func(in *alerts.RuleInput) { in.Recipients.UserIDs = []string{"bad id"} }, "recipients"},
		{func(in *alerts.RuleInput) { in.Recipients.ChannelIDs = []string{"<x>"} }, "recipients"},
		{func(in *alerts.RuleInput) { in.Recipients.UserIDs = make([]string, 51) }, "recipients"},
		{func(in *alerts.RuleInput) { in.ClusterID = theirs.ID }, "cluster_id"},
		{func(in *alerts.RuleInput) { in.ClusterID = "not-a-uuid" }, "cluster_id"},
	} {
		in := valid(c.ID)
		tc.mut(&in)
		if _, err := s.Create(ctx, in); !errors.Is(err, clusters.ErrInvalid) || fieldOf(err) != tc.field {
			t.Errorf("%+v: %v (want %s)", in, err, tc.field)
		}
	}
}

func TestRuleCRUD(t *testing.T) {
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	s := rules(e)
	admin := ct.As(ct.TenantA, ct.Admin)

	r, err := s.Create(admin, valid(c.ID))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Enabled || r.ClusterID != c.ID || r.CreatedBy != ct.Admin || r.ThresholdCount != 3 || r.Recipients.ChannelIDs == nil {
		t.Fatalf("created %+v", r)
	}
	off := false
	global := valid("")
	global.Name, global.ConditionKind, global.EventTypes, global.ThresholdCount, global.WindowMinutes, global.Enabled =
		"offline", repo.ConditionResourceOffline, nil, 0, 0, &off
	g, err := s.Create(admin, global)
	if err != nil || g.ClusterID != "" || g.Enabled || g.EventTypes == nil {
		t.Fatalf("global %+v %v", g, err)
	}
	// A viewer reads (alerts:read) but cannot change; another tenant sees nothing.
	viewer := ct.As(ct.TenantA, ct.Viewer)
	p, err := s.List(viewer)
	if err != nil || len(p.Items) != 2 {
		t.Fatalf("viewer list %+v %v", p, err)
	}
	if _, err := s.Create(viewer, valid(c.ID)); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer create: %v", err)
	}
	if p, _ := s.List(ct.As(ct.TenantB, ct.Admin)); len(p.Items) != 0 {
		t.Fatal("another tenant lists the rules")
	}
	if _, err := s.Update(ct.As(ct.TenantB, ct.Admin), r.ID, valid("")); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("cross-tenant update: %v", err)
	}
	if err := s.Delete(ct.As(ct.TenantB, ct.Admin), r.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}

	in := valid(c.ID)
	in.Name, in.ThresholdCount, in.WindowMinutes = "any failed login", 0, 0
	up, err := s.Update(admin, r.ID, in)
	if err != nil || up.Name != "any failed login" || up.ThresholdCount != 0 || up.ID != r.ID {
		t.Fatalf("update %+v %v", up, err)
	}
	moved := in
	moved.ClusterID = ""
	if _, err := s.Update(admin, r.ID, moved); fieldOf(err) != "cluster_id" {
		t.Fatalf("scope change: %v", err)
	}
	bad := in
	bad.Name = ""
	if _, err := s.Update(admin, r.ID, bad); fieldOf(err) != "name" {
		t.Fatalf("invalid update: %v", err)
	}
	if _, err := s.Update(admin, "018f3a2b-0000-7000-8000-0000000000ff", in); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := s.Delete(admin, r.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(admin, r.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	e.Repo.FailNext("ListAlertRules")
	if _, err := s.List(admin); err == nil {
		t.Fatal("store failure hidden")
	}
	e.Repo.FailNext("CreateAlertRule")
	if _, err := s.Create(admin, valid(c.ID)); err == nil {
		t.Fatal("store failure hidden")
	}
	rows := strings.Join(e.AuditRows(), ",")
	for _, want := range []string{"teleport.alert_rule.create:success", "teleport.alert_rule.update:success", "teleport.alert_rule.delete:success",
		"teleport.alert_rule.create:failure", "teleport.alert_rule.delete:failure"} {
		if !strings.Contains(rows, want) {
			t.Errorf("audit lacks %s (%s)", want, rows)
		}
	}
}
