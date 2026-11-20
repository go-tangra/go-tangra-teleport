// Package alerts is the alerting half of US4 (FR-023, research D8): tenant
// alert rules, and the leased poller that evaluates them against each
// cluster's Teleport audit log and delivers matches through the
// notification module (template teleport.alert).
//
// A rule is either a Teleport-event rule (allow-listed normalized event
// types from internal/auditlog; any match, or at least N matches by one user
// within W minutes) or a module condition (cluster_unreachable,
// credential_expiring, resource_offline) raised by the other stories. Rules
// address tangra users by id; channel ids are stored for the UI but not
// delivered to, because the notification SDK sends a system template to one
// recipient (plan.md deviation).
package alerts

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/auditlog"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
)

// Bounds (data-model alert_rule).
const (
	MaxName       = 64
	MaxThreshold  = 1000
	MaxWindow     = 1440
	MaxRecipients = 50
	MaxChannels   = 20
)

// Conditions lists every rule condition kind.
var Conditions = []string{repo.ConditionTeleportEvent, repo.ConditionClusterUnreachable, repo.ConditionCredentialExpiring,
	repo.ConditionResourceOffline}

var (
	recipientID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@:-]{0,127}$`)
	uuidRe      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// Recipients are notification recipients by reference.
type Recipients struct {
	UserIDs    []string `json:"user_ids"`
	ChannelIDs []string `json:"channel_ids"`
}

// RuleInput is the POST and PUT body (PUT replaces every field; the
// cluster scope cannot change).
type RuleInput struct {
	ClusterID      string     `json:"cluster_id,omitempty"`
	Name           string     `json:"name"`
	ConditionKind  string     `json:"condition_kind"`
	EventTypes     []string   `json:"event_types,omitempty"`
	ThresholdCount int        `json:"threshold_count,omitempty"`
	WindowMinutes  int        `json:"window_minutes,omitempty"`
	Recipients     Recipients `json:"recipients"`
	Enabled        *bool      `json:"enabled,omitempty"`
}

// Rule is an alert rule as the API returns it.
type Rule struct {
	ID             string     `json:"id"`
	ClusterID      string     `json:"cluster_id,omitempty"`
	Name           string     `json:"name"`
	ConditionKind  string     `json:"condition_kind"`
	EventTypes     []string   `json:"event_types"`
	ThresholdCount int        `json:"threshold_count"`
	WindowMinutes  int        `json:"window_minutes"`
	Recipients     Recipients `json:"recipients"`
	Enabled        bool       `json:"enabled"`
	CreatedBy      string     `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// RulePage lists the tenant's rules by name.
type RulePage struct {
	Items []Rule `json:"items"`
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ViewOf renders a stored rule.
func ViewOf(r repo.AlertRule) Rule {
	return Rule{ID: r.ID, ClusterID: r.ClusterID, Name: r.Name, ConditionKind: r.ConditionKind, EventTypes: orEmpty(r.EventTypes),
		ThresholdCount: r.ThresholdCount, WindowMinutes: r.WindowMinutes,
		Recipients: Recipients{UserIDs: orEmpty(r.Recipients.UserIDs), ChannelIDs: orEmpty(r.Recipients.ChannelIDs)},
		Enabled:    r.Enabled, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}

func invalid(field, msg string) error { return &clusters.FieldError{Field: field, Msg: msg} }

func ids(field string, v []string, max int) error {
	if len(v) > max {
		return invalid(field, "too many recipients")
	}
	for _, id := range v {
		if !recipientID.MatchString(id) {
			return invalid(field, "recipient ids may contain only letters, digits and . _ @ : -")
		}
	}
	return nil
}

// validate checks in (the cluster scope is checked by the caller).
func validate(in RuleInput) error {
	name := strings.TrimSpace(in.Name)
	if name == "" || len([]rune(name)) > MaxName || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return invalid("name", "must be 1 to 64 characters without control characters")
	}
	if !slices.Contains(Conditions, in.ConditionKind) {
		return invalid("condition_kind", "must be teleport_event, cluster_unreachable, credential_expiring or resource_offline")
	}
	if in.ConditionKind == repo.ConditionTeleportEvent {
		if len(in.EventTypes) == 0 || len(in.EventTypes) > auditlog.MaxTypes {
			return invalid("event_types", "a Teleport-event rule needs 1 to 32 event types")
		}
		seen := map[string]bool{}
		for _, t := range in.EventTypes {
			if !auditlog.Allowed(t) || seen[t] {
				return invalid("event_types", "unknown or repeated event type")
			}
			seen[t] = true
		}
		if in.ThresholdCount != 0 || in.WindowMinutes != 0 {
			if in.ThresholdCount < 1 || in.ThresholdCount > MaxThreshold {
				return invalid("threshold_count", "must be 1 to 1000 with a window")
			}
			if in.WindowMinutes < 1 || in.WindowMinutes > MaxWindow {
				return invalid("window_minutes", "must be 1 to 1440 with a threshold")
			}
		}
	} else {
		if len(in.EventTypes) > 0 {
			return invalid("event_types", "only Teleport-event rules take event types")
		}
		if in.ThresholdCount != 0 || in.WindowMinutes != 0 {
			return invalid("threshold_count", "only Teleport-event rules take a threshold")
		}
	}
	if len(in.Recipients.UserIDs) == 0 {
		return invalid("recipients", "at least one user is required")
	}
	if err := ids("recipients", in.Recipients.UserIDs, MaxRecipients); err != nil {
		return err
	}
	return ids("recipients", in.Recipients.ChannelIDs, MaxChannels)
}

// Rules is the alert-rule service. Repo and Authz are required.
type Rules struct {
	Repo  repo.Store
	Authz *authz.Authorizer
	Audit audit.Recorder
	Now   func() time.Time
}

func (s *Rules) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Rules) record(ctx context.Context, a audit.Action, r repo.AlertRule, err error) {
	clusters.Audit(ctx, s.Audit, a, audit.TargetAlertRule, r.ClusterID, r.ID, err, map[string]any{"name": r.Name,
		"condition_kind": r.ConditionKind, "event_types": r.EventTypes})
}

// scope checks a rule's cluster belongs to the caller's tenant ("" = all).
func (s *Rules) scope(ctx context.Context, tenantID, clusterID string) error {
	if clusterID == "" {
		return nil
	}
	if !uuidRe.MatchString(clusterID) {
		return invalid("cluster_id", "must be a cluster id")
	}
	if _, err := s.Repo.GetCluster(ctx, tenantID, clusterID); err != nil {
		return invalid("cluster_id", "no such cluster")
	}
	return nil
}

func apply(r *repo.AlertRule, in RuleInput) {
	r.Name, r.ConditionKind = strings.TrimSpace(in.Name), in.ConditionKind
	r.EventTypes = slices.Clone(in.EventTypes)
	r.ThresholdCount, r.WindowMinutes = in.ThresholdCount, in.WindowMinutes
	r.Recipients = repo.Recipients{UserIDs: slices.Clone(in.Recipients.UserIDs), ChannelIDs: slices.Clone(in.Recipients.ChannelIDs)}
	r.Enabled = in.Enabled == nil || *in.Enabled
}

// List returns the tenant's rules (alerts:read).
func (s *Rules) List(ctx context.Context) (RulePage, error) {
	if err := s.Authz.Require(ctx, authz.AlertsRead); err != nil {
		return RulePage{}, err
	}
	subj, _ := authz.FromContext(ctx)
	rs, err := s.Repo.ListAlertRules(ctx, subj.TenantID)
	if err != nil {
		return RulePage{}, err
	}
	out := RulePage{Items: make([]Rule, 0, len(rs))}
	for _, r := range rs {
		out.Items = append(out.Items, ViewOf(r))
	}
	return out, nil
}

// Create stores a new rule (alerts:manage).
func (s *Rules) Create(ctx context.Context, in RuleInput) (v Rule, err error) {
	if err := s.Authz.Require(ctx, authz.AlertsManage); err != nil {
		return Rule{}, err
	}
	subj, _ := authz.FromContext(ctx)
	now := s.now()
	r := repo.AlertRule{ID: store.NewID(), TenantID: subj.TenantID, ClusterID: in.ClusterID, CreatedBy: subj.ActorID(), CreatedAt: now, UpdatedAt: now}
	apply(&r, in)
	defer func() { s.record(ctx, audit.AlertRuleCreate, r, err) }()
	if err := validate(in); err != nil {
		return Rule{}, err
	}
	if err := s.scope(ctx, subj.TenantID, in.ClusterID); err != nil {
		return Rule{}, err
	}
	if err := s.Repo.CreateAlertRule(ctx, r); err != nil {
		return Rule{}, err
	}
	return ViewOf(r), nil
}

// Update replaces a rule's fields (alerts:manage); the scope cannot change.
func (s *Rules) Update(ctx context.Context, id string, in RuleInput) (v Rule, err error) {
	if err := s.Authz.Require(ctx, authz.AlertsManage); err != nil {
		return Rule{}, err
	}
	subj, _ := authz.FromContext(ctx)
	r := repo.AlertRule{ID: id, TenantID: subj.TenantID, Name: in.Name}
	defer func() { s.record(ctx, audit.AlertRuleUpdate, r, err) }()
	if err := validate(in); err != nil {
		return Rule{}, err
	}
	cur, err := s.Repo.GetAlertRule(ctx, subj.TenantID, id)
	if err != nil {
		return Rule{}, err
	}
	r = cur
	if in.ClusterID != cur.ClusterID {
		return Rule{}, invalid("cluster_id", "the cluster scope of a rule cannot change")
	}
	apply(&r, in)
	stored, err := s.Repo.UpdateAlertRule(ctx, r)
	if err != nil {
		return Rule{}, err
	}
	r = stored
	return ViewOf(stored), nil
}

// Delete removes a rule and its delivery records (alerts:manage).
func (s *Rules) Delete(ctx context.Context, id string) (err error) {
	if err := s.Authz.Require(ctx, authz.AlertsManage); err != nil {
		return err
	}
	subj, _ := authz.FromContext(ctx)
	r := repo.AlertRule{ID: id, TenantID: subj.TenantID}
	defer func() { s.record(ctx, audit.AlertRuleDelete, r, err) }()
	if cur, err := s.Repo.GetAlertRule(ctx, subj.TenantID, id); err == nil {
		r = cur
	}
	return s.Repo.DeleteAlertRule(ctx, subj.TenantID, id)
}
