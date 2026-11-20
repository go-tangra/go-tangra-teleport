package auditlog

import (
	"context"
	"time"

	"github.com/go-tangra/go-tangra/v4/listquery"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

// TrailList is the GET /audit list contract: by time, newest first.
var TrailList = listquery.Spec{
	Fields:   map[string]listquery.Field{"time": {Expr: "time", DefaultDir: listquery.Desc, NotNull: true}},
	Default:  "time",
	TieBreak: "id",
}

// TrailFilter narrows the module audit trail ("" and zero = any).
type TrailFilter struct {
	ClusterID string
	Action    string
	Outcome   string
	From, To  time.Time
}

// TrailRow is one module audit record as the API returns it. Details passed
// the audit detail guard when they were recorded: they carry no secret.
type TrailRow struct {
	ID            string         `json:"id"`
	Time          time.Time      `json:"time"`
	ActorKind     string         `json:"actor_kind"`
	ActorID       string         `json:"actor_id"`
	ClusterID     string         `json:"cluster_id,omitempty"`
	Action        string         `json:"action"`
	TargetKind    string         `json:"target_kind"`
	TargetName    string         `json:"target_name"`
	Outcome       string         `json:"outcome"`
	Reason        string         `json:"reason,omitempty"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	Detail        map[string]any `json:"detail"`
}

func trailRow(r repo.AuditRow) TrailRow {
	d := r.Detail
	if d == nil {
		d = map[string]any{}
	}
	return TrailRow{ID: r.ID, Time: r.Time.UTC(), ActorKind: r.ActorKind, ActorID: r.ActorID, ClusterID: r.ClusterID, Action: r.Action,
		TargetKind: r.TargetKind, TargetName: r.TargetName, Outcome: r.Outcome, Reason: r.Reason, CorrelationID: r.CorrelationID, Detail: d}
}

func (f TrailFilter) validate() error {
	if f.Action != "" && !audit.Known(f.Action) {
		return invalid("action", "unknown action")
	}
	switch f.Outcome {
	case "", audit.OutcomeSuccess, audit.OutcomeFailure, audit.OutcomeUnknown:
	default:
		return invalid("outcome", "must be success, failure or unknown")
	}
	if !f.From.IsZero() && !f.To.IsZero() && f.To.Before(f.From) {
		return invalid("to", "must not be before from")
	}
	return nil
}

// Trail returns one page of the caller's tenant's module audit trail
// (audit:read). A page beyond the end is the last page.
func (s *Service) Trail(ctx context.Context, req listquery.Request, f TrailFilter) (listquery.Page[TrailRow], error) {
	if err := f.validate(); err != nil {
		return listquery.Page[TrailRow]{}, err
	}
	if err := s.Clusters.Authz.Require(ctx, authz.AuditRead); err != nil {
		return listquery.Page[TrailRow]{}, err
	}
	subj, _ := authz.FromContext(ctx)
	q := repo.AuditQuery{ClusterID: f.ClusterID, Action: f.Action, Outcome: f.Outcome, From: f.From, To: f.To,
		Ascending: req.Order == listquery.Asc, Offset: req.Offset(), Limit: req.Limit()}
	rows, total, err := s.Clusters.Repo.ListAudit(ctx, subj.TenantID, q)
	if err != nil {
		return listquery.Page[TrailRow]{}, err
	}
	if len(rows) == 0 && total > 0 {
		req = req.Clamp(total)
		q.Offset = req.Offset()
		if rows, total, err = s.Clusters.Repo.ListAudit(ctx, subj.TenantID, q); err != nil {
			return listquery.Page[TrailRow]{}, err
		}
	}
	items := make([]TrailRow, 0, len(rows))
	for _, r := range rows {
		items = append(items, trailRow(r))
	}
	return listquery.NewPage(items, total, req), nil
}
