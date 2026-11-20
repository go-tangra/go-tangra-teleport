package teleportapi

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/trace"
)

// The reads of US4 (research D8): Teleport audit-event search and recorded
// session search. Both are served live with a required window and an opaque
// cursor; events come back as JSON (the shape tctl and the web UI show) and
// are normalised and bounded by internal/auditlog.

// EventQuery is one page of an event search.
type EventQuery struct {
	From, To  time.Time
	Types     []string // empty: every type
	Limit     int
	Next      string
	Ascending bool // oldest first (the alert poller); default newest first
}

// AuditEvent is one Teleport audit event. Raw is its JSON encoding.
type AuditEvent struct {
	ID    string
	Type  string
	Code  string
	Time  time.Time
	Index int64
	Raw   json.RawMessage
}

func order(asc bool) types.EventOrder {
	if asc {
		return types.EventOrderAscending
	}
	return types.EventOrderDescending
}

func auditEventOf(e apievents.AuditEvent) AuditEvent {
	raw, err := json.Marshal(e)
	if err != nil {
		raw = []byte("{}")
	}
	return AuditEvent{ID: e.GetID(), Type: e.GetType(), Code: e.GetCode(), Time: e.GetTime().UTC(), Index: e.GetIndex(), Raw: raw}
}

func eventPage(evs []apievents.AuditEvent, next string) Page[AuditEvent] {
	out := Page[AuditEvent]{Next: next, Items: make([]AuditEvent, 0, len(evs))}
	for _, e := range evs {
		out.Items = append(out.Items, auditEventOf(e))
	}
	return out
}

func (q EventQuery) check() error {
	if q.From.IsZero() || q.To.IsZero() || q.To.Before(q.From) {
		return trace.BadParameter("an event search needs a window")
	}
	return nil
}

// ---- real

func (r *real) SearchEvents(ctx context.Context, q EventQuery) (Page[AuditEvent], error) {
	if err := q.check(); err != nil {
		return Page[AuditEvent]{}, err
	}
	evs, next, err := r.e.SearchEvents(ctx, q.From.UTC(), q.To.UTC(), defaults.Namespace, q.Types, q.Limit, order(q.Ascending), q.Next, "")
	if err != nil {
		return Page[AuditEvent]{}, err
	}
	return eventPage(evs, next), nil
}

func (r *real) SearchSessions(ctx context.Context, q EventQuery) (Page[AuditEvent], error) {
	if err := q.check(); err != nil {
		return Page[AuditEvent]{}, err
	}
	evs, next, err := r.e.SearchSessionEvents(ctx, q.From.UTC(), q.To.UTC(), q.Limit, order(q.Ascending), q.Next)
	if err != nil {
		return Page[AuditEvent]{}, err
	}
	return eventPage(evs, next), nil
}

// ---- limited

func (c *limited) SearchEvents(ctx context.Context, q EventQuery) (Page[AuditEvent], error) {
	return call(c, ctx, func(ctx context.Context) (Page[AuditEvent], error) { return c.inner.SearchEvents(ctx, q) })
}

func (c *limited) SearchSessions(ctx context.Context, q EventQuery) (Page[AuditEvent], error) {
	return call(c, ctx, func(ctx context.Context) (Page[AuditEvent], error) { return c.inner.SearchSessions(ctx, q) })
}
