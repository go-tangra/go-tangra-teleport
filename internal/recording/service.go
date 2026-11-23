// Package recording replays recorded SSH sessions in the portal (spec 003).
// A permitted user's player fetches a recording page by page; each page is
// read live from the cluster with its management identity
// (teleportapi.Client.StreamRecording from the cursor's event index,
// research R1), turned into compact replay events (R2) and relayed. Nothing
// is stored: no row, file, cache, log line, metric label, event or audit
// detail carries recording content (FR-013, FR-014).
//
// Bounds (R3, R7, R8): a page stops at 1 MiB of output, 4000 events or 15 s
// of reading; a playback stops at MaxBytes (500 MiB, lowerable by config);
// at most 8 page reads run per module instance and 2 per user (ErrBusy).
//
// Access (R13, FR-009..FR-012): every page needs sessions:play and a
// cluster of the caller's tenant (clusters.Service.Client). The first page
// (no cursor) records one teleport.session.played audit row; later pages
// need the signed cursor of the previous one (R4), which only the same
// tenant, user, cluster and session can use and which no other module
// instance accepts, so no page can be read without an audited start.
package recording

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// Bounds (research R3, R7).
const (
	PageBytes  = 1 << 20
	PageEvents = 4000
	PageTime   = 15 * time.Second
	MaxBytes   = 500 << 20
	// MaxTerm bounds a terminal dimension (columns or rows).
	MaxTerm = 4096
)

// validSID is a Teleport session id (a UUID in practice), as accepted by
// the route.
var validSID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

// Service serves recording pages. Clusters, Signer and Limiter are
// required; Audit may be nil (nothing is audited, tests only). The page
// bounds and MaxBytes default when zero.
type Service struct {
	Clusters *clusters.Service
	Audit    audit.Recorder
	Signer   *Signer
	Limiter  *Limiter
	MaxBytes int64

	PageBytes  int
	PageEvents int
	PageTime   time.Duration
}

func (s *Service) bounds() bounds {
	b := bounds{maxBytes: s.MaxBytes, pageBytes: s.PageBytes, pageEvents: s.PageEvents}
	if b.maxBytes <= 0 {
		b.maxBytes = MaxBytes
	}
	if b.pageBytes <= 0 {
		b.pageBytes = PageBytes
	}
	if b.pageEvents <= 0 {
		b.pageEvents = PageEvents
	}
	return b
}

// Reason is the closed-vocabulary reason of a playback refusal (the API's,
// and the audit row's).
func Reason(err error) string {
	switch {
	case errors.Is(err, ErrNotFound):
		return "recording_not_found"
	case errors.Is(err, ErrAccessDenied):
		return "recording_access_denied"
	case errors.Is(err, ErrNotPlayable):
		return "not_playable"
	case errors.Is(err, ErrTooLarge):
		return "recording_too_large"
	case errors.Is(err, ErrExpired):
		return "playback_expired"
	case errors.Is(err, ErrBusy):
		return "rate_limited"
	}
	return clusters.ReasonOf(err)
}

// streamError maps a failed stream (research R9).
func streamError(err error) error {
	switch {
	case errors.Is(err, teleportapi.ErrAccessDenied):
		return ErrAccessDenied
	case errors.Is(err, teleportapi.ErrNotFound):
		return ErrNotFound
	}
	return err
}

// Page returns the page of session sid of cluster clusterID that cursor
// points at ("" starts the playback).
func (s *Service) Page(ctx context.Context, clusterID, sid, cursor string) (p Page, err error) {
	c, cl, err := s.Clusters.Client(ctx, clusterID, authz.SessionsPlay)
	if err != nil {
		return Page{}, err
	}
	if !validSID.MatchString(sid) {
		return Page{}, &clusters.FieldError{Field: "sid", Msg: "is not a session id"}
	}
	subj, _ := authz.FromContext(ctx)
	bind := binding{Tenant: subj.TenantID, User: subj.ActorID(), Cluster: c.ID, Session: sid}
	var pos position
	if cursor == "" {
		// R5 / FR-011: the start of a playback is audited once, with its
		// outcome, before any content leaves the module.
		defer func() { s.record(ctx, subj, c.ID, sid, err) }()
	} else if pos, err = s.Signer.open(cursor, bind); err != nil {
		return Page{}, err
	}
	release, ok := s.Limiter.Acquire(subj.TenantID + "/" + subj.ActorID())
	if !ok {
		return Page{}, ErrBusy
	}
	defer release()

	b := newBuilder(pos, s.bounds())
	rctx, cancel := context.WithCancel(ctx)
	defer cancel() // stops the cluster stream when the page is complete
	evs, errs := cl.StreamRecording(rctx, sid, pos.Next)
	limit := s.PageTime
	if limit <= 0 {
		limit = PageTime
	}
	if err := read(rctx, evs, errs, b, limit); err != nil {
		return Page{}, err
	}
	if !b.page.Done {
		b.page.Next = s.Signer.sign(bind, b.pos)
	}
	return b.page, nil
}

// read fills b from the stream until the page is complete, the stream
// ends, or limit has passed (a short page; the cursor continues it).
func read(ctx context.Context, evs <-chan teleportapi.RecordingEvent, errs <-chan error, b *builder, limit time.Duration) error {
	timer := time.NewTimer(limit)
	defer timer.Stop()
	for {
		select {
		case e, ok := <-evs:
			if !ok {
				if err := <-errs; err != nil {
					return streamError(err)
				}
				return b.end()
			}
			full, err := b.add(e)
			if err != nil {
				return err
			}
			if full {
				return nil
			}
		case <-timer.C:
			if b.first && !b.started {
				return teleportapi.ErrUnreachable // no session start within the page time
			}
			return nil
		case <-ctx.Done():
			return teleportapi.MapError(ctx.Err())
		}
	}
}

func (s *Service) record(ctx context.Context, subj authz.Subjects, clusterID, sid string, err error) {
	e := audit.FromSubjects(subj, audit.SessionPlayed, audit.TargetSession, sid, audit.OutcomeSuccess)
	e.ClusterID, e.Details = clusterID, map[string]any{"session_id": sid}
	if err != nil {
		e.Outcome, e.Reason = audit.OutcomeFailure, Reason(err)
	}
	audit.Emit(ctx, s.Audit, e)
}
