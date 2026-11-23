package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/recording"
)

// Spec 003 refusals (plan.md Contract).
var (
	ErrRecordingNotFound     = &Error{http.StatusNotFound, "recording_not_found"}
	ErrRecordingAccessDenied = &Error{http.StatusConflict, "recording_access_denied"}
	ErrPlaybackExpired       = &Error{http.StatusGone, "playback_expired"}
	ErrRecordingTooLarge     = &Error{http.StatusRequestEntityTooLarge, "recording_too_large"}
	ErrNotPlayable           = &Error{http.StatusUnprocessableEntity, "not_playable"}
)

// retryAfter is the Retry-After of a rate-limited page (seconds): page
// reads last at most 15 s, most far less.
const retryAfter = "2"

// registerRecording mounts the session player's page route (spec 003).
// The body is recording content for the caller only: it is never logged.
func (s *Server) registerRecording(svc *recording.Service) {
	s.MustHandle("GET", Prefix+"/clusters/{id}/sessions/{sid}/recording", func(w http.ResponseWriter, r *http.Request) {
		p, err := svc.Page(r.Context(), r.PathValue("id"), r.PathValue("sid"), r.URL.Query().Get("cursor"))
		if err != nil {
			s.failRecording(w, r, err, svc)
			return
		}
		WriteJSON(w, http.StatusOK, p)
	})
}

func (s *Server) failRecording(w http.ResponseWriter, r *http.Request, err error, svc *recording.Service) {
	switch {
	case errors.Is(err, recording.ErrBusy):
		w.Header().Set("Retry-After", retryAfter)
		WriteError(w, ErrRateLimited.Status, ErrRateLimited.Reason)
	case errors.Is(err, recording.ErrExpired):
		WriteDetail(w, ErrPlaybackExpired, map[string]any{"message": "this playback has expired; start it again"})
	case errors.Is(err, recording.ErrNotFound):
		WriteDetail(w, ErrRecordingNotFound, map[string]any{
			"message": "Teleport has no recording of this session: it was not recorded, is still in progress, or was deleted"})
	case errors.Is(err, recording.ErrAccessDenied):
		WriteDetail(w, ErrRecordingAccessDenied, map[string]any{
			"message": "the cluster's management role cannot read session recordings: give it session: [list, read] " +
				"(re-run the bootstrap or apply the documented tangra-manager role)"})
	case errors.Is(err, recording.ErrTooLarge):
		max := svc.MaxBytes
		if max <= 0 {
			max = recording.MaxBytes
		}
		WriteDetail(w, ErrRecordingTooLarge, map[string]any{"max_bytes": max,
			"message": "this recording is too large to play here; open it in Teleport"})
	case errors.Is(err, recording.ErrNotPlayable):
		WriteDetail(w, ErrNotPlayable, map[string]any{"message": "only SSH terminal sessions can be played here; open it in Teleport"})
	default:
		s.failCluster(w, r, err)
	}
}
