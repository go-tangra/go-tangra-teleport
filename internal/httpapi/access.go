package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/access"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
)

// Spec 004 refusals (plan.md Contract).
var (
	ErrMFARequired        = &Error{http.StatusForbidden, "mfa_required"}
	ErrNotProvisioned     = &Error{http.StatusConflict, "not_provisioned"}
	ErrUserLocked         = &Error{http.StatusConflict, "user_locked"}
	ErrSessionMFARequired = &Error{http.StatusUnprocessableEntity, "session_mfa_required"}
	// Spec 005: the access identity brokered access issues with.
	ErrAccessIdentityMissing = &Error{http.StatusUnprocessableEntity, "access_identity_missing"}
	ErrAccessIdentityExpired = &Error{http.StatusUnprocessableEntity, "access_identity_expired"}
	ErrAccessIdentityInvalid = &Error{http.StatusUnprocessableEntity, "access_identity_invalid"}
	ErrTooManyTerminals      = &Error{http.StatusTooManyRequests, "too_many"}
	ErrTerminalEnded         = &Error{http.StatusConflict, "terminal_ended"}
)

// failAccess answers an access refusal with its reason and a message for
// the person; anything else is a cluster failure.
func (s *Server) failAccess(w http.ResponseWriter, r *http.Request, err error) {
	msg := func(e *Error, m string) { WriteJSON(w, e.Status, map[string]any{"reason": e.Reason, "message": m}) }
	switch {
	case errors.Is(err, access.ErrMFARequired):
		msg(ErrMFARequired, "sign in to the portal with a second factor (MFA) to get Teleport access")
	case errors.Is(err, access.ErrNotProvisioned):
		msg(ErrNotProvisioned, "you have no Teleport user on this cluster; ask an administrator to provision you")
	case errors.Is(err, access.ErrLocked):
		msg(ErrUserLocked, "your Teleport user on this cluster is locked")
	case errors.Is(err, access.ErrSessionMFARequired):
		msg(ErrSessionMFARequired, "a role of your Teleport user requires Teleport's per-session MFA; use tsh login on this cluster")
	case errors.Is(err, access.ErrAccessIdentityMissing):
		msg(ErrAccessIdentityMissing, "portal access needs the cluster's access identity: an administrator must upload a tsh login identity "+
			"of tangra-access on the cluster page")
	case errors.Is(err, access.ErrAccessIdentityExpired):
		msg(ErrAccessIdentityExpired, "the cluster's access identity has expired: an administrator must sign in as tangra-access again and replace it")
	case errors.Is(err, access.ErrAccessIdentityInvalid):
		msg(ErrAccessIdentityInvalid, "Teleport rejected the cluster's access identity: an administrator must check the tangra-access role "+
			"and replace the identity")
	case errors.Is(err, access.ErrInvalid):
		WriteDetail(w, ErrValidation, map[string]any{"field": "ttl_minutes",
			"message": "must be 15 to 720 minutes"})
	default:
		s.failCluster(w, r, err)
	}
}

// optionalJSON decodes a body that may be absent or empty.
func optionalJSON(r *http.Request, v any) error {
	b, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 4096))
	if err != nil {
		return ErrBodyTooLarge
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrMalformed
	}
	if dec.More() {
		return ErrMalformed
	}
	return nil
}

var safeFile = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// registerAccess mounts brokered access (spec 004): my access, nodes,
// the identity download and the access settings. No response or log line
// carries a key or certificate except the identity download's body.
func (s *Server) registerAccess(svc *access.Service) {
	// FR-017: a download refused for the missing permission is audited too.
	s.OnDenied("POST "+Prefix+"/clusters/{id}/access/identity", func(r *http.Request, _ authz.Subjects) {
		svc.Record(r.Context(), audit.AccessIssued, access.Grant{}, authz.ErrForbidden, map[string]any{"kind": access.KindDownload})
	})
	s.MustHandle("GET", Prefix+"/clusters/{id}/access", func(w http.ResponseWriter, r *http.Request) {
		m, err := svc.Mine(r.Context(), r.PathValue("id"))
		if err != nil {
			s.failAccess(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, m)
	})
	s.MustHandle("GET", Prefix+"/clusters/{id}/access/nodes", func(w http.ResponseWriter, r *http.Request) {
		n, err := svc.Nodes(r.Context(), r.PathValue("id"))
		if err != nil {
			s.failAccess(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": n})
	})
	s.MustHandle("POST", Prefix+"/clusters/{id}/access/identity", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			TTLMinutes int `json:"ttl_minutes"`
		}
		if err := optionalJSON(r, &in); err != nil {
			Fail(w, r, s.log, err)
			return
		}
		if in.TTLMinutes != 0 && (in.TTLMinutes < access.MinTTLMinutes || in.TTLMinutes > access.MaxTTLMinutes) {
			s.failAccess(w, r, access.ErrInvalid)
			return
		}
		id, err := svc.Download(r.Context(), r.PathValue("id"), in.TTLMinutes)
		if err != nil {
			s.failAccess(w, r, err)
			return
		}
		defer id.File.Wipe()
		name := safeFile.ReplaceAllString(id.User+"-"+id.Cluster, "_") + ".identity"
		h := w.Header()
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Teleport-Expires", id.Expires.UTC().Format(time.RFC3339))
		h.Set("X-Teleport-User", id.User)
		w.WriteHeader(http.StatusOK)
		b := id.File.Reveal()
		_, _ = w.Write(b)
		clear(b)
	})
	s.MustHandle("PUT", Prefix+"/clusters/{id}/access/settings", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			AccessTTLMinutes int `json:"access_ttl_minutes"`
		}
		if err := DecodeJSON(r, &in, 4096); err != nil {
			Fail(w, r, s.log, err)
			return
		}
		v, err := svc.PutSettings(r.Context(), r.PathValue("id"), in.AccessTTLMinutes)
		if err != nil {
			if errors.Is(err, access.ErrInvalid) {
				WriteDetail(w, ErrValidation, map[string]any{"field": "access_ttl_minutes", "message": "must be 15 to 720 minutes"})
				return
			}
			s.failAccess(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, v)
	})
}
