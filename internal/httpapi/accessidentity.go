package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
)

// Spec 005 upload refusals.
var (
	ErrNotSignIn         = &Error{http.StatusUnprocessableEntity, "access_identity_not_sign_in"}
	ErrCannotImpersonate = &Error{http.StatusUnprocessableEntity, "access_identity_cannot_impersonate"}
)

// failAccessIdentity answers an access identity refusal with its reason
// and a message for the administrator; anything else is a cluster failure.
func (s *Server) failAccessIdentity(w http.ResponseWriter, r *http.Request, err error) {
	msg := func(e *Error, m string) { WriteJSON(w, e.Status, map[string]any{"reason": e.Reason, "message": m}) }
	switch {
	case errors.Is(err, clusters.ErrNotSignIn):
		msg(ErrNotSignIn, "this identity was made with tctl auth sign, which Teleport never lets impersonate: "+
			"sign in as tangra-access with tsh login --out=access.identity and upload that file")
	case errors.Is(err, clusters.ErrCannotImpersonate):
		msg(ErrCannotImpersonate, "Teleport refused to issue certificates for a managed user with this identity: "+
			"give its user the tangra-access role and sign in again")
	default:
		s.failCluster(w, r, err)
	}
}

// registerAccessIdentity mounts the access identity routes (spec 005):
// status (clusters:read), upload or replace and remove (clusters:manage).
// No response carries the identity or its reference.
func (s *Server) registerAccessIdentity(svc *clusters.Service) {
	s.MustHandle("GET", Prefix+"/clusters/{id}/access-identity", func(w http.ResponseWriter, r *http.Request) {
		v, err := svc.AccessIdentity(r.Context(), r.PathValue("id"))
		if err != nil {
			s.failCluster(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, v)
	})
	s.MustHandle("PUT", Prefix+"/clusters/{id}/access-identity", func(w http.ResponseWriter, r *http.Request) {
		var in clusters.AccessIdentityInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failCluster(w, r, err)
			return
		}
		v, err := svc.PutAccessIdentity(r.Context(), r.PathValue("id"), in)
		in.Credential.Wipe()
		if err != nil {
			s.failAccessIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, v)
	})
	s.MustHandle("DELETE", Prefix+"/clusters/{id}/access-identity", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.DeleteAccessIdentity(r.Context(), r.PathValue("id")); err != nil {
			s.failCluster(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
