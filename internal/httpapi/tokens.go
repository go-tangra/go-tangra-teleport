package httpapi

import (
	"net/http"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/tokens"
)

// registerTokens mounts the join-token routes (US3). The token value, the
// install command and the config snippet appear only in the 201 response.
func (s *Server) registerTokens(svc *tokens.Service) {
	s.MustHandle("GET", Prefix+"/clusters/{id}/tokens", func(w http.ResponseWriter, r *http.Request) {
		p, err := svc.List(r.Context(), r.PathValue("id"))
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, p)
	})
	s.MustHandle("POST", Prefix+"/clusters/{id}/tokens", func(w http.ResponseWriter, r *http.Request) {
		var in tokens.CreateInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failIdentity(w, r, err)
			return
		}
		v, err := svc.Create(r.Context(), r.PathValue("id"), in)
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		WriteJSON(w, http.StatusCreated, v)
	})
	s.MustHandle("DELETE", Prefix+"/clusters/{id}/tokens/{tid}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.Revoke(r.Context(), r.PathValue("id"), r.PathValue("tid")); err != nil {
			s.failIdentity(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
