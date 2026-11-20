package httpapi

import (
	"net/http"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/locks"
)

// registerLocks mounts the lock routes (US2; operators may manage locks).
func (s *Server) registerLocks(svc *locks.Service) {
	s.MustHandle("GET", Prefix+"/clusters/{id}/locks", func(w http.ResponseWriter, r *http.Request) {
		p, err := svc.List(r.Context(), r.PathValue("id"))
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, p)
	})
	s.MustHandle("POST", Prefix+"/clusters/{id}/locks", func(w http.ResponseWriter, r *http.Request) {
		var in locks.CreateInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failIdentity(w, r, err)
			return
		}
		v, err := svc.Create(r.Context(), r.PathValue("id"), in)
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusCreated, v)
	})
	s.MustHandle("DELETE", Prefix+"/clusters/{id}/locks/{name}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.Remove(r.Context(), r.PathValue("id"), r.PathValue("name")); err != nil {
			s.failIdentity(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
