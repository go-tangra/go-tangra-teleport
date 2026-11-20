package httpapi

import (
	"net/http"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/users"
)

// registerUsers mounts the Teleport user routes (US2). The invite and reset
// URLs travel only in the create and reset responses.
func (s *Server) registerUsers(svc *users.Service) {
	s.MustHandle("GET", Prefix+"/clusters/{id}/users", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		p, err := svc.List(r.Context(), r.PathValue("id"), users.ListInput{Q: q.Get("q"), Next: q.Get("next"), Limit: pageSize(r)})
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, p)
	})
	s.MustHandle("POST", Prefix+"/clusters/{id}/users", func(w http.ResponseWriter, r *http.Request) {
		var in users.CreateInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failIdentity(w, r, err)
			return
		}
		out, err := svc.Create(r.Context(), r.PathValue("id"), in)
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusCreated, out)
	})
	s.MustHandle("PUT", Prefix+"/clusters/{id}/users/{name}", func(w http.ResponseWriter, r *http.Request) {
		var in users.UpdateInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failIdentity(w, r, err)
			return
		}
		v, err := svc.Update(r.Context(), r.PathValue("id"), r.PathValue("name"), in)
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, v)
	})
	s.MustHandle("POST", Prefix+"/clusters/{id}/users/{name}/reset", func(w http.ResponseWriter, r *http.Request) {
		out, err := svc.Reset(r.Context(), r.PathValue("id"), r.PathValue("name"))
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.MustHandle("DELETE", Prefix+"/clusters/{id}/users/{name}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.Delete(r.Context(), r.PathValue("id"), r.PathValue("name")); err != nil {
			s.failIdentity(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
