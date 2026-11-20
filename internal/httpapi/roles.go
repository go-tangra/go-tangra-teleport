package httpapi

import (
	"net/http"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/roles"
)

// registerRoles mounts the Teleport role routes (US2; roles:manage is
// administrator-only, SR-005).
func (s *Server) registerRoles(svc *roles.Service) {
	s.MustHandle("GET", Prefix+"/clusters/{id}/roles", func(w http.ResponseWriter, r *http.Request) {
		p, err := svc.List(r.Context(), r.PathValue("id"), roles.ListInput{Next: r.URL.Query().Get("next"), Limit: pageSize(r)})
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, p)
	})
	s.MustHandle("GET", Prefix+"/clusters/{id}/roles/{name}", func(w http.ResponseWriter, r *http.Request) {
		d, err := svc.Get(r.Context(), r.PathValue("id"), r.PathValue("name"))
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, d)
	})
	s.MustHandle("POST", Prefix+"/clusters/{id}/roles/preview", func(w http.ResponseWriter, r *http.Request) {
		var in roles.PreviewInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failIdentity(w, r, err)
			return
		}
		p, err := svc.Preview(r.Context(), r.PathValue("id"), in)
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, p)
	})
	s.MustHandle("PUT", Prefix+"/clusters/{id}/roles/{name}", func(w http.ResponseWriter, r *http.Request) {
		var in roles.PutInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failIdentity(w, r, err)
			return
		}
		v, err := svc.Put(r.Context(), r.PathValue("id"), r.PathValue("name"), in)
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, v)
	})
	s.MustHandle("DELETE", Prefix+"/clusters/{id}/roles/{name}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.Delete(r.Context(), r.PathValue("id"), r.PathValue("name")); err != nil {
			s.failIdentity(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
