package httpapi

import (
	"net/http"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/resources"
)

// registerResources mounts the resource list and the link routes (US3).
func (s *Server) registerResources(svc *resources.Service) {
	s.MustHandle("GET", Prefix+"/clusters/{id}/resources", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		p, err := svc.List(r.Context(), r.PathValue("id"), resources.ListInput{Kind: q.Get("kind"), Label: q.Get("label"),
			Q: q.Get("q"), Status: q.Get("status"), Next: q.Get("next"), Limit: pageSize(r)})
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, p)
	})
	s.MustHandle("POST", Prefix+"/clusters/{id}/resources/{rid}/links", func(w http.ResponseWriter, r *http.Request) {
		var in resources.LinkInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failIdentity(w, r, err)
			return
		}
		v, err := svc.ConfirmLink(r.Context(), r.PathValue("id"), r.PathValue("rid"), in)
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusCreated, v)
	})
	s.MustHandle("DELETE", Prefix+"/clusters/{id}/resources/{rid}/links/{lid}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.RemoveLink(r.Context(), r.PathValue("id"), r.PathValue("rid"), r.PathValue("lid")); err != nil {
			s.failIdentity(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
