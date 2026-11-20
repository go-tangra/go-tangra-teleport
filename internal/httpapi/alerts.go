package httpapi

import (
	"net/http"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/alerts"
)

// registerAlerts mounts the alert-rule routes (US4).
func (s *Server) registerAlerts(svc *alerts.Rules) {
	s.MustHandle("GET", Prefix+"/alert-rules", func(w http.ResponseWriter, r *http.Request) {
		p, err := svc.List(r.Context())
		if err != nil {
			s.failCluster(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, p)
	})
	s.MustHandle("POST", Prefix+"/alert-rules", func(w http.ResponseWriter, r *http.Request) {
		var in alerts.RuleInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failCluster(w, r, err)
			return
		}
		v, err := svc.Create(r.Context(), in)
		if err != nil {
			s.failCluster(w, r, err)
			return
		}
		WriteJSON(w, http.StatusCreated, v)
	})
	s.MustHandle("PUT", Prefix+"/alert-rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		var in alerts.RuleInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failCluster(w, r, err)
			return
		}
		v, err := svc.Update(r.Context(), r.PathValue("id"), in)
		if err != nil {
			s.failCluster(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, v)
	})
	s.MustHandle("DELETE", Prefix+"/alert-rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.Delete(r.Context(), r.PathValue("id")); err != nil {
			s.failCluster(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
