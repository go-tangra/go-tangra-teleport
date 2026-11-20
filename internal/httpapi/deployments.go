package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/deploy"
)

// failDeploy maps the wizard's own refusals; the rest is failCluster.
func (s *Server) failDeploy(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, deploy.ErrRateLimited):
		w.Header().Set("Retry-After", "10")
		WriteDetail(w, ErrRateLimited, map[string]any{"message": "checks run at most once every 10 seconds per draft"})
	case errors.Is(err, deploy.ErrUnknownArtifact):
		WriteError(w, ErrNotFound.Status, ErrNotFound.Reason)
	default:
		s.failCluster(w, r, err)
	}
}

// registerDeployments mounts the deployment-wizard routes (US6). Artifacts
// are rendered per request and sent as text/plain attachments.
func (s *Server) registerDeployments(svc *deploy.Service) {
	s.MustHandle("GET", Prefix+"/deployments", func(w http.ResponseWriter, r *http.Request) {
		p, err := svc.List(r.Context())
		if err != nil {
			s.failDeploy(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, p)
	})
	s.MustHandle("POST", Prefix+"/deployments", func(w http.ResponseWriter, r *http.Request) {
		var in deploy.DraftInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failDeploy(w, r, err)
			return
		}
		v, err := svc.Create(r.Context(), in)
		if err != nil {
			s.failDeploy(w, r, err)
			return
		}
		WriteJSON(w, http.StatusCreated, v)
	})
	s.MustHandle("GET", Prefix+"/deployments/{id}", func(w http.ResponseWriter, r *http.Request) {
		v, err := svc.Get(r.Context(), r.PathValue("id"))
		if err != nil {
			s.failDeploy(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, v)
	})
	s.MustHandle("PUT", Prefix+"/deployments/{id}", func(w http.ResponseWriter, r *http.Request) {
		var in deploy.DraftInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failDeploy(w, r, err)
			return
		}
		v, err := svc.Update(r.Context(), r.PathValue("id"), in)
		if err != nil {
			s.failDeploy(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, v)
	})
	s.MustHandle("DELETE", Prefix+"/deployments/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.Delete(r.Context(), r.PathValue("id")); err != nil {
			s.failDeploy(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	s.MustHandle("GET", Prefix+"/deployments/{id}/artifacts/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		b, err := svc.Artifact(r.Context(), r.PathValue("id"), name)
		if err != nil {
			s.failDeploy(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`) // name is one of deploy.Artifacts
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b) // #nosec G705 -- rendered artifact served as a text/plain attachment with nosniff
	})
	s.MustHandle("POST", Prefix+"/deployments/{id}/checks", func(w http.ResponseWriter, r *http.Request) {
		v, err := svc.Check(r.Context(), r.PathValue("id"))
		if err != nil {
			s.failDeploy(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, v)
	})
}
