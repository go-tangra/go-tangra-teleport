package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-tangra/go-tangra/v4/listquery"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
)

// failCluster writes a cluster-domain refusal: field errors carry the field
// and a message about the caller's input, an unwritable secret store says
// which dependency is missing; everything else goes through Fail. No branch
// ever echoes a credential or a Teleport message. The later stories call it
// for every error that may come from clusters.Service.Client.
func (s *Server) failCluster(w http.ResponseWriter, r *http.Request, err error) {
	var fe *clusters.FieldError
	var ge *clusters.GuardError
	switch {
	case errors.As(err, &ge):
		// A safety guard: no permission overrides it (FR-011, FR-013).
		WriteJSON(w, ErrForbidden.Status, map[string]any{"reason": ErrForbidden.Reason, "message": ge.Msg,
			"detail": map[string]any{"guard": ge.Guard, "message": ge.Msg}})
	case errors.As(err, &fe):
		WriteDetail(w, ErrValidation, map[string]any{"field": fe.Field, "message": fe.Msg})
	case errors.Is(err, clusters.ErrUnsupportedVersion):
		WriteError(w, ErrUnsupportedVersion.Status, ErrUnsupportedVersion.Reason)
	case errors.Is(err, secrets.ErrWriteUnsupported):
		// Production stores credentials in warden, which has no write RPC yet:
		// registration is refused rather than stored anywhere else.
		WriteDetail(w, ErrDependency, map[string]any{"dependency": "secret_store",
			"message": "the secret store cannot store Teleport credentials yet (warden write support is pending)"})
	case errors.Is(err, secrets.ErrUnavailable):
		WriteDetail(w, ErrDependency, map[string]any{"dependency": "secret_store"})
	default:
		Fail(w, r, s.log, err)
	}
}

// parseList reads page/page_size/sort/order against spec; an invalid value
// is answered with validation_failed naming the parameter and ok=false.
func parseList(w http.ResponseWriter, r *http.Request, spec listquery.Spec) (listquery.Request, bool) {
	req, err := listquery.Parse(r.URL.Query(), spec)
	var le *listquery.Error
	if errors.As(err, &le) {
		WriteDetail(w, ErrValidation, map[string]any{"param": le.Param})
		return req, false
	}
	if err != nil {
		WriteError(w, ErrValidation.Status, ErrValidation.Reason)
		return req, false
	}
	return req, true
}

// registerClusters mounts the cluster routes (US1). Route permissions are
// enforced by the authorize middleware from the document; the service checks
// them again with the cluster's tenant ownership (another tenant's id is
// not_found). This is the handler-registration pattern of every story: one
// registerX(service) calling MustHandle for each declared route.
func (s *Server) registerClusters(svc *clusters.Service) {
	s.MustHandle("GET", Prefix+"/clusters", func(w http.ResponseWriter, r *http.Request) {
		req, ok := parseList(w, r, clusters.ClusterList)
		if !ok {
			return
		}
		page, err := svc.List(r.Context(), req)
		if err != nil {
			s.failCluster(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, page)
	})
	s.MustHandle("POST", Prefix+"/clusters", func(w http.ResponseWriter, r *http.Request) {
		var in clusters.RegisterInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failCluster(w, r, err)
			return
		}
		v, err := svc.Register(r.Context(), in)
		if err != nil {
			s.failCluster(w, r, err)
			return
		}
		WriteJSON(w, http.StatusCreated, v)
	})
	s.MustHandle("GET", Prefix+"/clusters/{id}", func(w http.ResponseWriter, r *http.Request) {
		v, err := svc.Get(r.Context(), r.PathValue("id"))
		if err != nil {
			s.failCluster(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, v)
	})
	s.MustHandle("PATCH", Prefix+"/clusters/{id}", func(w http.ResponseWriter, r *http.Request) {
		var in clusters.UpdateInput
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
	s.MustHandle("DELETE", Prefix+"/clusters/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.Remove(r.Context(), r.PathValue("id")); err != nil {
			s.failCluster(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	s.MustHandle("POST", Prefix+"/clusters/{id}/credential", func(w http.ResponseWriter, r *http.Request) {
		var in clusters.RotateInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failCluster(w, r, err)
			return
		}
		v, err := svc.RotateCredential(r.Context(), r.PathValue("id"), in)
		if err != nil {
			s.failCluster(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, v)
	})
	s.MustHandle("POST", Prefix+"/clusters/{id}/check", func(w http.ResponseWriter, r *http.Request) {
		v, err := svc.Check(r.Context(), r.PathValue("id"))
		if err != nil {
			s.failCluster(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, v)
	})
}
