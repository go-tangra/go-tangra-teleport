package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/provisioning"
)

// failProvisioning is failIdentity for the provisioning routes, which also
// name the missing dependency: auth (membership) or notification (invites).
func (s *Server) failProvisioning(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, provisioning.ErrMembershipUnavailable):
		WriteDetail(w, ErrDependency, map[string]any{"dependency": "auth",
			"message": "the tenant's membership cannot be read from auth; nothing was changed"})
	case errors.Is(err, notify.ErrUnavailable), errors.Is(err, notify.ErrNotDelivered):
		WriteDetail(w, ErrDependency, map[string]any{"dependency": "notification",
			"message": "the invite could not be delivered; the user was not provisioned"})
	case errors.Is(err, provisioning.ErrRetryFailed):
		WriteDetail(w, ErrUnavailable, map[string]any{"message": "retrying the provisioning failed; see the module audit trail"})
	default:
		s.failIdentity(w, r, err)
	}
}

// registerProvisioning mounts the role-mapping, managed-user, sync and
// member-search routes (US5). No response carries an invite link: it goes through notification.
func (s *Server) registerProvisioning(svc *provisioning.Service) {
	s.MustHandle("GET", Prefix+"/clusters/{id}/mappings", func(w http.ResponseWriter, r *http.Request) {
		p, err := svc.ListMappings(r.Context(), r.PathValue("id"))
		if err != nil {
			s.failProvisioning(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, p)
	})
	s.MustHandle("POST", Prefix+"/clusters/{id}/mappings", func(w http.ResponseWriter, r *http.Request) {
		var in provisioning.MappingInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failProvisioning(w, r, err)
			return
		}
		v, err := svc.CreateMapping(r.Context(), r.PathValue("id"), in)
		if err != nil {
			s.failProvisioning(w, r, err)
			return
		}
		WriteJSON(w, http.StatusCreated, v)
	})
	s.MustHandle("PUT", Prefix+"/clusters/{id}/mappings/{mid}", func(w http.ResponseWriter, r *http.Request) {
		var in provisioning.MappingUpdate
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failProvisioning(w, r, err)
			return
		}
		v, err := svc.UpdateMapping(r.Context(), r.PathValue("id"), r.PathValue("mid"), in)
		if err != nil {
			s.failProvisioning(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, v)
	})
	s.MustHandle("DELETE", Prefix+"/clusters/{id}/mappings/{mid}", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.DeleteMapping(r.Context(), r.PathValue("id"), r.PathValue("mid")); err != nil {
			s.failProvisioning(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	s.MustHandle("GET", Prefix+"/clusters/{id}/managed-users", func(w http.ResponseWriter, r *http.Request) {
		p, err := svc.ListManaged(r.Context(), r.PathValue("id"))
		if err != nil {
			s.failProvisioning(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, p)
	})
	s.MustHandle("POST", Prefix+"/clusters/{id}/managed-users", func(w http.ResponseWriter, r *http.Request) {
		var in provisioning.ProvisionInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failProvisioning(w, r, err)
			return
		}
		v, err := svc.Provision(r.Context(), r.PathValue("id"), in)
		if err != nil {
			s.failProvisioning(w, r, err)
			return
		}
		WriteJSON(w, http.StatusCreated, v)
	})
	s.MustHandle("POST", Prefix+"/clusters/{id}/provisioning/sync", func(w http.ResponseWriter, r *http.Request) {
		sum, err := svc.Sync(r.Context(), r.PathValue("id"))
		if err != nil {
			s.failProvisioning(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, sum)
	})
	s.MustHandle("GET", Prefix+"/clusters/{id}/provisioning/members", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit := 0
		if v := q.Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n == 0 {
				n = -1 // refused by the service as validation_failed
			}
			limit = n
		}
		p, err := svc.SearchMembers(r.Context(), r.PathValue("id"), q.Get("q"), limit)
		if err != nil {
			s.failProvisioning(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, p)
	})
}
