package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/enroll"
)

// registerEnrollments mounts the inventory-agent enrollment routes (spec
// 002). No response carries a join token: it is minted only when the
// host's agent fetches the material through inventory.
func (s *Server) registerEnrollments(svc *enroll.Service) {
	s.MustHandle("GET", Prefix+"/clusters/{id}/enrollment-targets", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		limit := 0
		if v := q.Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n == 0 {
				n = -1 // refused by the service as validation_failed
			}
			limit = n
		}
		p, err := svc.ListTargets(r.Context(), r.PathValue("id"), q.Get("q"), limit)
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, p)
	})
	s.MustHandle("GET", Prefix+"/clusters/{id}/enrollments", func(w http.ResponseWriter, r *http.Request) {
		p, err := svc.List(r.Context(), r.PathValue("id"))
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, p)
	})
	s.MustHandle("POST", Prefix+"/clusters/{id}/enrollments", func(w http.ResponseWriter, r *http.Request) {
		var in enroll.CreateInput
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
	s.MustHandle("POST", Prefix+"/clusters/{id}/enrollments/{eid}/cancel", func(w http.ResponseWriter, r *http.Request) {
		v, err := svc.Cancel(r.Context(), r.PathValue("id"), r.PathValue("eid"))
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, v)
	})
	s.MustHandle("POST", Prefix+"/clusters/{id}/enrollments/{eid}/retry", func(w http.ResponseWriter, r *http.Request) {
		v, err := svc.Retry(r.Context(), r.PathValue("id"), r.PathValue("eid"))
		var re *enroll.RefusedError
		if errors.As(err, &re) {
			err = &Error{http.StatusConflict, re.Reason}
		}
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusCreated, v)
	})
}
