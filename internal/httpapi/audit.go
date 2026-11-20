package httpapi

import (
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/auditlog"
)

// queryTime reads an RFC 3339 query parameter (zero when absent; the
// document has validated the format).
func queryTime(q url.Values, name string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, q.Get(name))
	return t
}

func queryInt(q url.Values, name string) int {
	n, _ := strconv.Atoi(q.Get(name))
	return n
}

// registerAudit mounts the Teleport event and session search and the
// module audit trail (US4). Teleport-supplied strings are returned as JSON
// data only (encoding/json escapes <, > and &).
func (s *Server) registerAudit(svc *auditlog.Service) {
	s.MustHandle("GET", Prefix+"/clusters/{id}/events", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		p, err := svc.Events(r.Context(), r.PathValue("id"), auditlog.Query{From: queryTime(q, "from"), To: queryTime(q, "to"),
			Types: q["types"], User: q.Get("user"), Resource: q.Get("resource"), Limit: queryInt(q, "limit"), Next: q.Get("next")})
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, p)
	})
	s.MustHandle("GET", Prefix+"/clusters/{id}/sessions", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		p, err := svc.Sessions(r.Context(), r.PathValue("id"), auditlog.SessionQuery{From: queryTime(q, "from"), To: queryTime(q, "to"),
			Limit: queryInt(q, "limit"), Next: q.Get("next")})
		if err != nil {
			s.failIdentity(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, p)
	})
	s.MustHandle("GET", Prefix+"/audit", func(w http.ResponseWriter, r *http.Request) {
		req, ok := parseList(w, r, auditlog.TrailList)
		if !ok {
			return
		}
		q := r.URL.Query()
		p, err := svc.Trail(r.Context(), req, auditlog.TrailFilter{ClusterID: q.Get("cluster_id"), Action: q.Get("action"),
			Outcome: q.Get("outcome"), From: queryTime(q, "from"), To: queryTime(q, "to")})
		if err != nil {
			s.failCluster(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, p)
	})
}
