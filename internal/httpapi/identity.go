package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/roleyaml"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// failIdentity is failCluster for the user, role and lock routes (US2),
// which also explain refusals about the caller's own input: an invalid role
// definition (roleyaml's bounded message) and a Teleport rejection (the
// sanitized first line of Teleport's message, never a stack trace).
func (s *Server) failIdentity(w http.ResponseWriter, r *http.Request, err error) {
	var ye *roleyaml.Error
	switch {
	case errors.As(err, &ye):
		WriteDetail(w, ErrValidation, map[string]any{"field": "yaml", "message": ye.Msg})
	case teleportapi.Reason(err) == ErrTeleportRejected.Reason && teleportapi.Detail(err) != "":
		WriteDetail(w, ErrTeleportRejected, map[string]any{"message": teleportapi.Detail(err)})
	default:
		s.failCluster(w, r, err)
	}
}

// pageSize reads the optional page_size (validated by the document).
func pageSize(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	return n
}
