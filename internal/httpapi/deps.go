package httpapi

import (
	"net/http"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/alerts"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/auditlog"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/deploy"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/locks"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/provisioning"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/resources"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/roles"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/stream"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/tokens"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/users"
)

// Prefix of the browser API.
const Prefix = "/api/teleport/v1"

// Deps wire the HTTP handlers. Every field is optional: a route whose service
// is not wired answers 501 not_implemented. The domain services of the user
// stories (clusters, users, roles, locks, tokens, resources, audit, alerts,
// provisioning, deployments) are added here as they land; the router
// registration pattern is one registerX(service) per story, each calling
// MustHandle for its declared routes.
type Deps struct {
	Health func() map[string]string // component status for /health
	Hub    *stream.Hub              // SSE relay of the tenant's teleport.* events

	Clusters *clusters.Service // US1: registration, health, credential rotation
	Users    *users.Service    // US2: Teleport users and their invite/reset links
	Roles    *roles.Service    // US2: Teleport roles as YAML
	Locks    *locks.Service    // US2: locks

	Tokens    *tokens.Service    // US3: join tokens
	Resources *resources.Service // US3: resource inventory and links

	Audit  *auditlog.Service // US4: Teleport events and sessions, module audit trail
	Alerts *alerts.Rules     // US4: alert rules

	Provisioning *provisioning.Service // US5: role mappings, managed users, sync
	Deployments  *deploy.Service       // US6: deployment wizard drafts, artifacts, checks
}

// Register mounts the handlers of every wired dependency.
func (s *Server) Register(d Deps) {
	s.MustHandle("GET", Prefix+"/health", func(w http.ResponseWriter, _ *http.Request) {
		out := map[string]any{"status": "ok"}
		if d.Health != nil {
			comps := d.Health()
			for _, v := range comps {
				if v != "ok" {
					out["status"] = "degraded"
				}
			}
			out["components"] = comps
		}
		WriteJSON(w, http.StatusOK, out)
	})
	if d.Hub != nil {
		s.registerStream(d.Hub)
	}
	if d.Clusters != nil {
		s.registerClusters(d.Clusters)
	}
	if d.Users != nil {
		s.registerUsers(d.Users)
	}
	if d.Roles != nil {
		s.registerRoles(d.Roles)
	}
	if d.Locks != nil {
		s.registerLocks(d.Locks)
	}
	if d.Tokens != nil {
		s.registerTokens(d.Tokens)
	}
	if d.Resources != nil {
		s.registerResources(d.Resources)
	}
	if d.Audit != nil {
		s.registerAudit(d.Audit)
	}
	if d.Alerts != nil {
		s.registerAlerts(d.Alerts)
	}
	if d.Provisioning != nil {
		s.registerProvisioning(d.Provisioning)
	}
	if d.Deployments != nil {
		s.registerDeployments(d.Deployments)
	}
}
