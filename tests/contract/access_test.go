package contract

import (
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
)

// accessRoutes are the spec 004 routes (plan.md Contract).
var accessRoutes = map[string]string{
	"GET /api/teleport/v1/clusters/{id}/access":                     authz.AccessTerminal,
	"GET /api/teleport/v1/clusters/{id}/access/nodes":               authz.AccessTerminal,
	"POST /api/teleport/v1/clusters/{id}/access/identity":           authz.AccessDownload,
	"PUT /api/teleport/v1/clusters/{id}/access/settings":            authz.ClustersManage,
	"POST /api/teleport/v1/clusters/{id}/terminals":                 authz.AccessTerminal,
	"DELETE /api/teleport/v1/clusters/{id}/terminals/{tid}":         authz.AccessTerminal,
	"GET /api/teleport/v1/clusters/{id}/terminals/{tid}/output":     authz.AccessTerminal,
	"POST /api/teleport/v1/clusters/{id}/terminals/{tid}/input":     authz.AccessTerminal,
	"POST /api/teleport/v1/clusters/{id}/terminals/{tid}/resize":    authz.AccessTerminal,
	"POST /api/teleport/v1/clusters/{id}/terminals/{tid}/keepalive": authz.AccessTerminal,
}

func accessRouteList() []string {
	out := make([]string, 0, len(accessRoutes))
	for r := range accessRoutes {
		out = append(out, r)
	}
	return out
}
