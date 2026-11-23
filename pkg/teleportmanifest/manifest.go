// Package teleportmanifest declares what the Teleport module registers with
// the application gateway: routes derived from the embedded OpenAPI
// document, the API permissions, the CASL abilities and the navigation
// entries; plus the module roles and built-in role grants it registers with
// the auth service (contracts/http-api.md). The teleport.v1 gRPC surface is
// service to service and is not proxied by the gateway. Adapted from dns-v4
// pkg/dnsmanifest.
package teleportmanifest

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra-portal/sdk/v4/pkg/gatewayclient"

	"github.com/go-tangra/go-tangra-teleport/v4/api/openapi"
)

// Module identity.
const (
	Module       = "teleport"
	DisplayName  = "Teleport"
	Version      = "1.0.0"
	RemotePrefix = "/ui"
	APIPrefix    = "/api/teleport"
)

// OpenAPI operation extensions.
const (
	PermissionExtension = "x-freya-permission"
	PublicExtension     = "x-freya-public"
	BodyLimitExtension  = "x-freya-max-body-bytes"
	TimeoutExtension    = "x-freya-timeout-seconds"
)

// Permissions the module registers (contracts/http-api.md).
var Permissions = []gatewayclient.Permission{
	{Resource: "clusters", Action: "read", Description: "List and view Teleport clusters and their health, and the live stream"},
	{Resource: "clusters", Action: "manage", Description: "Register, edit and remove clusters and rotate their credential"},
	{Resource: "users", Action: "read", Description: "List and view Teleport users, managed users and role mappings"},
	{Resource: "users", Action: "manage", Description: "Create, edit, reset and delete Teleport users"},
	{Resource: "roles", Action: "read", Description: "List and view Teleport roles"},
	{Resource: "roles", Action: "manage", Description: "Create, edit and delete Teleport roles (administrators only)"},
	{Resource: "locks", Action: "read", Description: "List active Teleport locks"},
	{Resource: "locks", Action: "manage", Description: "Create and remove Teleport locks"},
	{Resource: "tokens", Action: "manage", Description: "Create, list and revoke join tokens"},
	{Resource: "resources", Action: "read", Description: "List enrolled resources and their inventory/asset links"},
	{Resource: "resources", Action: "link", Description: "Confirm or remove inventory/asset links"},
	{Resource: "resources", Action: "enroll", Description: "Enroll inventory hosts as SSH nodes through their inventory agent"},
	{Resource: "audit", Action: "read", Description: "Read Teleport audit events and sessions and the module audit trail"},
	{Resource: "alerts", Action: "read", Description: "List alert rules"},
	{Resource: "alerts", Action: "manage", Description: "Create, edit and delete alert rules"},
	{Resource: "provisioning", Action: "manage", Description: "Manage role mappings and provision or de-provision Tangra users"},
	{Resource: "deployments", Action: "manage", Description: "Use the deployment wizard: drafts, artifacts and checks"},
	{Resource: "sessions", Action: "play", Description: "Replay recorded SSH sessions in the portal (shows everything that was on the terminal)"},
}

// PermissionRefs lists "resource:action" for every declared permission.
func PermissionRefs() []string {
	out := make([]string, 0, len(Permissions))
	for _, p := range Permissions {
		out = append(out, p.Resource+":"+p.Action)
	}
	return out
}

// readPermissions are the *:read permissions.
func readPermissions() []string {
	var out []string
	for _, p := range Permissions {
		if p.Action == "read" {
			out = append(out, p.Resource+":"+p.Action)
		}
	}
	return out
}

// Permission sets of the module roles (contracts/http-api.md).
var (
	administratorPermissions = PermissionRefs()
	operatorPermissions      = append(readPermissions(), "tokens:manage", "locks:manage", "resources:link", "resources:enroll")
	auditorPermissions       = readPermissions()
	viewerPermissions        = slices.DeleteFunc(readPermissions(), func(p string) bool { return p == "audit:read" })
)

// Roles is the module's role set (feature 019): ready-made roles auth offers
// in every tenant. Only administrators hold roles:manage (SR-005).
var Roles = []authclient.ModuleRole{
	{
		Slug: "administrator", DisplayName: DisplayName + " administrator",
		Description: "Manage clusters, users, roles, locks, tokens, links, alerts, provisioning and deployments; play recorded sessions",
		Permissions: administratorPermissions,
	},
	{
		Slug: "operator", DisplayName: DisplayName + " operator",
		Description: "Read everything; create join tokens, enroll inventory hosts, manage locks and confirm resource links",
		Permissions: operatorPermissions,
	},
	{
		Slug: "auditor", DisplayName: DisplayName + " auditor",
		Description: "Read everything, including Teleport audit events and sessions",
		Permissions: auditorPermissions,
	},
	{
		Slug: "viewer", DisplayName: DisplayName + " viewer",
		Description: "Read clusters, users, roles, locks, resources and alert rules (no audit)",
		Permissions: viewerPermissions,
	},
}

// Grants maps the platform's built-in role slugs to the module role
// permission sets: owner/admin → administrator, operator → operator,
// auditor → auditor, member → viewer.
var Grants = map[string][]string{
	"owner":    administratorPermissions,
	"admin":    administratorPermissions,
	"operator": operatorPermissions,
	"auditor":  auditorPermissions,
	"member":   viewerPermissions,
}

// BuiltinRoles lists the built-in role slugs granted, in a stable order.
var BuiltinRoles = []string{"owner", "admin", "operator", "auditor", "member"}

// Methods proxied by the gateway: none (teleport.v1 gRPC is service to service).
var Methods []gatewayclient.Method

// Abilities are the CASL rules bound to the permissions.
var Abilities = []gatewayclient.Ability{
	{Action: []string{"read"}, Subject: []string{"TeleportCluster"}, Requires: "clusters:read"},
	{Action: []string{"create", "update", "delete", "rotate"}, Subject: []string{"TeleportCluster"}, Requires: "clusters:manage"},
	{Action: []string{"read"}, Subject: []string{"TeleportUser", "TeleportManagedUser", "TeleportMapping"}, Requires: "users:read"},
	{Action: []string{"create", "update", "delete", "reset"}, Subject: []string{"TeleportUser"}, Requires: "users:manage"},
	{Action: []string{"read"}, Subject: []string{"TeleportRole"}, Requires: "roles:read"},
	{Action: []string{"create", "update", "delete"}, Subject: []string{"TeleportRole"}, Requires: "roles:manage"},
	{Action: []string{"read"}, Subject: []string{"TeleportLock"}, Requires: "locks:read"},
	{Action: []string{"create", "delete"}, Subject: []string{"TeleportLock"}, Requires: "locks:manage"},
	{Action: []string{"manage"}, Subject: []string{"TeleportToken"}, Requires: "tokens:manage"},
	{Action: []string{"read"}, Subject: []string{"TeleportResource"}, Requires: "resources:read"},
	{Action: []string{"link"}, Subject: []string{"TeleportResource"}, Requires: "resources:link"},
	{Action: []string{"enroll"}, Subject: []string{"TeleportResource"}, Requires: "resources:enroll"},
	{Action: []string{"read"}, Subject: []string{"TeleportAudit"}, Requires: "audit:read"},
	{Action: []string{"read"}, Subject: []string{"TeleportAlertRule"}, Requires: "alerts:read"},
	{Action: []string{"create", "update", "delete"}, Subject: []string{"TeleportAlertRule"}, Requires: "alerts:manage"},
	{Action: []string{"manage"}, Subject: []string{"TeleportProvisioning", "TeleportMapping"}, Requires: "provisioning:manage"},
	{Action: []string{"manage"}, Subject: []string{"TeleportDeployment"}, Requires: "deployments:manage"},
	{Action: []string{"play"}, Subject: []string{"TeleportSession"}, Requires: "sessions:play"},
}

// Nav lists the navigation contributions.
var Nav = []gatewayclient.NavEntry{
	{Title: "Clusters", Path: "/teleport", Icon: "mdi-server-security", Order: 990, Requires: "clusters:read"},
	{Title: "Alerts", Path: "/teleport/alerts", Icon: "mdi-bell-alert-outline", Order: 992, Requires: "alerts:read"},
	{Title: "Audit", Path: "/teleport/audit", Icon: "mdi-clipboard-text-clock-outline", Order: 994, Requires: "audit:read"},
	{Title: "Deployments", Path: "/teleport/deployments", Icon: "mdi-rocket-launch-outline", Order: 996, Requires: "deployments:manage"},
}

// Routes derives the gateway routes from the OpenAPI document.
func Routes(doc *openapi3.T) ([]gatewayclient.Route, error) {
	known := map[string]bool{}
	for _, p := range PermissionRefs() {
		known[p] = true
	}
	var routes []gatewayclient.Route
	for p, item := range doc.Paths.Map() {
		for m, op := range item.Operations() {
			r := gatewayclient.Route{Method: strings.ToUpper(m), Path: p}
			perm, _ := op.Extensions[PermissionExtension].(string)
			public, _ := op.Extensions[PublicExtension].(bool)
			switch {
			case public:
				r.Public = true
			case perm == "":
				return nil, fmt.Errorf("teleportmanifest: %s %s declares no permission", r.Method, p)
			case !known[perm]:
				return nil, fmt.Errorf("teleportmanifest: %s %s uses undeclared permission %q", r.Method, p, perm)
			default:
				r.Permission = perm
			}
			if v, ok := op.Extensions[BodyLimitExtension]; ok {
				n, ok := v.(float64)
				if !ok || n <= 0 {
					return nil, fmt.Errorf("teleportmanifest: %s %s has a bad body limit", r.Method, p)
				}
				r.MaxBodyBytes = uint64(n)
			}
			if v, ok := op.Extensions[TimeoutExtension]; ok {
				n, ok := v.(float64)
				if !ok || n <= 0 || n > 600 {
					return nil, fmt.Errorf("teleportmanifest: %s %s has a bad timeout", r.Method, p)
				}
				r.Timeout = time.Duration(n) * time.Second
			}
			routes = append(routes, r)
		}
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Method+" "+routes[i].Path < routes[j].Method+" "+routes[j].Path })
	return routes, nil
}

// Load parses the embedded document.
func Load() (*openapi3.T, error) {
	return openapi3.NewLoader().LoadFromData(openapi.Teleport)
}

// Manifest builds the gateway manifest from the embedded OpenAPI document.
func Manifest() (gatewayclient.Manifest, error) {
	doc, err := Load()
	if err != nil {
		return gatewayclient.Manifest{}, err
	}
	routes, err := Routes(doc)
	if err != nil {
		return gatewayclient.Manifest{}, err
	}
	return gatewayclient.Manifest{
		Module: Module, DisplayName: DisplayName, Version: Version,
		Prefixes:    []string{APIPrefix},
		Routes:      routes,
		Methods:     Methods,
		Permissions: Permissions,
		Abilities:   Abilities,
		Exposes:     []string{"./routes", "./nav"},
		Nav:         Nav,
	}, nil
}

// Registration is what the module registers with auth: every module
// permission, the module roles and the built-in role grants.
func Registration() authclient.Registration {
	reg := authclient.Registration{Module: Module, DisplayName: DisplayName, Roles: Roles, BuiltinGrants: Grants}
	for _, p := range Permissions {
		reg.Permissions = append(reg.Permissions, authclient.Permission{Resource: p.Resource, Action: p.Action, Description: p.Description})
	}
	return reg
}
