package teleportmanifest

import (
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/go-tangra/go-tangra-teleport/v4/api/openapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
)

func TestOpenAPIParsesAndValidates(t *testing.T) {
	openapi3.DefineStringFormatValidator("uuid", openapi3.NewRegexpFormatValidator(openapi3.FormatOfStringForUUIDOfRFC9562))
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(openapi.Teleport)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := doc.Validate(loader.Context, openapi3.DisableExamplesValidation()); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// Every OpenAPI operation has a known permission (or is the public health route).
func TestManifestBuilds(t *testing.T) {
	m, err := Manifest()
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if m.Module != "teleport" || m.DisplayName != "Teleport" || len(m.Prefixes) != 1 || m.Prefixes[0] != "/api/teleport" || len(m.Methods) != 0 {
		t.Fatalf("identity = %+v", m)
	}
	if len(m.Routes) == 0 {
		t.Fatal("no routes")
	}
	known := PermissionRefs()
	for _, r := range m.Routes {
		if !strings.HasPrefix(r.Path, "/api/teleport/v1/") {
			t.Fatalf("route outside prefix: %s", r.Path)
		}
		if r.Public {
			if r.Path != "/api/teleport/v1/health" {
				t.Fatalf("unexpected public route %s", r.Path)
			}
			continue
		}
		if !slices.Contains(known, r.Permission) {
			t.Fatalf("%s %s permission %q unknown", r.Method, r.Path, r.Permission)
		}
		if r.Path == "/api/teleport/v1/stream" && (r.Permission != "clusters:read" || r.Timeout.Seconds() != 300) {
			t.Fatalf("stream route %+v", r)
		}
	}
	if !slices.Equal(m.Exposes, []string{"./routes", "./nav"}) {
		t.Fatalf("exposes %v", m.Exposes)
	}
}

// Nav entries exist, use mdi icons and require module permissions.
func TestNav(t *testing.T) {
	if len(Nav) == 0 {
		t.Fatal("no nav")
	}
	for _, n := range Nav {
		if !strings.HasPrefix(n.Path, "/teleport") || !strings.HasPrefix(n.Icon, "mdi-") || !slices.Contains(PermissionRefs(), n.Requires) {
			t.Errorf("nav %+v", n)
		}
	}
	if Nav[0].Title != "Clusters" || Nav[0].Path != "/teleport" || Nav[0].Requires != "clusters:read" {
		t.Fatalf("first nav %+v", Nav[0])
	}
	for _, a := range Abilities {
		if !slices.Contains(PermissionRefs(), a.Requires) {
			t.Errorf("ability %+v requires an unknown permission", a)
		}
	}
}

// The manifest's permission vocabulary is exactly the module's authz set
// (which TestPermissionsMatchContract pins to contracts/http-api.md).
func TestPermissionsMatchAuthz(t *testing.T) {
	got := PermissionRefs()
	want := append([]string(nil), authz.Permissions...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("manifest %v != authz %v", got, want)
	}
}

var reads = []string{"clusters:read", "users:read", "roles:read", "locks:read", "resources:read", "audit:read", "alerts:read"}

// TestRoles pins the module roles of contracts/http-api.md.
func TestRoles(t *testing.T) {
	want := map[string][]string{
		"administrator": authz.Permissions,
		"operator":      append(slices.Clone(reads), "tokens:manage", "locks:manage", "resources:link", "resources:enroll", "access:terminal"),
		"auditor":       reads,
		"viewer":        slices.DeleteFunc(slices.Clone(reads), func(p string) bool { return p == "audit:read" }),
	}
	if len(Roles) != len(want) {
		t.Fatalf("want %d roles, got %d", len(want), len(Roles))
	}
	slug := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`)
	for _, r := range Roles {
		if !slug.MatchString(r.Slug) || r.DisplayName != "Teleport "+r.Slug || r.Description == "" {
			t.Errorf("role %+v", r)
		}
		got, exp := slices.Clone(r.Permissions), slices.Clone(want[r.Slug])
		sort.Strings(got)
		sort.Strings(exp)
		if !reflect.DeepEqual(got, exp) {
			t.Errorf("role %q: permissions %v, want %v", r.Slug, got, exp)
		}
		// SR-005: only administrators manage Teleport roles.
		if r.Slug != "administrator" && slices.Contains(r.Permissions, "roles:manage") {
			t.Errorf("role %q holds roles:manage", r.Slug)
		}
	}
}

// TestGrants: owner/admin → administrator, operator → operator, auditor →
// auditor, member → viewer.
func TestGrants(t *testing.T) {
	role := func(slug string) []string {
		for _, r := range Roles {
			if r.Slug == slug {
				return r.Permissions
			}
		}
		return nil
	}
	want := map[string][]string{"owner": role("administrator"), "admin": role("administrator"), "operator": role("operator"),
		"auditor": role("auditor"), "member": role("viewer")}
	if !reflect.DeepEqual(Grants, want) {
		t.Fatalf("grants:\n got %v\nwant %v", Grants, want)
	}
	if len(BuiltinRoles) != len(Grants) {
		t.Fatalf("BuiltinRoles %v vs grants %v", BuiltinRoles, Grants)
	}
}

// Spec 003 FR-010 / R13: sessions:play goes to the administrator role and
// the owner/admin grants only; every other role and grant is built from
// the *:read permissions and never holds it.
func TestSessionsPlayAdministratorsOnly(t *testing.T) {
	const play = "sessions:play"
	if !slices.Contains(PermissionRefs(), play) {
		t.Fatalf("%s not declared", play)
	}
	for _, r := range Roles {
		if got := slices.Contains(r.Permissions, play); got != (r.Slug == "administrator") {
			t.Errorf("role %q holds %s = %v", r.Slug, play, got)
		}
	}
	for slug, perms := range Grants {
		if got := slices.Contains(perms, play); got != (slug == "owner" || slug == "admin") {
			t.Errorf("grant %q holds %s = %v", slug, play, got)
		}
	}
	found := false
	for _, a := range Abilities {
		if a.Requires == play {
			found = slices.Equal(a.Action, []string{"play"}) && slices.Equal(a.Subject, []string{"TeleportSession"})
		}
	}
	if !found {
		t.Fatal("no play/TeleportSession ability for sessions:play")
	}
}

// Spec 004 FR-015 / R13: administrators get both brokered-access
// permissions, operators the terminal only, auditors and viewers neither.
func TestBrokeredAccessGrants(t *testing.T) {
	const term, dl = "access:terminal", "access:download"
	for _, p := range []string{term, dl} {
		if !slices.Contains(PermissionRefs(), p) {
			t.Fatalf("%s not declared", p)
		}
	}
	want := map[string][2]bool{"administrator": {true, true}, "operator": {true, false}, "auditor": {false, false}, "viewer": {false, false}}
	for _, r := range Roles {
		got := [2]bool{slices.Contains(r.Permissions, term), slices.Contains(r.Permissions, dl)}
		if got != want[r.Slug] {
			t.Errorf("role %q: terminal/download = %v, want %v", r.Slug, got, want[r.Slug])
		}
	}
	grants := map[string][2]bool{"owner": {true, true}, "admin": {true, true}, "operator": {true, false}, "auditor": {false, false}, "member": {false, false}}
	for slug, perms := range Grants {
		got := [2]bool{slices.Contains(perms, term), slices.Contains(perms, dl)}
		if got != grants[slug] {
			t.Errorf("grant %q: terminal/download = %v, want %v", slug, got, grants[slug])
		}
	}
	abilities := map[string]string{}
	for _, a := range Abilities {
		abilities[a.Requires] = strings.Join(a.Action, ",") + "/" + strings.Join(a.Subject, ",")
	}
	if abilities[term] != "terminal/TeleportAccess" || abilities[dl] != "download/TeleportAccess" {
		t.Fatalf("abilities %v", abilities)
	}
}

func TestRegistration(t *testing.T) {
	reg := Registration()
	if err := reg.Validate(); err != nil {
		t.Fatal(err)
	}
	req := reg.Request()
	if req.GetModule() != "teleport" || req.GetModuleDisplayName() != "Teleport" || !req.GetDeclaresRoles() {
		t.Fatalf("module %q display %q declares_roles %v", req.GetModule(), req.GetModuleDisplayName(), req.GetDeclaresRoles())
	}
	if len(req.GetPermissions()) != len(authz.Permissions) || len(req.GetRoles()) != 4 {
		t.Fatalf("%d permissions, %d roles", len(req.GetPermissions()), len(req.GetRoles()))
	}
}

func docWith(ext map[string]any) *openapi3.T {
	paths := openapi3.NewPaths()
	paths.Set("/x", &openapi3.PathItem{Get: &openapi3.Operation{Extensions: ext}})
	return &openapi3.T{Paths: paths}
}

func TestRoutesValidationBranches(t *testing.T) {
	routes, err := Routes(docWith(map[string]any{PublicExtension: true}))
	if err != nil || !routes[0].Public {
		t.Fatalf("public: %v", err)
	}
	routes, err = Routes(docWith(map[string]any{PermissionExtension: "clusters:read", BodyLimitExtension: float64(2048), TimeoutExtension: float64(30)}))
	if err != nil || routes[0].MaxBodyBytes != 2048 || routes[0].Timeout.Seconds() != 30 {
		t.Fatalf("valid: %v %+v", err, routes)
	}
	bad := []map[string]any{
		{},
		{PermissionExtension: "made:up"},
		{PermissionExtension: "clusters:read", BodyLimitExtension: float64(0)},
		{PermissionExtension: "clusters:read", BodyLimitExtension: "big"},
		{PermissionExtension: "clusters:read", TimeoutExtension: float64(9999)},
		{PermissionExtension: "clusters:read", TimeoutExtension: "slow"},
	}
	for i, ext := range bad {
		if _, err := Routes(docWith(ext)); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

// The gateway's manifest schema (go-tangra-portal internal/manifest) refuses
// the whole registration when any route path falls outside this pattern.
var gatewayPathRE = regexp.MustCompile(`^/[A-Za-z0-9._~-]+(/([A-Za-z0-9._~-]+|\{[a-z][a-z0-9_]*\}))*(/\{[a-z][a-z0-9_]*\.\.\.\})?$`)

func TestRoutePathsMatchGatewaySchema(t *testing.T) {
	m, err := Manifest()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range m.Routes {
		if !gatewayPathRE.MatchString(r.Path) {
			t.Errorf("%s %s: the gateway refuses this path", r.Method, r.Path)
		}
	}
}
