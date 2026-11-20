// Package contract verifies the Teleport OpenAPI document against the
// mounted HTTP surface and the gateway manifest (T042): the document parses
// and validates; every route declares a known permission (only /health is
// public); every mutating route requires the CSRF header; every route the
// server mounts is declared; no schema can carry credential material; and
// handler responses validate against the declared schemas. The user-story
// tasks extend contractRoutes and the response cases as their routes land.
package contract

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-teleport/v4/pkg/teleportmanifest"
)

// contractRoutes are the routes of contracts/http-api.md declared so far:
// the platform routes plus each story's (clusters_test.go for US1,
// identity_test.go for US2).
var contractRoutes = append([]string{
	"GET /api/teleport/v1/health",
	"GET /api/teleport/v1/stream",
}, append(append(append(append(append(clusterRouteList(), identityRouteList()...), resourceRouteList()...), enrollmentRouteList()...), auditRouteList()...),
	append(provisioningRouteList(), deploymentRouteList()...)...)...)

func load(t *testing.T) *openapi3.T {
	t.Helper()
	doc, err := httpapi.LoadDocument()
	if err != nil {
		t.Fatalf("document: %v", err)
	}
	return doc
}

func TestDocumentMatchesContract(t *testing.T) {
	doc := load(t)
	declared := map[string]bool{}
	for _, r := range httpapi.DeclaredRoutes(doc) {
		declared[r.String()] = true
	}
	for _, want := range contractRoutes {
		if !declared[want] {
			t.Errorf("contract route %s is not declared", want)
		}
	}
	if len(declared) != len(contractRoutes) {
		t.Errorf("declared %d routes, contract lists %d", len(declared), len(contractRoutes))
	}
	routes, err := teleportmanifest.Routes(doc)
	if err != nil {
		t.Fatalf("manifest routes: %v", err)
	}
	public := httpapi.PublicRoutes(doc)
	if len(public) != 1 || !public[httpapi.Route{Method: "GET", Path: "/api/teleport/v1/health"}] {
		t.Fatalf("exactly /health is public: %v", public)
	}
	for _, r := range routes {
		if r.Public {
			continue
		}
		if !authz.Known(r.Permission) {
			t.Errorf("%s %s: unknown permission %q", r.Method, r.Path, r.Permission)
		}
		if r.Path == "/api/teleport/v1/stream" && (r.Timeout != 5*time.Minute || r.Permission != authz.ClustersRead) {
			t.Errorf("/stream: %v %s", r.Timeout, r.Permission)
		}
	}
}

func TestMutationsRequireCSRF(t *testing.T) {
	doc := load(t)
	for p, item := range doc.Paths.Map() {
		for m, op := range item.Operations() {
			if m == "GET" || m == "HEAD" {
				continue
			}
			found := false
			for _, prm := range op.Parameters {
				if prm.Value != nil && prm.Value.In == "header" && prm.Value.Name == "X-CSRF-Token" && prm.Value.Required {
					found = true
				}
			}
			if !found {
				t.Errorf("%s %s does not require X-CSRF-Token", m, p)
			}
		}
	}
}

// forbiddenFields must never appear in a response schema (SR-001/SR-002):
// identity files, private keys and secret references stay server-side.
// One-time values (join tokens, invite URLs) are declared per route and
// checked by the story tasks.
var forbiddenFields = []string{"identity_file", "private_key", "credential_ref", "password", "secret", "api_key"}

func schemaFields(s *openapi3.SchemaRef, out map[string]bool, seen map[*openapi3.Schema]bool) {
	if s == nil || s.Value == nil || seen[s.Value] {
		return
	}
	v := s.Value
	seen[v] = true
	for k, p := range v.Properties {
		out[strings.ToLower(k)] = true
		schemaFields(p, out, seen)
	}
	schemaFields(v.Items, out, seen)
	if v.AdditionalProperties.Schema != nil {
		schemaFields(v.AdditionalProperties.Schema, out, seen)
	}
	for _, group := range []openapi3.SchemaRefs{v.AllOf, v.AnyOf, v.OneOf} {
		for _, sub := range group {
			schemaFields(sub, out, seen)
		}
	}
}

func TestNoResponseCarriesCredentialMaterial(t *testing.T) {
	doc := load(t)
	fields := map[string]bool{}
	for _, item := range doc.Paths.Map() {
		for _, op := range item.Operations() {
			if op.Responses == nil {
				continue
			}
			for _, resp := range op.Responses.Map() {
				if resp.Value == nil {
					continue
				}
				for _, media := range resp.Value.Content {
					schemaFields(media.Schema, fields, map[*openapi3.Schema]bool{})
				}
			}
		}
	}
	if !fields["reason"] {
		t.Fatal("schema walk missed the Error schema")
	}
	for f := range fields {
		for _, bad := range forbiddenFields {
			if strings.Contains(f, bad) {
				t.Errorf("a response exposes field %q", f)
			}
		}
	}
}

func TestMountedRoutesAreDeclared(t *testing.T) {
	s := server(t)
	declared := map[string]bool{}
	for _, r := range s.Declared() {
		declared[r.String()] = true
	}
	var got []string
	for _, r := range s.Implemented() {
		if !declared[r.String()] {
			t.Errorf("mounted but undeclared: %s", r)
		}
		got = append(got, r.String())
	}
	if !strings.Contains(strings.Join(got, ","), "GET /api/teleport/v1/health") {
		t.Errorf("/health not mounted (have %v)", got)
	}
	if err := s.HandleFunc("GET", "/api/teleport/v1/proxy", nil); err == nil {
		t.Fatal("an undeclared route was mounted")
	}
}

type verifier struct{}

func (verifier) Verify(_ context.Context, token string) (authclient.Identity, error) {
	if token == "admin" {
		return authclient.Identity{UserID: "u1", TenantID: "11111111-1111-7111-8111-111111111111"}, nil
	}
	return authclient.Identity{}, httpapi.ErrUnauthenticated
}

func server(t *testing.T) *httpapi.Server {
	t.Helper()
	rt := testrt.New(t, testutil.MustCA("example.org"), "teleport")
	s, err := httpapi.NewHandler(rt, httpapi.WithVerifier(verifier{}), httpapi.WithChecker(authz.Static{"u1": authz.Permissions}))
	if err != nil {
		t.Fatal(err)
	}
	s.Register(httpapi.Deps{Health: func() map[string]string { return map[string]string{"store": "ok"} }})
	return s
}

// ValidateResponse checks a recorded response against the document: the
// harness the story tasks call for every handler they add.
func ValidateResponse(t *testing.T, doc *openapi3.T, req *http.Request, w *httptest.ResponseRecorder) {
	t.Helper()
	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		t.Fatal(err)
	}
	route, params, err := router.FindRoute(req)
	if err != nil {
		t.Fatalf("route %s %s: %v", req.Method, req.URL.Path, err)
	}
	in := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{Request: req, PathParams: params, Route: route,
			Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc}},
		Status: w.Code, Header: w.Header(), Body: io.NopCloser(bytes.NewReader(w.Body.Bytes())),
		Options: &openapi3filter.Options{IncludeResponseStatus: true},
	}
	if err := openapi3filter.ValidateResponse(context.Background(), in); err != nil {
		t.Errorf("%s %s -> %d does not match the document: %v\n%s", req.Method, req.URL.Path, w.Code, err, w.Body)
	}
}

func TestResponsesMatchSchemas(t *testing.T) {
	doc := load(t)
	s := server(t)
	for _, c := range []struct {
		path, token string
		status      int
	}{
		{"/api/teleport/v1/health", "", 200},
		{"/api/teleport/v1/stream", "", 401}, // default Error response
	} {
		req := httptest.NewRequest("GET", "https://localhost"+c.path, nil)
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != c.status {
			t.Fatalf("%s = %d", c.path, w.Code)
		}
		ValidateResponse(t, doc, req, w)
	}
}
