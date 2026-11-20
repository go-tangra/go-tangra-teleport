package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/stream"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

const (
	tenant  = "11111111-1111-7111-8111-111111111111"
	viewer  = "44444444-4444-7444-8444-444444444444"
	admin   = "55555555-5555-7555-8555-555555555555"
	nobody  = "66666666-6666-7666-8666-666666666666"
	session = "csrf"
)

type fakeVerifier map[string]authclient.Identity

func (f fakeVerifier) Verify(_ context.Context, token string) (authclient.Identity, error) {
	if id, ok := f[token]; ok {
		return id, nil
	}
	return authclient.Identity{}, ErrUnauthenticated
}

func newServer(t *testing.T, opts ...Option) *Server {
	t.Helper()
	rt := testrt.New(t, testutil.MustCA("example.org"), "teleport")
	v := fakeVerifier{
		"tok-viewer": {UserID: viewer, TenantID: tenant},
		"tok-admin":  {UserID: admin, TenantID: tenant, Roles: []string{"owner"}},
		"tok-nobody": {UserID: nobody, TenantID: tenant},
		"tok-notent": {UserID: admin},
	}
	checker := authz.Static{viewer: {authz.ClustersRead}, admin: authz.Permissions}
	s, err := NewHandler(rt, append([]Option{WithVerifier(v), WithChecker(checker)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func do(s *Server, method, path, token, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if method != http.MethodGet {
		r.Header.Set("X-CSRF-Token", session)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func reason(w *httptest.ResponseRecorder) string {
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	r, _ := m["reason"].(string)
	return r
}

func TestHealthIsPublicAndReportsComponents(t *testing.T) {
	s := newServer(t)
	s.Register(Deps{Health: func() map[string]string { return map[string]string{"store": "ok", "valkey": "unreachable"} }})
	w := do(s, "GET", Prefix+"/health", "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"degraded"`) {
		t.Fatalf("health = %d %s", w.Code, w.Body)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("secure headers missing")
	}
	s2 := newServer(t)
	s2.Register(Deps{})
	if w := do(s2, "GET", Prefix+"/health", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"ok"`) {
		t.Fatalf("bare health = %s", w.Body)
	}
	if s2.IsPublic("GET", Prefix+"/stream") || !s2.IsPublic("GET", Prefix+"/health") {
		t.Fatal("public flags")
	}
}

// The declared x-freya-permission of every route is checked for the verified
// user, and the subjects reach the handler through the context.
func TestPermissionEnforcement(t *testing.T) {
	s := newServer(t)
	var seen authz.Subjects
	s.MustHandle("GET", Prefix+"/stream", func(w http.ResponseWriter, r *http.Request) {
		seen, _ = authz.FromContext(r.Context())
		WriteJSON(w, 200, map[string]any{})
	})
	if w := do(s, "GET", Prefix+"/stream", "", ""); w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("anonymous = %d", w.Code)
	}
	if w := do(s, "GET", Prefix+"/stream", "bogus", ""); w.Code != 401 {
		t.Fatalf("bad token = %d", w.Code)
	}
	if w := do(s, "GET", Prefix+"/stream", "tok-notent", ""); w.Code != 401 {
		t.Fatalf("tenantless identity = %d", w.Code)
	}
	if w := do(s, "GET", Prefix+"/stream", "tok-nobody", ""); w.Code != 403 || reason(w) != "forbidden" {
		t.Fatalf("no permission = %d", w.Code)
	}
	if w := do(s, "GET", Prefix+"/stream", "tok-viewer", ""); w.Code != 200 {
		t.Fatalf("viewer = %d %s", w.Code, w.Body)
	}
	if seen.UserID != viewer || seen.TenantID != tenant || seen.ActorKind != authz.ActorUser {
		t.Fatalf("subjects in context = %+v", seen)
	}
	if s.Permission("GET", Prefix+"/stream") != authz.ClustersRead || s.Permission("GET", Prefix+"/health") != "" {
		t.Fatal("permission lookup")
	}
	// No checker installed: fail closed.
	closed := newServer(t, WithChecker(nil))
	closed.MustHandle("GET", Prefix+"/stream", func(w http.ResponseWriter, _ *http.Request) { WriteJSON(w, 200, nil) })
	if w := do(closed, "GET", Prefix+"/stream", "tok-admin", ""); w.Code != 403 {
		t.Fatalf("nil checker = %d", w.Code)
	}
	// No verifier installed: unauthenticated.
	nov, err := NewHandler(testrt.New(t, testutil.MustCA("example.org"), "teleport"))
	if err != nil {
		t.Fatal(err)
	}
	nov.MustHandle("GET", Prefix+"/stream", func(w http.ResponseWriter, _ *http.Request) { WriteJSON(w, 200, nil) })
	if w := do(nov, "GET", Prefix+"/stream", "tok-admin", ""); w.Code != 401 {
		t.Fatalf("nil verifier = %d", w.Code)
	}
}

func TestContractValidation(t *testing.T) {
	s := newServer(t)
	s.MustHandle("GET", Prefix+"/stream", func(w http.ResponseWriter, _ *http.Request) { WriteJSON(w, 200, map[string]any{}) })
	cases := []struct {
		method, path string
		want         int
	}{
		{"GET", Prefix + "/stream?last_id=" + strings.Repeat("1", 65), 422},
		{"GET", Prefix + "/stream?last_id=1-0", 200},
		{"POST", Prefix + "/stream", 405},
		{"GET", Prefix + "/nowhere", 404},
		{"GET", Prefix + "/health", 501}, // declared, not registered
	}
	for _, c := range cases {
		if w := do(s, c.method, c.path, "tok-admin", ""); w.Code != c.want {
			t.Errorf("%s %s = %d (%s), want %d", c.method, c.path, w.Code, w.Body, c.want)
		}
	}
}

func TestStreamRelaysTenantEvents(t *testing.T) {
	hub := stream.NewHub(stream.NewMemory(), stream.Config{}, nil)
	defer hub.Close()
	s := newServer(t)
	s.Register(Deps{Hub: hub})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+Prefix+"/stream", nil)
	req.Header.Set("Authorization", "Bearer tok-viewer")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream = %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = hub.PublishID(context.Background(), tenant, nil, true, "teleport.cluster.registered", map[string]string{"cluster_id": "c1"}, true)
	}()
	buf := make([]byte, 4096)
	var got strings.Builder
	for !strings.Contains(got.String(), "teleport.cluster.registered") {
		n, err := res.Body.Read(buf)
		if err != nil {
			t.Fatalf("read: %v (%q)", err, got.String())
		}
		got.Write(buf[:n])
	}
}

func TestRouteBookkeeping(t *testing.T) {
	s := newServer(t)
	if err := s.HandleFunc("GET", Prefix+"/undeclared", func(http.ResponseWriter, *http.Request) {}); err == nil {
		t.Fatal("undeclared route accepted")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("MustHandle on undeclared route must panic")
			}
		}()
		s.MustHandle("GET", "/nope", func(http.ResponseWriter, *http.Request) {})
	}()
	before := len(s.Missing())
	s.Register(Deps{})
	if len(s.Implemented()) != 1 || len(s.Missing()) != before-1 || len(s.Declared()) != before {
		t.Fatalf("implemented=%d missing=%d declared=%d", len(s.Implemented()), len(s.Missing()), len(s.Declared()))
	}
	if s.Document() == nil || s.Edge() != nil {
		t.Fatal("accessors")
	}
}

func TestRemoteServing(t *testing.T) {
	dist := fstest.MapFS{
		"mf-manifest.json":  {Data: []byte(`{}`)},
		"assets/app-abc.js": {Data: []byte(`console.log(1)`)},
		"remoteEntry.js":    {Data: []byte(`export {}`)},
	}
	s := newServer(t, WithRemote(dist))
	w := do(s, "GET", "/ui/assets/app-abc.js", "", "")
	if w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset = %d %q", w.Code, w.Header().Get("Cache-Control"))
	}
	if w := do(s, "GET", "/ui/mf-manifest.json", "", ""); w.Code != 200 || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("manifest = %d %q", w.Code, w.Header().Get("Cache-Control"))
	}
	for _, p := range []string{"/ui/", "/ui/assets/", "/ui/missing.js"} {
		if w := do(s, "GET", p, "", ""); w.Code != 404 {
			t.Errorf("%s = %d", p, w.Code)
		}
	}
}

func TestSubjectsCarryVerifiedIdentityOnly(t *testing.T) {
	if _, err := Subjects(httptest.NewRequest("GET", "/", nil)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("subjects without identity")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(authclient.WithIdentity(r.Context(), authclient.Identity{UserID: admin, TenantID: tenant, Roles: []string{"owner"}}))
	s, err := Subjects(r)
	if err != nil || s.ActorKind != authz.ActorUser || !s.HasRole("owner") || s.TenantID != tenant {
		t.Fatalf("subjects = %+v %v", s, err)
	}
	if c, err := Caller(r); err != nil || c.UserID != admin || RequestID(r) != "" {
		t.Fatal("caller")
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		err    error
		status int
		reason string
	}{
		{ErrTeleportRejected, 422, "teleport_rejected"},
		{fmt.Errorf("wrap: %w", ErrConflict), 409, "conflict"},
		{&http.MaxBytesError{Limit: 1}, 413, "body_too_large"},
		{authz.ErrForbidden, 403, "forbidden"},
		{authz.ErrUnauthenticated, 401, "unauthenticated"},
		{repo.ErrNotFound, 404, "not_found"},
		{repo.ErrConflict, 409, "conflict"},
		{secrets.ErrUnavailable, 503, "dependency_unavailable"},
		{secrets.ErrWriteUnsupported, 503, "dependency_unavailable"},
		{teleportapi.MapError(errors.New("x")), 422, "teleport_rejected"},
		{teleportapi.ErrUnreachable, 502, "cluster_unreachable"},
		{teleportapi.ErrCredentialInvalid, 422, "credential_invalid"},
		{teleportapi.ErrBlockedTarget, 422, "blocked_target"},
		{teleportapi.ErrNotFound, 404, "not_found"},
		{teleportapi.ErrConflict, 409, "conflict"},
		{errors.New("db exploded"), 503, "temporarily_unavailable"},
	}
	for _, c := range cases {
		st, r := Status(c.err)
		if st != c.status || r != c.reason {
			t.Errorf("%v => %d %s", c.err, st, r)
		}
	}
	for _, e := range []*Error{ErrUnsupportedVersion, ErrEnterpriseOnly, ErrDependency, ErrClusterUnreachable, ErrCredentialInvalid,
		ErrBlockedTarget, ErrRateLimited, ErrBadRequest, ErrNotImplemented, ErrValidation, ErrMalformed} {
		if st, r := Status(e); st != e.Status || r != e.Reason || r == "" {
			t.Errorf("%s mapping", e.Reason)
		}
	}
	w := httptest.NewRecorder()
	Fail(w, httptest.NewRequest("GET", "/x", nil), nil, errors.New("TELEPORT-MARKER-SECRET"))
	if strings.Contains(w.Body.String(), "TELEPORT-MARKER") || w.Code != 503 {
		t.Fatalf("fail leaked: %s", w.Body)
	}
	w = httptest.NewRecorder()
	WriteDetail(w, ErrValidation, map[string]any{"param": "page_size"})
	if !strings.Contains(w.Body.String(), `"param":"page_size"`) || w.Code != 422 {
		t.Fatal("detail")
	}
	if ErrConflict.Error() != "conflict" {
		t.Fatal("error string")
	}
}

func TestDecodeJSON(t *testing.T) {
	var v struct{ A int }
	req := func(b string) *http.Request { return httptest.NewRequest("POST", "/", strings.NewReader(b)) }
	if err := DecodeJSON(req(`{"A":1}`), &v, 0); err != nil || v.A != 1 {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"B":1}`, `{"A":1} {}`, `nope`} {
		if err := DecodeJSON(req(bad), &v, 0); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if err := DecodeJSON(req(`{"A":1111111}`), &v, 4); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("limit: %v", err)
	}
}
