// Package security holds the negative security tests of the Teleport module
// (constitution Principle IV): tenant isolation, permission refusals, the
// SSRF guard and credential redaction across every output channel.
package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"
	"github.com/gravitational/trace"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/alerts"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/auditlog"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/locks"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/provisioning"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/resources"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/roles"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi/identitytest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/tokens"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/users"
)

type verifier map[string]authclient.Identity

func (v verifier) Verify(_ context.Context, token string) (authclient.Identity, error) {
	if id, ok := v[token]; ok {
		return id, nil
	}
	return authclient.Identity{}, httpapi.ErrUnauthenticated
}

// syncBuffer is a log sink safe for concurrent writers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fixture is the US1 harness behind the HTTP surface, with every output
// channel captured: responses, the slog handler (service and HTTP layer),
// published events, audit rows and notifications.
type fixture struct {
	*ct.Env
	auth      *provisioning.FakeMembership
	deps      httpapi.Deps
	srv       *httpapi.Server
	logs      *syncBuffer
	responses []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	logs := &syncBuffer{}
	h := slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})
	e := ct.New(t, h)
	rt := testrt.New(t, testutil.MustCA("example.org"), "teleport")
	v := verifier{
		"admin-a":    {UserID: ct.Admin, TenantID: ct.TenantA},
		"viewer-a":   {UserID: ct.Viewer, TenantID: ct.TenantA},
		"operator-a": {UserID: ct.Operator, TenantID: ct.TenantA},
		"auditor-a":  {UserID: ct.Auditor, TenantID: ct.TenantA},
		"admin-b":    {UserID: ct.Admin, TenantID: ct.TenantB},
	}
	auth := provisioning.NewFakeMembership()
	s, err := httpapi.NewHandler(rt, httpapi.WithVerifier(v), httpapi.WithChecker(e.Perms), httpapi.WithLogger(slog.New(h)))
	if err != nil {
		t.Fatal(err)
	}
	deps := httpapi.Deps{Clusters: e.Service,
		Users:  &users.Service{Clusters: e.Service, Audit: e.Audit, Events: e.Events},
		Roles:  &roles.Service{Clusters: e.Service, Audit: e.Audit, Events: e.Events},
		Locks:  &locks.Service{Clusters: e.Service, Audit: e.Audit, Events: e.Events},
		Tokens: &tokens.Service{Clusters: e.Service, Repo: e.Repo, Audit: e.Audit, Events: e.Events, Now: e.Now},
		Resources: &resources.Service{Clusters: e.Service, Repo: e.Repo, Audit: e.Audit, Events: e.Events, Now: e.Now,
			Linker: &resources.Linker{Repo: e.Repo, Directory: resources.UnavailableDirectory{}, Events: e.Events, Now: e.Now}},
		Audit:  &auditlog.Service{Clusters: e.Service},
		Alerts: &alerts.Rules{Repo: e.Repo, Authz: e.Service.Authz, Audit: e.Audit, Now: e.Now},
		Provisioning: &provisioning.Service{Clusters: e.Service, Repo: e.Repo, Membership: auth, Notify: e.Notify, Audit: e.Audit,
			Events: e.Events, Log: slog.New(h), Now: e.Now,
			Users: &users.Service{Clusters: e.Service, Audit: e.Audit, Events: e.Events},
			Locks: &locks.Service{Clusters: e.Service, Audit: e.Audit, Events: e.Events, Now: e.Now}}}
	s.Register(deps)
	return &fixture{Env: e, auth: auth, deps: deps, srv: s, logs: logs}
}

func (f *fixture) do(t *testing.T, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, "https://localhost/api/teleport/v1"+path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, "https://localhost/api/teleport/v1"+path, nil)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	if method != http.MethodGet {
		r.Header.Set("X-CSRF-Token", "csrf")
	}
	w := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(w, r)
	f.responses = append(f.responses, w.Body.String())
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m
}

func (f *fixture) register(t *testing.T, token, name, addr, cred string) (int, map[string]any) {
	return f.do(t, "POST", "/clusters", token, map[string]any{"display_name": name, "proxy_addr": addr, "credential": cred})
}

// Another tenant's cluster answers 404 on every route; nothing about it leaks.
func TestCrossTenantClusterIsNotFound(t *testing.T) {
	f := newFixture(t)
	code, theirs := f.register(t, "admin-b", "theirs", ct.ProxyAddr, f.Identity(t, 30*24*time.Hour))
	if code != http.StatusCreated {
		t.Fatalf("register in B: %d", code)
	}
	id := theirs["id"].(string)
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/clusters/" + id, nil},
		{"PATCH", "/clusters/" + id, map[string]any{"display_name": "mine"}},
		{"POST", "/clusters/" + id + "/check", nil},
		{"POST", "/clusters/" + id + "/credential", map[string]any{"credential": f.Identity(t, 30*24*time.Hour)}},
		{"DELETE", "/clusters/" + id, nil},
	} {
		code, m := f.do(t, c.method, c.path, "admin-a", c.body)
		if code != http.StatusNotFound || m["reason"] != "not_found" {
			t.Errorf("%s %s from tenant A: %d %v", c.method, c.path, code, m)
		}
	}
	if code, m := f.do(t, "GET", "/clusters", "admin-a", nil); code != 200 || m["total"].(float64) != 0 {
		t.Fatalf("tenant A lists B's cluster: %v", m)
	}
	if c, err := f.Repo.GetCluster(context.Background(), ct.TenantB, id); err != nil || c.DisplayName != "theirs" {
		t.Fatalf("B's cluster changed: %v %+v", err, c)
	}
}

// A viewer reads but every write is forbidden.
func TestViewerCannotWrite(t *testing.T) {
	f := newFixture(t)
	_, mine := f.register(t, "admin-a", "prod", ct.ProxyAddr, f.Identity(t, 30*24*time.Hour))
	id := mine["id"].(string)
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/clusters", map[string]any{"display_name": "x", "proxy_addr": ct.ProxyAddr, "credential": f.Identity(t, time.Hour)}},
		{"PATCH", "/clusters/" + id, map[string]any{"display_name": "renamed"}},
		{"POST", "/clusters/" + id + "/credential", map[string]any{"credential": f.Identity(t, time.Hour)}},
		{"DELETE", "/clusters/" + id, nil},
	} {
		if code, m := f.do(t, c.method, c.path, "viewer-a", c.body); code != http.StatusForbidden || m["reason"] != "forbidden" {
			t.Errorf("viewer %s %s: %d %v", c.method, c.path, code, m)
		}
	}
	for _, c := range []struct{ method, path string }{{"GET", "/clusters"}, {"GET", "/clusters/" + id}, {"POST", "/clusters/" + id + "/check"}} {
		if code, _ := f.do(t, c.method, c.path, "viewer-a", nil); code != http.StatusOK {
			t.Errorf("viewer %s %s: %d", c.method, c.path, code)
		}
	}
	if got, _ := f.Repo.ListClusters(context.Background(), ct.TenantA); len(got) != 1 || got[0].DisplayName != "prod" {
		t.Fatalf("viewer changed clusters: %+v", got)
	}
}

// Metadata, loopback and names resolving to them are refused before any
// connection, and nothing is stored.
func TestBlockedTargets(t *testing.T) {
	f := newFixture(t)
	cred := f.Identity(t, 30*24*time.Hour)
	for _, addr := range []string{"169.254.169.254", "169.254.169.254:443", "127.0.0.1", "127.0.0.1:3080", "[::1]:443", "metadata.example.com", "10.0.0.5:443"} {
		if code, m := f.register(t, "admin-a", "x", addr, cred); code != http.StatusUnprocessableEntity || m["reason"] != "blocked_target" {
			t.Errorf("%s: %d %v", addr, code, m)
		}
	}
	if got, _ := f.Repo.ListClusters(context.Background(), ct.TenantA); len(got) != 0 || f.Secrets.Len() != 0 || f.Dials() != 0 {
		t.Fatalf("stored %d, secrets %d, dials %d", len(got), f.Secrets.Len(), f.Dials())
	}
}

// No identity material appears in any response, log line, event, audit row
// or notification across the whole cluster lifecycle, including failures.
func TestNoCredentialMaterialInAnyOutput(t *testing.T) {
	f := newFixture(t)
	var idents []string
	ident := func(lifetime time.Duration) string {
		s := f.Identity(t, lifetime)
		idents = append(idents, s)
		return s
	}
	if err := f.Repo.CreateAlertRule(context.Background(), repo.AlertRule{ID: "018f3a2b-0000-7000-8000-0000000000b1", TenantID: ct.TenantA,
		Name: "outage", ConditionKind: repo.ConditionClusterUnreachable, Recipients: repo.Recipients{UserIDs: []string{"ops"}}, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	// Failures first: unreachable (a logged 5xx), rejected, malformed, blocked, store down.
	f.Teleport.FailNext("Ping", trace.ConnectionProblem(errors.New("dial"), "connection refused"))
	f.register(t, "admin-a", "prod", ct.ProxyAddr, ident(30*24*time.Hour))
	truncated := ident(30 * 24 * time.Hour)
	if code, _ := f.register(t, "admin-a", "prod", ct.ProxyAddr, truncated[:len(truncated)/2]); code != http.StatusUnprocessableEntity {
		t.Fatalf("truncated identity: %d", code)
	}
	f.register(t, "admin-a", "prod", "169.254.169.254", ident(30*24*time.Hour))
	f.Secrets.SetErr(secrets.ErrWriteUnsupported)
	f.register(t, "admin-a", "prod", ct.ProxyAddr, ident(30*24*time.Hour))
	f.Secrets.SetErr(nil)

	// The lifecycle.
	code, c := f.register(t, "admin-a", "prod", ct.ProxyAddr, ident(30*24*time.Hour))
	if code != http.StatusCreated {
		t.Fatalf("register: %d %v", code, c)
	}
	id := c["id"].(string)
	f.do(t, "GET", "/clusters", "viewer-a", nil)
	f.do(t, "GET", "/clusters/"+id, "viewer-a", nil)
	f.do(t, "POST", "/clusters/"+id+"/credential", "admin-a", map[string]any{"credential": ident(60 * 24 * time.Hour)})
	short := ident(time.Hour)
	f.do(t, "POST", "/clusters/"+id+"/credential", "admin-a", map[string]any{"credential": short[:len(short)-80]})
	f.Teleport.SetErr(trace.ConnectionProblem(errors.New("dial"), "connection refused"))
	for range 3 {
		f.do(t, "POST", "/clusters/"+id+"/check", "viewer-a", nil)
	}
	f.Teleport.SetErr(nil)
	f.Advance(55 * 24 * time.Hour) // inside the expiry threshold of the rotated identity
	f.do(t, "POST", "/clusters/"+id+"/check", "viewer-a", nil)
	f.do(t, "DELETE", "/clusters/"+id, "admin-a", nil)

	if len(f.Events.All()) == 0 || len(f.Notify.Sent()) == 0 || f.logs.String() == "" {
		t.Fatalf("a channel stayed silent: events %d notifications %d logs %d", len(f.Events.All()), len(f.Notify.Sent()), len(f.logs.String()))
	}
	channels := map[string]string{"responses": strings.Join(f.responses, "\n"), "logs": f.logs.String()}
	b, _ := json.Marshal(f.Events.All())
	channels["events"] = string(b)
	f.Audit.Flush(context.Background())
	b, _ = json.Marshal(f.Repo.Audit())
	channels["audit"] = string(b)
	b, _ = json.Marshal(f.Notify.Sent())
	channels["notifications"] = string(b)
	for name, out := range channels {
		for _, raw := range idents {
			for _, frag := range identitytest.Fragments(raw) {
				if strings.Contains(out, frag) {
					t.Errorf("%s carry identity material %q", name, frag)
				}
			}
		}
		for _, bad := range []string{"warden:", "credential_ref", "[REDACTED]"} {
			if strings.Contains(out, bad) && name != "logs" {
				t.Errorf("%s carry %q", name, bad)
			}
		}
	}
}
