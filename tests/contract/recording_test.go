package contract

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra/v4/freyatest/testrt"
	"github.com/go-tangra/go-tangra/v4/freyatest/testutil"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/recording"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/gravitational/trace"
)

// recordingRoutes is the spec 003 route (plan.md Contract).
var recordingRoutes = map[string]string{
	"GET /api/teleport/v1/clusters/{id}/sessions/{sid}/recording": authz.SessionsPlay,
}

func recordingRouteList() []string {
	out := make([]string, 0, len(recordingRoutes))
	for r := range recordingRoutes {
		out = append(out, r)
	}
	return out
}

const (
	recSID    = "8f0b3c3e-1d2a-4c5b-9e7f-0a1b2c3d4e5f"
	player2   = "99999999-9999-7999-8999-999999999999"
	otherTnt  = "33333333-3333-7333-8333-333333333333"
	unknownID = "018f3a2b-0000-7000-8000-0000000000ff"
)

func recordingServer(t *testing.T, svc func(*recording.Service)) (*httpapi.Server, *ct.Env, string) {
	t.Helper()
	e := ct.New(t, nil)
	e.Perms[player2] = authz.Permissions
	e.Perms[otherTnt] = authz.Permissions
	c := e.Register(t, ct.TenantA, "prod")
	e.Teleport.Recordings = map[string][]teleportapi.RecordingEvent{
		recSID: {{Type: teleportapi.RecordingStart, Size: "80:24"}, {Type: teleportapi.RecordingPrint, Ms: 10, Data: []byte("hello\r\n")},
			{Type: teleportapi.RecordingResize, Size: "120:40"}, {Type: teleportapi.RecordingPrint, Ms: 900, Data: []byte{0xff, 0x1b, '['}},
			{Type: teleportapi.RecordingEnd}},
		"kube-1": {{Type: teleportapi.RecordingStart, Kube: true}},
	}
	rt := testrt.New(t, testutil.MustCA("example.org"), "teleport")
	v := tokens{"admin": {UserID: ct.Admin, TenantID: ct.TenantA}, "auditor": {UserID: ct.Auditor, TenantID: ct.TenantA},
		"player2": {UserID: player2, TenantID: ct.TenantA}, "outsider": {UserID: otherTnt, TenantID: ct.TenantB}}
	s, err := httpapi.NewHandler(rt, httpapi.WithVerifier(v), httpapi.WithChecker(e.Perms))
	if err != nil {
		t.Fatal(err)
	}
	r := &recording.Service{Clusters: e.Service, Audit: e.Audit, Signer: recording.NewSigner(), Limiter: recording.NewLimiter(0, 0)}
	if svc != nil {
		svc(r)
	}
	s.Register(httpapi.Deps{Clusters: e.Service, Recording: r})
	return s, e, c.ID
}

func TestRecordingRouteDeclaresItsPermission(t *testing.T) {
	s, _, _ := recordingServer(t, nil)
	implemented := map[string]bool{}
	for _, r := range s.Implemented() {
		implemented[r.String()] = true
	}
	for route, perm := range recordingRoutes {
		method, path, _ := strings.Cut(route, " ")
		if got := s.Permission(method, path); got != perm {
			t.Errorf("%s: permission %q, want %q", route, got, perm)
		}
		if !implemented[route] {
			t.Errorf("%s has no handler", route)
		}
	}
	doc := load(t)
	op := doc.Paths.Find("/api/teleport/v1/clusters/{id}/sessions/{sid}/recording").Get
	if op.Extensions["x-freya-timeout-seconds"] != float64(60) {
		t.Fatalf("timeout %v", op.Extensions["x-freya-timeout-seconds"])
	}
}

type recPage struct {
	Width, Height int
	Events        [][3]any
	Next          string
	Done          bool
	Bytes         int64
}

func reasonOf(t *testing.T, body []byte) string {
	t.Helper()
	var m struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(body, &m)
	return m.Reason
}

// Plan Contract: every status of the route, response shapes, and exactly
// one audit row per playback (FR-011, SC-004).
func TestRecordingResponsesMatchSchemas(t *testing.T) {
	doc := load(t)
	s, e, id := recordingServer(t, func(r *recording.Service) { r.PageEvents = 2 })
	base := "/api/teleport/v1/clusters/" + id + "/sessions/"
	get := func(token, path string, status int, reason string) []byte {
		t.Helper()
		r, rec := call(s, "GET", path, token, nil)
		if rec.Code != status {
			t.Fatalf("GET %s as %s: %d %s", path, token, rec.Code, rec.Body)
		}
		if reason != "" && reasonOf(t, rec.Body.Bytes()) != reason {
			t.Fatalf("GET %s: reason %s, want %s", path, rec.Body, reason)
		}
		ValidateResponse(t, doc, r, rec)
		return rec.Body.Bytes()
	}

	// A full playback in pages.
	var pages []recPage
	path := base + recSID + "/recording"
	for range 10 {
		var p recPage
		if err := json.Unmarshal(get("admin", path, 200, ""), &p); err != nil {
			t.Fatal(err)
		}
		pages = append(pages, p)
		if p.Done {
			break
		}
		path = base + recSID + "/recording?cursor=" + url.QueryEscape(p.Next)
	}
	if len(pages) != 2 || pages[0].Width != 80 || pages[0].Height != 24 || !pages[1].Done || pages[1].Next != "" {
		t.Fatalf("pages %+v", pages)
	}
	if ev := pages[0].Events; ev[0][1] != "o" || ev[0][2] != "aGVsbG8NCg==" || ev[1][1] != "r" || ev[1][2] != "120x40" {
		t.Fatalf("events %v", ev)
	}
	if rows := e.AuditRows(); strings.Count(strings.Join(rows, ","), "teleport.session.played:success") != 1 {
		t.Fatalf("audit %v", rows)
	}
	first := pages[0].Next

	_, rec := call(s, "GET", base+recSID+"/recording", "admin", nil)
	var p0 recPage
	_ = json.Unmarshal(rec.Body.Bytes(), &p0)
	cursor := "?cursor=" + url.QueryEscape(p0.Next)

	get("auditor", base+recSID+"/recording", 403, "forbidden")  // audit:read only
	get("outsider", base+recSID+"/recording", 404, "not_found") // cluster of another tenant
	get("admin", "/api/teleport/v1/clusters/"+unknownID+"/sessions/"+recSID+"/recording", 404, "not_found")
	get("admin", base+"missing-1/recording", 404, "recording_not_found")
	get("admin", base+"kube-1/recording", 422, "not_playable")
	get("admin", base+"bad%20sid/recording", 422, "validation_failed")
	get("admin", base+recSID+"/recording?cursor=junk", 422, "validation_failed")
	get("admin", base+recSID+"/recording?cursor="+strings.Repeat("a", 1025), 422, "validation_failed")
	get("player2", base+recSID+"/recording"+cursor, 410, "playback_expired") // another user's cursor
	get("admin", base+"kube-1/recording"+cursor, 410, "playback_expired")    // another session
	get("admin", base+recSID+"/recording?cursor="+url.QueryEscape(first), 200, "")

	e.Teleport.FailNext("StreamRecording", trace.AccessDenied("access denied to session"))
	body := get("admin", base+recSID+"/recording", 409, "recording_access_denied")
	if !strings.Contains(string(body), "session") || !strings.Contains(string(body), "role") {
		t.Fatalf("the refusal names the role fix: %s", body)
	}
	e.Teleport.FailNext("StreamRecording", trace.ConnectionProblem(nil, "down"))
	get("admin", base+recSID+"/recording", 502, "cluster_unreachable")

	// Every refusal after the forbidden/not-found gates is audited as a
	// failed start; later pages never are.
	rows := strings.Join(e.AuditRows(), ",")
	if n := strings.Count(rows, "teleport.session.played:success"); n != 2 {
		t.Fatalf("%d successful starts in %s", n, rows)
	}
}

func TestRecordingLimits(t *testing.T) {
	doc := load(t)
	var svc *recording.Service
	s, e, id := recordingServer(t, func(r *recording.Service) { r.MaxBytes = 4; svc = r })
	path := "/api/teleport/v1/clusters/" + id + "/sessions/" + recSID + "/recording"
	r, rec := call(s, "GET", path, "admin", nil)
	if rec.Code != 413 || reasonOf(t, rec.Body.Bytes()) != "recording_too_large" || !strings.Contains(rec.Body.String(), `"max_bytes":4`) {
		t.Fatalf("too large: %d %s", rec.Code, rec.Body)
	}
	ValidateResponse(t, doc, r, rec)

	svc.MaxBytes = 0
	rel1, _ := svc.Limiter.Acquire(ct.TenantA + "/" + ct.Admin)
	rel2, _ := svc.Limiter.Acquire(ct.TenantA + "/" + ct.Admin)
	r, rec = call(s, "GET", path, "admin", nil)
	if rec.Code != 429 || reasonOf(t, rec.Body.Bytes()) != "rate_limited" || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("busy: %d %s %v", rec.Code, rec.Body, rec.Header())
	}
	ValidateResponse(t, doc, r, rec)
	rel1()
	rel2()
	if _, rec = call(s, "GET", path, "admin", nil); rec.Code != 200 {
		t.Fatalf("after release: %d", rec.Code)
	}
	if e.Teleport.Calls("StreamRecording") != 2 {
		t.Fatalf("%d reads: refusals read nothing", e.Teleport.Calls("StreamRecording"))
	}
}
