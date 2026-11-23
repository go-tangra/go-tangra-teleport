package recording_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/trace"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/recording"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

const (
	sid    = "8f0b3c3e-1d2a-4c5b-9e7f-0a1b2c3d4e5f"
	other  = "99999999-9999-7999-8999-999999999999" // a second player
	secret = "SENTINEL-printed-secret-7f3a"
)

var t0 = time.Unix(1700000000, 0).UTC()

func ssh(outputs ...string) []teleportapi.RecordingEvent {
	evs := []teleportapi.RecordingEvent{{Type: teleportapi.RecordingStart, Time: t0, Size: "100:30"}}
	for i, o := range outputs {
		evs = append(evs, teleportapi.RecordingEvent{Type: teleportapi.RecordingPrint, Ms: int64(i+1) * 1000, Data: []byte(o)})
	}
	return append(evs, teleportapi.RecordingEvent{Type: teleportapi.RecordingEnd})
}

type env struct {
	*ct.Env
	svc     *recording.Service
	cluster string
	logs    *bytes.Buffer
}

func setup(t *testing.T) env {
	t.Helper()
	logs := &bytes.Buffer{}
	e := ct.New(t, slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e.Perms[other] = authz.Permissions
	c := e.Register(t, ct.TenantA, "prod")
	e.Teleport.Recordings = map[string][]teleportapi.RecordingEvent{sid: ssh("ls\r\n", secret+"\r\n", "\x1b[31mexit\xff")}
	svc := &recording.Service{Clusters: e.Service, Audit: e.Audit, Signer: recording.NewSigner(), Limiter: recording.NewLimiter(0, 0)}
	return env{Env: e, svc: svc, cluster: c.ID, logs: logs}
}

// playAll fetches every page as user and returns them.
func playAll(t *testing.T, s *recording.Service, ctx context.Context, cluster string) []recording.Page {
	t.Helper()
	var pages []recording.Page
	cursor := ""
	for range 100 {
		p, err := s.Page(ctx, cluster, sid, cursor)
		if err != nil {
			t.Fatalf("page %d: %v", len(pages), err)
		}
		pages = append(pages, p)
		if p.Done {
			if p.Next != "" {
				t.Fatal("next on the last page")
			}
			return pages
		}
		if p.Next == "" {
			t.Fatal("no next before done")
		}
		cursor = p.Next
	}
	t.Fatal("never done")
	return nil
}

func output(t *testing.T, pages []recording.Page) string {
	t.Helper()
	var b strings.Builder
	for _, p := range pages {
		for _, e := range p.Events {
			if e.Kind == recording.KindOutput {
				raw, err := base64.StdEncoding.DecodeString(e.Data)
				if err != nil {
					t.Fatal(err)
				}
				b.Write(raw)
			}
		}
	}
	return b.String()
}

func played(e env) []repo.AuditRow {
	e.Audit.Flush(context.Background())
	var out []repo.AuditRow
	for _, r := range e.Repo.Audit() {
		if r.Action == "teleport.session.played" {
			out = append(out, r)
		}
	}
	return out
}

func TestPlaybackPagesAndOneAuditRow(t *testing.T) {
	e := setup(t)
	e.svc.PageEvents = 1
	pages := playAll(t, e.svc, ct.As(ct.TenantA, ct.Admin), e.cluster)
	if len(pages) < 3 || pages[0].Width != 100 || pages[0].Height != 30 || pages[1].Width != 0 {
		t.Fatalf("pages %+v", pages)
	}
	if got := output(t, pages); got != "ls\r\n"+secret+"\r\n\x1b[31mexit\xff" {
		t.Fatalf("output %q", got)
	}
	last := pages[len(pages)-1]
	if last.Bytes != int64(len(output(t, pages))) {
		t.Fatalf("bytes %d", last.Bytes)
	}
	rows := played(e)
	if len(rows) != 1 {
		t.Fatalf("%d session.played rows", len(rows))
	}
	r := rows[0]
	if r.Outcome != "success" || r.TenantID != ct.TenantA || r.ActorID != ct.Admin || r.ClusterID != e.cluster ||
		r.TargetKind != "session" || r.TargetName != sid || r.Detail["session_id"] != sid {
		t.Fatalf("audit row %+v", r)
	}
	// A second playback is a second row.
	playAll(t, e.svc, ct.As(ct.TenantA, ct.Admin), e.cluster)
	if n := len(played(e)); n != 2 {
		t.Fatalf("%d rows after two playbacks", n)
	}
	if e.svc.Limiter.Active() != 0 {
		t.Fatal("slot leaked")
	}
}

func TestPlaybackRefusals(t *testing.T) {
	e := setup(t)
	admin := ct.As(ct.TenantA, ct.Admin)
	var fe *clusters.FieldError

	// No sessions:play (an auditor can list sessions but not play them).
	if _, err := e.svc.Page(ct.As(ct.TenantA, ct.Auditor), e.cluster, sid, ""); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("auditor: %v", err)
	}
	// A cluster of another tenant is not found.
	if _, err := e.svc.Page(ct.As(ct.TenantB, ct.Admin), e.cluster, sid, ""); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("other tenant: %v", err)
	}
	if e.Teleport.Calls("StreamRecording") != 0 || len(played(e)) != 0 {
		t.Fatal("refused before reading")
	}
	for _, bad := range []string{"", "../x", "a b", strings.Repeat("a", 65), "-lead"} {
		if _, err := e.svc.Page(admin, e.cluster, bad, ""); !errors.As(err, &fe) || fe.Field != "sid" {
			t.Errorf("sid %q: %v", bad, err)
		}
	}
	if _, err := e.svc.Page(admin, e.cluster, sid, "garbage"); !errors.As(err, &fe) || fe.Field != "cursor" {
		t.Fatalf("garbage cursor: %v", err)
	}

	// A cursor only opens for the same user and session.
	e.svc.PageEvents = 1
	p, err := e.svc.Page(admin, e.cluster, sid, "")
	if err != nil || p.Next == "" {
		t.Fatalf("first page: %v", err)
	}
	if _, err := e.svc.Page(ct.As(ct.TenantA, other), e.cluster, sid, p.Next); !errors.Is(err, recording.ErrExpired) {
		t.Fatalf("other user: %v", err)
	}
	e.Teleport.Recordings["other-session"] = ssh("x")
	if _, err := e.svc.Page(admin, e.cluster, "other-session", p.Next); !errors.Is(err, recording.ErrExpired) {
		t.Fatalf("other session: %v", err)
	}
	// Another module instance (another key).
	again := *e.svc
	again.Signer = recording.NewSigner()
	if _, err := again.Page(admin, e.cluster, sid, p.Next); !errors.Is(err, recording.ErrExpired) {
		t.Fatalf("other instance: %v", err)
	}
	if n := len(played(e)); n != 1 {
		t.Fatalf("%d rows: only the first page is audited", n)
	}
}

func TestPlaybackTeleportErrors(t *testing.T) {
	e := setup(t)
	admin := ct.As(ct.TenantA, ct.Admin)
	e.Teleport.Recordings["kube-1"] = []teleportapi.RecordingEvent{{Type: teleportapi.RecordingStart, Kube: true}}
	e.Teleport.Recordings["desk-1"] = []teleportapi.RecordingEvent{{Type: "windows.desktop.session.start"}}
	e.Teleport.Recordings["empty-1"] = nil
	cases := []struct {
		sid    string
		inject error
		want   error
		reason string
	}{
		{"missing-1", nil, recording.ErrNotFound, "recording_not_found"},
		{"empty-1", nil, recording.ErrNotFound, "recording_not_found"},
		{sid, trace.AccessDenied("access denied to session"), recording.ErrAccessDenied, "recording_access_denied"},
		{"kube-1", nil, recording.ErrNotPlayable, "not_playable"},
		{"desk-1", nil, recording.ErrNotPlayable, "not_playable"},
		{sid, trace.ConnectionProblem(nil, "down"), teleportapi.ErrUnreachable, "cluster_unreachable"},
	}
	for _, c := range cases {
		if c.inject != nil {
			e.Teleport.FailNext("StreamRecording", c.inject)
		}
		if _, err := e.svc.Page(admin, e.cluster, c.sid, ""); !errors.Is(err, c.want) {
			t.Errorf("%s %v: %v", c.sid, c.inject, err)
		}
	}
	rows := played(e)
	if len(rows) != len(cases) {
		t.Fatalf("%d rows for %d refused starts", len(rows), len(cases))
	}
	for i, r := range rows {
		if r.Outcome != "failure" || r.Reason != cases[i].reason {
			t.Errorf("row %d: %s %s, want failure %s", i, r.Outcome, r.Reason, cases[i].reason)
		}
	}

	// A cut on a later page keeps the cursor usable: retry after the outage.
	e.svc.PageEvents = 1
	p, err := e.svc.Page(admin, e.cluster, sid, "")
	if err != nil {
		t.Fatal(err)
	}
	e.Teleport.FailNext("StreamRecording", trace.ConnectionProblem(nil, "down"))
	if _, err := e.svc.Page(admin, e.cluster, sid, p.Next); !errors.Is(err, teleportapi.ErrUnreachable) {
		t.Fatalf("cut: %v", err)
	}
	if _, err := e.svc.Page(admin, e.cluster, sid, p.Next); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

func TestPlaybackLimits(t *testing.T) {
	e := setup(t)
	admin := ct.As(ct.TenantA, ct.Admin)
	// Over the size limit, on a later page too.
	e.svc.MaxBytes = 10
	e.svc.PageEvents = 1
	p, err := e.svc.Page(admin, e.cluster, sid, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Page(admin, e.cluster, sid, p.Next); !errors.Is(err, recording.ErrTooLarge) {
		t.Fatalf("too large: %v", err)
	}
	e.svc.MaxBytes = 0
	// Concurrency: the user's two slots are taken.
	r1, _ := e.svc.Limiter.Acquire(ct.TenantA + "/" + ct.Admin)
	r2, _ := e.svc.Limiter.Acquire(ct.TenantA + "/" + ct.Admin)
	if _, err := e.svc.Page(admin, e.cluster, sid, ""); !errors.Is(err, recording.ErrBusy) {
		t.Fatalf("busy: %v", err)
	}
	if _, err := e.svc.Page(ct.As(ct.TenantA, other), e.cluster, sid, ""); err != nil {
		t.Fatalf("another user: %v", err)
	}
	r1()
	r2()
	if _, err := e.svc.Page(admin, e.cluster, sid, ""); err != nil {
		t.Fatalf("after release: %v", err)
	}
	busy := 0
	for _, r := range played(e) {
		if r.Reason == "rate_limited" && r.Outcome == "failure" && r.ActorID == ct.Admin {
			busy++
		}
	}
	if busy != 1 {
		t.Fatalf("%d rate_limited rows", busy)
	}
}

// SC-005 / FR-013 / FR-014: the recording reaches the caller and nothing
// else — not the logs, the audit trail, the published events or the store.
func TestRecordingContentNeverLeaks(t *testing.T) {
	e := setup(t)
	e.svc.PageEvents = 1
	pages := playAll(t, e.svc, ct.As(ct.TenantA, ct.Admin), e.cluster)
	if !strings.Contains(output(t, pages), secret) {
		t.Fatal("the caller did not get the output")
	}
	// Refusals and failures too.
	e.Teleport.FailNext("StreamRecording", trace.ConnectionProblem(nil, "down: "+secret))
	_, _ = e.svc.Page(ct.As(ct.TenantA, ct.Admin), e.cluster, sid, "")
	e.svc.MaxBytes = 5
	_, _ = e.svc.Page(ct.As(ct.TenantA, ct.Admin), e.cluster, sid, "")

	e.Audit.Flush(context.Background())
	audit, _ := json.Marshal(e.Repo.Audit())
	events, _ := json.Marshal(e.Events.All())
	snapshots := fmt.Sprintf("%+v", e.Repo)
	for name, sink := range map[string]string{"logs": e.logs.String(), "audit": string(audit), "events": string(events), "store": snapshots} {
		for _, needle := range []string{secret, base64.StdEncoding.EncodeToString([]byte(secret + "\r\n")), "exit"} {
			if strings.Contains(sink, needle) {
				t.Errorf("%s contains recording content %q", name, needle)
			}
		}
	}
}
