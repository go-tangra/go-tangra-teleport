package audit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

const tn = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

type memStore struct {
	mu   sync.Mutex
	rows []repo.AuditRow
	err  error
}

func (m *memStore) AppendAudit(_ context.Context, r repo.AuditRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.rows = append(m.rows, r)
	return nil
}

func (m *memStore) all() []repo.AuditRow {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]repo.AuditRow(nil), m.rows...)
}

func ok(a Action) Event {
	return Event{TenantID: tn, Action: a, ActorKind: ActorUser, ActorID: "u1", TargetKind: TargetCluster, TargetName: "prod", Outcome: OutcomeSuccess}
}

func TestVocabulary(t *testing.T) {
	// The data-model examples are in the vocabulary.
	for _, want := range []string{"teleport.user.create", "teleport.role.update", "teleport.lock.create", "teleport.token.create",
		"teleport.cluster.register", "teleport.credential.rotate", "teleport.access.refused"} {
		if !Known(want) {
			t.Errorf("vocabulary lacks %s", want)
		}
	}
	for _, a := range Vocabulary {
		if !strings.HasPrefix(string(a), "teleport.") {
			t.Errorf("%s outside teleport.*", a)
		}
	}
	if Known("teleport.cluster.explode") || Known("") {
		t.Fatal("unknown accepted")
	}
}

func TestValidate(t *testing.T) {
	if err := Validate(ok(ClusterRegister)); err != nil {
		t.Fatal(err)
	}
	bad := []func(*Event){
		func(e *Event) { e.Action = "nope" },
		func(e *Event) { e.TenantID = "" },
		func(e *Event) { e.ActorKind = "robot" },
		func(e *Event) { e.TargetKind = "planet" },
		func(e *Event) { e.Outcome = "maybe" },
	}
	for i, mut := range bad {
		e := ok(ClusterRegister)
		mut(&e)
		if Validate(e) == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	for _, k := range []string{ActorModule, ActorWorker, ActorSystem} {
		for _, tk := range TargetKinds {
			for _, o := range []string{OutcomeFailure, OutcomeUnknown} {
				e := ok(UserCreate)
				e.ActorKind, e.TargetKind, e.Outcome = k, tk, o
				if err := Validate(e); err != nil {
					t.Errorf("actor %s target %s: %v", k, tk, err)
				}
			}
		}
	}
}

func TestRedact(t *testing.T) {
	long := strings.Repeat("x", 400)
	in := map[string]any{
		"name":            "alice",
		"roles":           []any{"access", "editor"},
		"identity_file":   "TELEPORT-MARKER-IDENTITY",
		"credential":      "c",
		"invite_url":      "https://p/invite/abc",
		"reset_url":       "https://p/reset/abc",
		"token":           "t",
		"Password":        "p",
		"private_key":     "k",
		"install_command": "curl ... | bash",
		"config_snippet":  "auth_token: x",
		"before_sha256":   "aa",
		"after_sha256":    "bb",
		"note":            long,
		"nested":          map[string]any{"secret": "s", "ok": 1, "list": []any{map[string]any{"authorization": "Bearer x", "n": "v"}}},
	}
	out := Redact(in)
	for _, k := range []string{"identity_file", "credential", "invite_url", "reset_url", "token", "Password", "private_key", "install_command", "config_snippet"} {
		if _, ok := out[k]; ok {
			t.Errorf("%s kept", k)
		}
	}
	for _, k := range []string{"name", "roles", "before_sha256", "after_sha256"} {
		if _, ok := out[k]; !ok {
			t.Errorf("%s dropped", k)
		}
	}
	if len(out["note"].(string)) != 256 {
		t.Fatal("not truncated")
	}
	n := out["nested"].(map[string]any)
	if _, ok := n["secret"]; ok || n["ok"] != 1 {
		t.Fatalf("nested %v", n)
	}
	inner := n["list"].([]any)[0].(map[string]any)
	if _, ok := inner["authorization"]; ok || inner["n"] != "v" {
		t.Fatalf("list %v", inner)
	}
	if Redact(nil) == nil || len(Redact(nil)) != 0 {
		t.Fatal("nil map")
	}
}

func TestWriterRecordsAndFlushes(t *testing.T) {
	st := &memStore{}
	var errs []error
	var emu sync.Mutex
	w := NewWriter(st, func(err error) { emu.Lock(); errs = append(errs, err); emu.Unlock() })
	e := ok(ClusterRegister)
	e.ClusterID = "c1"
	e.CorrelationID = "req-1"
	e.Reason = strings.Repeat("r", 400)
	e.Details = map[string]any{"credential": "TELEPORT-MARKER-X", "edition": "community"}
	if err := w.Record(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if err := w.Record(context.Background(), Event{Action: "nope"}); err == nil {
		t.Fatal("invalid event queued")
	}
	w.Flush(context.Background())
	rows := st.all()
	if len(rows) != 1 {
		t.Fatalf("rows %d", len(rows))
	}
	r := rows[0]
	if r.Action != "teleport.cluster.register" || r.TenantID != tn || r.ClusterID != "c1" || r.CorrelationID != "req-1" ||
		r.TargetKind != TargetCluster || r.TargetName != "prod" || r.Outcome != OutcomeSuccess || r.ID == "" || r.Time.IsZero() {
		t.Fatalf("row %+v", r)
	}
	if len(r.Reason) != 256 {
		t.Fatal("reason not truncated")
	}
	if _, ok := r.Detail["credential"]; ok || r.Detail["edition"] != "community" {
		t.Fatalf("detail %v", r.Detail)
	}
	// Store errors reach onError.
	st.err = errors.New("db down")
	_ = w.Record(context.Background(), ok(UserCreate))
	w.Flush(context.Background())
	emu.Lock()
	n := len(errs)
	emu.Unlock()
	if n != 1 {
		t.Fatalf("errors %d", n)
	}
	w.Close()
	w.Close() // idempotent
	if err := w.Record(context.Background(), ok(UserCreate)); err == nil {
		t.Fatal("record after close")
	}
	w.Flush(context.Background()) // no-op after close
	if w.Dropped() != 1 {
		t.Fatalf("dropped %d", w.Dropped())
	}
}

func TestWriterQueueFullAndFlushCancel(t *testing.T) {
	st := &memStore{}
	dropped := 0
	w := newWriter(st, func(error) { dropped++ }, 1)
	// Not started: the second record overflows the 1-slot queue.
	_ = w.Record(context.Background(), ok(UserCreate))
	_ = w.Record(context.Background(), ok(UserCreate))
	if dropped != 1 || w.Dropped() != 1 {
		t.Fatalf("dropped %d", dropped)
	}
	// Flush with a cancelled context returns without a running writer.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w.Flush(ctx)
	// Flush whose context ends while waiting for the drain.
	w.start()
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	w.Flush(ctx2)
	w.Close()
	if len(st.all()) != 1 {
		t.Fatalf("rows %d", len(st.all()))
	}
	// nil onError is tolerated.
	newWriter(st, nil, 1).onError(errors.New("x"))
}

func TestEmitAndActorOf(t *testing.T) {
	Emit(context.Background(), nil, ok(UserCreate)) // nil recorder is a no-op
	st := &memStore{}
	w := NewWriter(st, nil)
	Emit(context.Background(), w, ok(UserCreate))
	w.Flush(context.Background())
	w.Close()
	if len(st.all()) != 1 {
		t.Fatal("emit")
	}
	for kind, want := range map[string]string{authz.ActorModule: ActorModule, authz.ActorWorker: ActorWorker, authz.ActorSystem: ActorSystem, authz.ActorUser: ActorUser, "": ActorUser} {
		if got := ActorOf(kind); got != want {
			t.Errorf("ActorOf(%q) = %q", kind, got)
		}
	}
	s := authz.User(tn, "alice", nil)
	e := FromSubjects(s, RoleUpdate, TargetRole, "editor", OutcomeSuccess)
	if e.TenantID != tn || e.ActorID != "alice" || e.ActorKind != ActorUser || e.Action != RoleUpdate || e.TargetName != "editor" {
		t.Fatalf("FromSubjects %+v", e)
	}
}
