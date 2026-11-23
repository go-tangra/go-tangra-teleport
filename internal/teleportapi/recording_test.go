package teleportapi

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/trace"
)

// StreamSessionEvents mimics teleport/api: events, then either a closed
// events channel (EOF) or one error.
func (s *stubEnroll) StreamSessionEvents(ctx context.Context, sid string, start int64) (chan apievents.AuditEvent, chan error) {
	s.recSID, s.recStart = sid, start
	ch, errs := make(chan apievents.AuditEvent), make(chan error, 1)
	go func() {
		for _, e := range s.rec {
			select {
			case ch <- e:
			case <-ctx.Done():
				errs <- ctx.Err()
				return
			}
		}
		if s.recErr != nil {
			errs <- s.recErr
			return
		}
		close(ch)
	}()
	return ch, errs
}

// drain reads a recording stream to its end.
func drain(t *testing.T, evs <-chan RecordingEvent, errs <-chan error) ([]RecordingEvent, error) {
	t.Helper()
	var out []RecordingEvent
	timeout := time.After(5 * time.Second)
	for {
		select {
		case e, ok := <-evs:
			if !ok {
				return out, <-errs
			}
			out = append(out, e)
		case <-timeout:
			t.Fatal("stream did not end")
		}
	}
}

func TestRealStreamRecording(t *testing.T) {
	t0 := time.Unix(1700000000, 0).UTC()
	st := &stubEnroll{rec: []apievents.AuditEvent{
		&apievents.SessionStart{Metadata: apievents.Metadata{Type: "session.start", Index: 0, Time: t0}, TerminalSize: "80:24"},
		&apievents.SessionPrint{Metadata: apievents.Metadata{Type: "print", Index: 1, Time: t0.Add(time.Second)}, Data: []byte("ls\r\n"), DelayMilliseconds: 1000},
		&apievents.Resize{Metadata: apievents.Metadata{Type: "resize", Index: 2, Time: t0.Add(2 * time.Second)}, TerminalSize: "120:40"},
		&apievents.SessionStart{Metadata: apievents.Metadata{Type: "session.start", Index: 3}, TerminalSize: "80:24",
			KubernetesClusterMetadata: apievents.KubernetesClusterMetadata{KubernetesCluster: "k8s"}},
		&apievents.SessionEnd{Metadata: apievents.Metadata{Type: "session.end", Index: 4}},
	}}
	c := Limit(&real{e: st}, Limits{})
	evs, errs := c.StreamRecording(context.Background(), "abc-1", 0)
	got, err := drain(t, evs, errs)
	if err != nil {
		t.Fatal(err)
	}
	if st.recSID != "abc-1" || st.recStart != 0 || len(got) != 5 {
		t.Fatalf("sid %q start %d events %+v", st.recSID, st.recStart, got)
	}
	if g := got[0]; g.Type != "session.start" || g.Size != "80:24" || g.Kube || !g.Time.Equal(t0) {
		t.Fatalf("start %+v", g)
	}
	if g := got[1]; g.Type != "print" || g.Index != 1 || g.Ms != 1000 || !bytes.Equal(g.Data, []byte("ls\r\n")) {
		t.Fatalf("print %+v", g)
	}
	if g := got[2]; g.Type != "resize" || g.Size != "120:40" {
		t.Fatalf("resize %+v", g)
	}
	if !got[3].Kube || got[4].Type != "session.end" {
		t.Fatalf("kube %+v end %+v", got[3], got[4])
	}

	// An error after some events reaches the caller mapped.
	st.recErr = trace.NotFound("no recording")
	evs, errs = c.StreamRecording(context.Background(), "abc-1", 3)
	got, err = drain(t, evs, errs)
	if !errors.Is(err, ErrNotFound) || len(got) != 5 || st.recStart != 3 {
		t.Fatalf("not found: %v after %d", err, len(got))
	}
	st.rec, st.recErr = nil, trace.AccessDenied("access denied to session")
	evs, errs = c.StreamRecording(context.Background(), "abc-1", 0)
	if _, err = drain(t, evs, errs); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("denied: %v", err)
	}
	// An index beyond the API's int32 is refused before any call.
	st.recSID = ""
	evs, errs = c.StreamRecording(context.Background(), "abc-1", 1<<31)
	if _, err = drain(t, evs, errs); !errors.Is(err, ErrRejected) || st.recSID != "" {
		t.Fatalf("big index: %v (called %q)", err, st.recSID)
	}
}

// Cancelling the context ends the stream without the caller reading on.
func TestRealStreamRecordingCancel(t *testing.T) {
	var many []apievents.AuditEvent
	for i := range 100 {
		many = append(many, &apievents.SessionPrint{Metadata: apievents.Metadata{Type: "print", Index: int64(i)}, Data: []byte("x")})
	}
	st := &stubEnroll{rec: many}
	ctx, cancel := context.WithCancel(context.Background())
	evs, errs := Limit(&real{e: st}, Limits{}).StreamRecording(ctx, "abc-1", 0)
	<-evs
	cancel()
	if _, err := drain(t, evs, errs); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("cancelled: %v", err)
	}
}

func TestFakeStreamRecording(t *testing.T) {
	f := NewFake()
	f.Recordings = map[string][]RecordingEvent{"abc-1": {
		{Type: "session.start", Size: "80:24"}, {Type: "print", Data: []byte("a"), Ms: 5}, {Type: "session.end"},
	}}
	c := Limit(f, Limits{})
	evs, errs := c.StreamRecording(context.Background(), "abc-1", 1)
	got, err := drain(t, evs, errs)
	if err != nil || len(got) != 2 || got[0].Index != 1 || got[0].Type != "print" || got[1].Index != 2 {
		t.Fatalf("from 1: %v %+v", err, got)
	}
	if f.Calls("StreamRecording") != 1 {
		t.Fatal("calls")
	}
	evs, errs = c.StreamRecording(context.Background(), "nope", 0)
	if _, err := drain(t, evs, errs); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	f.FailNext("StreamRecording", trace.AccessDenied("denied"))
	evs, errs = c.StreamRecording(context.Background(), "abc-1", 0)
	if _, err := drain(t, evs, errs); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("denied: %v", err)
	}
	// A cut after the events: what was streamed arrives, then the error.
	f.RecordingErr = map[string]error{"abc-1": trace.ConnectionProblem(nil, "gone")}
	evs, errs = c.StreamRecording(context.Background(), "abc-1", 0)
	got, err = drain(t, evs, errs)
	if !errors.Is(err, ErrUnreachable) || len(got) != 3 {
		t.Fatalf("cut: %v after %d", err, len(got))
	}
	// Cancelled mid-stream.
	ctx, cancel := context.WithCancel(context.Background())
	f.RecordingErr = nil
	evs, errs = c.StreamRecording(ctx, "abc-1", 0)
	<-evs
	cancel()
	if _, err := drain(t, evs, errs); err == nil {
		t.Fatal("cancel: no error")
	}
}
