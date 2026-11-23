package teleportapi

import (
	"context"
	"math"
	"time"

	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/trace"
)

// Session recordings (spec 003, research R1): the events of one recorded
// session read live with StreamSessionEvents from an event index on. The
// module relays them to the portal player page by page and keeps nothing;
// Data is terminal output and must never be logged, audited or published.

// Recording event types (Teleport's).
const (
	RecordingStart  = "session.start"
	RecordingPrint  = "print"
	RecordingResize = "resize"
	RecordingEnd    = "session.end"
)

// RecordingEvent is one event of a session recording. Type is Teleport's
// event type; Size ("W:H") is set on session.start and resize, Ms (the
// delay from the session start) and Data on print, Kube on a session.start
// of a Kubernetes session.
type RecordingEvent struct {
	Index int64
	Type  string
	Time  time.Time
	Ms    int64
	Data  []byte
	Size  string
	Kube  bool
}

func recordingEventOf(e apievents.AuditEvent) RecordingEvent {
	out := RecordingEvent{Index: e.GetIndex(), Type: e.GetType(), Time: e.GetTime().UTC()}
	switch x := e.(type) {
	case *apievents.SessionStart:
		out.Size, out.Kube = x.TerminalSize, x.KubernetesCluster != ""
	case *apievents.SessionPrint:
		out.Ms, out.Data = x.DelayMilliseconds, x.Data
	case *apievents.Resize:
		out.Size = x.TerminalSize
	}
	return out
}

// streamFailed is a stream that fails at once with err.
func streamFailed(err error) (<-chan RecordingEvent, <-chan error) {
	out, errs := make(chan RecordingEvent), make(chan error, 1)
	errs <- err
	close(out)
	close(errs)
	return out, errs
}

// ---- real

// StreamRecording relays StreamSessionEvents. Events is closed when the
// stream ends; errs then holds at most one error and is closed. The caller
// cancels ctx to stop early (the teleport/api reader goroutine ends with it).
func (r *real) StreamRecording(ctx context.Context, sid string, start int64) (<-chan RecordingEvent, <-chan error) {
	if start < 0 || start > math.MaxInt32 {
		return streamFailed(trace.BadParameter("recording index out of range"))
	}
	evs, terrs := r.e.StreamSessionEvents(ctx, sid, start)
	out, errs := make(chan RecordingEvent), make(chan error, 1)
	go func() {
		defer close(errs)
		defer close(out)
		for {
			select {
			case e, ok := <-evs:
				if !ok {
					return
				}
				if ctx.Err() != nil {
					errs <- ctx.Err()
					return
				}
				select {
				case out <- recordingEventOf(e):
				case <-ctx.Done():
					errs <- ctx.Err()
					return
				}
			case err := <-terrs:
				errs <- err
				return
			case <-ctx.Done():
				errs <- ctx.Err()
				return
			}
		}
	}()
	return out, errs
}

// ---- limited

// StreamRecording opens the stream with the caller's context, like Watch: a
// page read is bounded by the recording service (time, size, concurrency),
// so neither the per-call timeout nor a cluster slot applies; the final
// error is mapped.
func (c *limited) StreamRecording(ctx context.Context, sid string, start int64) (<-chan RecordingEvent, <-chan error) {
	evs, errs := c.inner.StreamRecording(ctx, sid, start)
	mapped := make(chan error, 1)
	go func() {
		defer close(mapped)
		for err := range errs {
			mapped <- MapError(err)
		}
	}()
	return evs, mapped
}
