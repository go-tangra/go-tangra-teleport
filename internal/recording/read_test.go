package recording

import (
	"context"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// R3: a page ends after PageTime of reading even when the stream stalls.
func TestReadStopsAtPageTime(t *testing.T) {
	evs, errs := make(chan teleportapi.RecordingEvent), make(chan error, 1)
	go func() {
		evs <- teleportapi.RecordingEvent{Index: 5, Type: teleportapi.RecordingPrint, Data: []byte("x"), Ms: 1}
	}() // then nothing
	b := newBuilder(position{Next: 5, T0: 1}, bounds{maxBytes: MaxBytes, pageBytes: PageBytes, pageEvents: PageEvents})
	began := time.Now()
	if err := read(context.Background(), evs, errs, b, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if time.Since(began) > 2*time.Second || len(b.page.Events) != 1 || b.page.Done || b.pos.Next != 6 {
		t.Fatalf("page %+v next %d", b.page, b.pos.Next)
	}
	// A cancelled request ends the read with its error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := read(ctx, evs, errs, newBuilder(position{Next: 6, T0: 1}, b.b), time.Minute); err == nil {
		t.Fatal("cancelled read")
	}
}
