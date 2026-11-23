package recording

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

var t0 = time.Unix(1700000000, 0).UTC()

func start(size string) teleportapi.RecordingEvent {
	return teleportapi.RecordingEvent{Type: teleportapi.RecordingStart, Time: t0, Size: size}
}

func out(i int64, ms int64, data string) teleportapi.RecordingEvent {
	return teleportapi.RecordingEvent{Index: i, Type: teleportapi.RecordingPrint, Ms: ms, Data: []byte(data)}
}

func resize(i int64, at time.Duration, size string) teleportapi.RecordingEvent {
	return teleportapi.RecordingEvent{Index: i, Type: teleportapi.RecordingResize, Time: t0.Add(at), Size: size}
}

// feed adds events until the page is full or they run out.
func feed(t *testing.T, b *builder, evs ...teleportapi.RecordingEvent) (full bool, err error) {
	t.Helper()
	for _, e := range evs {
		if full, err = b.add(e); full || err != nil {
			return full, err
		}
	}
	return false, nil
}

func defaults() bounds {
	return bounds{maxBytes: MaxBytes, pageBytes: PageBytes, pageEvents: PageEvents}
}

func TestPageFromStart(t *testing.T) {
	b := newBuilder(position{}, defaults())
	full, err := feed(t, b, start("80:24"), out(1, 10, "ls\r\n"),
		teleportapi.RecordingEvent{Index: 2, Type: "session.join"},          // not replayed
		resize(3, 2*time.Second, "120:40"), out(4, 1500, "\x1b[31mred\xff"), // ms below the resize: clamped
		teleportapi.RecordingEvent{Index: 5, Type: teleportapi.RecordingEnd})
	if err != nil || !full {
		t.Fatalf("full %v err %v", full, err)
	}
	if err := b.end(); err != nil {
		t.Fatal(err)
	}
	p := b.page
	if !p.Done || p.Width != 80 || p.Height != 24 || p.Bytes != int64(len("ls\r\n")+len("\x1b[31mred\xff")) {
		t.Fatalf("page %+v", p)
	}
	want := []Event{{10, KindOutput, b64("ls\r\n")}, {2000, KindResize, "120x40"}, {2000, KindOutput, b64("\x1b[31mred\xff")}}
	if len(p.Events) != len(want) {
		t.Fatalf("events %+v", p.Events)
	}
	for i := range want {
		if p.Events[i] != want[i] {
			t.Fatalf("event %d = %+v, want %+v", i, p.Events[i], want[i])
		}
	}
	if b.pos.Next != 6 || b.pos.T0 != t0.UnixMilli() || b.pos.Ms != 2000 {
		t.Fatalf("position %+v", b.pos)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"events":[[10,"o","bHMNCg=="],[2000,"r","120x40"]`)) || !bytes.Contains(raw, []byte(`"done":true`)) {
		t.Fatalf("json %s", raw)
	}
	// Binary output survives the round trip byte for byte.
	var back struct{ Events [][3]any }
	_ = json.Unmarshal(raw, &back)
	got, _ := base64.StdEncoding.DecodeString(back.Events[2][2].(string))
	if string(got) != "\x1b[31mred\xff" {
		t.Fatalf("binary %q", got)
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// A later page continues from the cursor's position: no size, resize times
// against the carried session start, ms never below the last one.
func TestPageContinues(t *testing.T) {
	b := newBuilder(position{Next: 10, Bytes: 100, T0: t0.UnixMilli(), Ms: 5000}, defaults())
	if _, err := feed(t, b, out(9, 1, "old"), out(10, 4000, "a"), resize(11, 7*time.Second, "100:30"), resize(12, 0, "bad")); err != nil {
		t.Fatal(err)
	}
	if err := b.end(); err != nil {
		t.Fatal(err)
	}
	p := b.page
	if p.Width != 0 || p.Height != 0 || !p.Done || p.Bytes != 101 || len(p.Events) != 2 {
		t.Fatalf("page %+v", p)
	}
	if p.Events[0] != (Event{5000, KindOutput, b64("a")}) || p.Events[1] != (Event{7000, KindResize, "100x30"}) {
		t.Fatalf("events %+v", p.Events)
	}
	if b.pos.Next != 13 {
		t.Fatalf("next %d", b.pos.Next)
	}
}

func TestPageBounds(t *testing.T) {
	// 4000 events.
	b := newBuilder(position{}, defaults())
	if _, err := b.add(start("80:24")); err != nil {
		t.Fatal(err)
	}
	var full bool
	n := 0
	for i := int64(1); !full; i++ {
		var err error
		if full, err = b.add(out(i, i, "x")); err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != PageEvents || len(b.page.Events) != PageEvents || b.page.Done || b.pos.Next != PageEvents+1 {
		t.Fatalf("events bound: %d events, next %d", n, b.pos.Next)
	}
	// 1 MiB of output.
	b = newBuilder(position{Next: 1, T0: 1}, defaults())
	chunk := string(bytes.Repeat([]byte("y"), 300<<10))
	full, err := feed(t, b, out(1, 1, chunk), out(2, 2, chunk), out(3, 3, chunk), out(4, 4, chunk), out(5, 5, chunk))
	if err != nil || !full || len(b.page.Events) != 4 || b.page.Bytes != 4*300<<10 {
		t.Fatalf("bytes bound: full %v err %v events %d", full, err, len(b.page.Events))
	}
	// Empty output is skipped.
	b = newBuilder(position{Next: 1, T0: 1}, defaults())
	if _, err := b.add(out(1, 1, "")); err != nil || len(b.page.Events) != 0 || b.pos.Next != 2 {
		t.Fatalf("empty print %+v", b.page)
	}
}

func TestPageSizeLimit(t *testing.T) {
	bd := defaults()
	bd.maxBytes = 10
	b := newBuilder(position{Next: 1, Bytes: 8, T0: 1}, bd)
	if _, err := b.add(out(1, 1, "ab")); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	if _, err := b.add(out(2, 2, "c")); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over the limit: %v", err)
	}
}

func TestPageNotPlayable(t *testing.T) {
	kube := start("80:24")
	kube.Kube = true
	for name, first := range map[string]teleportapi.RecordingEvent{
		"kubernetes": kube,
		"desktop":    {Type: "windows.desktop.session.start"},
		"database":   {Type: "db.session.start"},
		"print":      out(0, 0, "no start"),
	} {
		b := newBuilder(position{}, defaults())
		if _, err := b.add(first); !errors.Is(err, ErrNotPlayable) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A stream with nothing in it has no recording.
	if err := newBuilder(position{}, defaults()).end(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty: %v", err)
	}
	// A later page that is empty is just the end.
	b := newBuilder(position{Next: 5, T0: 1}, defaults())
	if err := b.end(); err != nil || !b.page.Done {
		t.Fatalf("empty later page: %v %+v", err, b.page)
	}
}

func TestTerminalSize(t *testing.T) {
	for in, want := range map[string][2]int{"80:24": {80, 24}, "4096:4096": {4096, 4096}, "0:24": {}, "80:": {}, "80x24": {},
		"4097:10": {}, "-1:5": {}, "a:b": {}, "": {}, "80:24:1": {}} {
		w, h, ok := termSize(in)
		if ok != (want != [2]int{}) || w != want[0] || h != want[1] {
			t.Errorf("%q = %d,%d,%v", in, w, h, ok)
		}
	}
	// An unusable start size falls back to 80x24.
	b := newBuilder(position{}, defaults())
	if _, err := b.add(start("junk")); err != nil || b.page.Width != 80 || b.page.Height != 24 {
		t.Fatalf("fallback %+v %v", b.page, err)
	}
}
