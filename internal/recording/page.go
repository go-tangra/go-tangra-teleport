package recording

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// Event kinds of a page (research R2).
const (
	KindOutput = "o" // [ms, "o", base64 output]
	KindResize = "r" // [ms, "r", "WxH"]
)

// Event is one replay event, ms from the session start.
type Event struct {
	Ms   int64
	Kind string
	Data string
}

// MarshalJSON encodes the event as [ms, kind, data].
func (e Event) MarshalJSON() ([]byte, error) { return json.Marshal([3]any{e.Ms, e.Kind, e.Data}) }

// Page is one page of a recording (the RecordingPage schema). Width and
// Height are the initial terminal size, on the first page only.
type Page struct {
	Width  int     `json:"width,omitempty"`
	Height int     `json:"height,omitempty"`
	Events []Event `json:"events"`
	Next   string  `json:"next,omitempty"`
	Done   bool    `json:"done"`
	Bytes  int64   `json:"bytes"`
}

// position is where a playback stands between pages; the cursor carries it.
type position struct {
	Next  int64 `json:"n"`  // next event index to read
	Bytes int64 `json:"b"`  // output relayed so far
	T0    int64 `json:"t0"` // session start, unix ms (resize times are relative to it)
	Ms    int64 `json:"ms"` // ms of the last event (events never go back in time)
}

// bounds of one page and one playback.
type bounds struct {
	maxBytes   int64
	pageBytes  int
	pageEvents int
}

// Default terminal size when a recording names none.
const (
	defaultWidth  = 80
	defaultHeight = 24
)

// builder turns recording events into one page. It never logs or keeps the
// output beyond the page it builds.
type builder struct {
	pos       position
	first     bool // the page starts the playback (from index 0)
	started   bool // the first page saw session.start
	b         bounds
	pageBytes int
	page      Page
}

func newBuilder(pos position, b bounds) *builder {
	return &builder{pos: pos, first: pos.Next == 0, b: b, page: Page{Events: []Event{}, Bytes: pos.Bytes}}
}

// termSize parses Teleport's "W:H" (each 1..MaxTerm).
func termSize(s string) (w, h int, ok bool) {
	ws, hs, found := strings.Cut(s, ":")
	if !found {
		return 0, 0, false
	}
	w, err1 := strconv.Atoi(ws)
	h, err2 := strconv.Atoi(hs)
	if err1 != nil || err2 != nil || w < 1 || h < 1 || w > MaxTerm || h > MaxTerm {
		return 0, 0, false
	}
	return w, h, true
}

func (b *builder) emit(ms int64, kind, data string) {
	if ms < b.pos.Ms {
		ms = b.pos.Ms
	}
	b.pos.Ms = ms
	b.page.Events = append(b.page.Events, Event{Ms: ms, Kind: kind, Data: data})
}

// add takes the next event of the stream; full reports that the page is
// complete (a bound was reached or the session ended).
func (b *builder) add(e teleportapi.RecordingEvent) (full bool, err error) {
	if e.Index < b.pos.Next && (b.started || !b.first) {
		return false, nil // already relayed
	}
	if b.first && !b.started {
		// R6: only an SSH terminal session (session.start without a
		// Kubernetes cluster) is replayed here.
		if e.Type != teleportapi.RecordingStart || e.Kube {
			return false, ErrNotPlayable
		}
		b.started = true
		b.page.Width, b.page.Height = defaultWidth, defaultHeight
		if w, h, ok := termSize(e.Size); ok {
			b.page.Width, b.page.Height = w, h
		}
		if !e.Time.IsZero() {
			b.pos.T0 = e.Time.UnixMilli()
		}
	}
	b.pos.Next = e.Index + 1
	switch e.Type {
	case teleportapi.RecordingPrint:
		if len(e.Data) == 0 {
			return false, nil
		}
		if b.pos.Bytes+int64(len(e.Data)) > b.b.maxBytes {
			return false, ErrTooLarge
		}
		b.pos.Bytes += int64(len(e.Data))
		b.page.Bytes = b.pos.Bytes
		b.pageBytes += len(e.Data)
		b.emit(e.Ms, KindOutput, base64.StdEncoding.EncodeToString(e.Data))
	case teleportapi.RecordingResize:
		w, h, ok := termSize(e.Size)
		if !ok {
			return false, nil
		}
		ms := b.pos.Ms
		if !e.Time.IsZero() && b.pos.T0 != 0 {
			ms = e.Time.UnixMilli() - b.pos.T0
		}
		b.emit(ms, KindResize, strconv.Itoa(w)+"x"+strconv.Itoa(h))
	case teleportapi.RecordingEnd:
		b.page.Done = true
		return true, nil
	}
	return b.pageBytes >= b.b.pageBytes || len(b.page.Events) >= b.b.pageEvents, nil
}

// end marks the end of the stream: the recording is complete. A first page
// that saw nothing has no recording.
func (b *builder) end() error {
	if b.first && !b.started {
		return ErrNotFound
	}
	b.page.Done = true
	return nil
}
