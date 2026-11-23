package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/stream"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/terminal"
)

// TerminalStreamMaxAge closes each output stream (the gateway's route
// timeout is 300 s); the client resumes from the last event id.
var TerminalStreamMaxAge = stream.MaxAge

func (s *Server) failTerminal(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, terminal.ErrNotFound):
		WriteError(w, ErrNotFound.Status, ErrNotFound.Reason)
	case errors.Is(err, terminal.ErrTooMany):
		WriteJSON(w, ErrTooManyTerminals.Status, map[string]any{"reason": ErrTooManyTerminals.Reason,
			"message": fmt.Sprintf("at most %d terminals can be open at once; end one first", terminal.MaxPerUser)})
	case errors.Is(err, terminal.ErrEnded):
		WriteError(w, ErrTerminalEnded.Status, ErrTerminalEnded.Reason)
	case errors.Is(err, terminal.ErrLogin):
		WriteDetail(w, ErrValidation, map[string]any{"field": "login", "message": "your Teleport user does not hold this login"})
	case errors.Is(err, terminal.ErrInputTooBig):
		WriteDetail(w, ErrValidation, map[string]any{"field": "data", "message": "at most 64 KiB of input at once"})
	default:
		s.failAccess(w, r, err)
	}
}

// registerTerminals mounts the brokered terminal (spec 004, US1): create,
// SSE output, input, resize, keepalive and end. Terminal content is never
// logged.
func (s *Server) registerTerminals(hub *terminal.Hub) {
	base := Prefix + "/clusters/{id}/terminals"
	s.MustHandle("POST", base, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Node  string `json:"node"`
			Login string `json:"login"`
			Cols  int    `json:"cols"`
			Rows  int    `json:"rows"`
		}
		if err := DecodeJSON(r, &in, 4096); err != nil {
			Fail(w, r, s.log, err)
			return
		}
		v, err := hub.Create(r.Context(), r.PathValue("id"), teleportapi.ShellRequest{Node: in.Node, Login: in.Login, Cols: in.Cols, Rows: in.Rows})
		if err != nil {
			s.failTerminal(w, r, err)
			return
		}
		WriteJSON(w, http.StatusCreated, v)
	})
	s.MustHandle("DELETE", base+"/{tid}", func(w http.ResponseWriter, r *http.Request) {
		if err := hub.Close(r.Context(), r.PathValue("id"), r.PathValue("tid")); err != nil {
			s.failTerminal(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	s.MustHandle("POST", base+"/{tid}/input", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Data string `json:"data"`
		}
		if err := DecodeJSON(r, &in, 128<<10); err != nil {
			Fail(w, r, s.log, err)
			return
		}
		p, err := base64.StdEncoding.DecodeString(in.Data)
		if err != nil || len(p) == 0 {
			WriteDetail(w, ErrValidation, map[string]any{"field": "data", "message": "must be base64"})
			return
		}
		err = hub.Input(r.Context(), r.PathValue("id"), r.PathValue("tid"), p)
		clear(p)
		if err != nil {
			s.failTerminal(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	s.MustHandle("POST", base+"/{tid}/resize", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Cols int `json:"cols"`
			Rows int `json:"rows"`
		}
		if err := DecodeJSON(r, &in, 1024); err != nil {
			Fail(w, r, s.log, err)
			return
		}
		if in.Cols < 1 || in.Cols > 1000 || in.Rows < 1 || in.Rows > 1000 {
			WriteDetail(w, ErrValidation, map[string]any{"field": "cols", "message": "cols and rows must be 1 to 1000"})
			return
		}
		if err := hub.Resize(r.Context(), r.PathValue("id"), r.PathValue("tid"), in.Cols, in.Rows); err != nil {
			s.failTerminal(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	s.MustHandle("POST", base+"/{tid}/keepalive", func(w http.ResponseWriter, r *http.Request) {
		if err := hub.Keepalive(r.Context(), r.PathValue("id"), r.PathValue("tid")); err != nil {
			s.failTerminal(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	s.MustHandle("GET", base+"/{tid}/output", func(w http.ResponseWriter, r *http.Request) {
		t, err := hub.Output(r.Context(), r.PathValue("id"), r.PathValue("tid"))
		if err != nil {
			s.failTerminal(w, r, err)
			return
		}
		from := int64(0)
		for _, v := range []string{r.Header.Get("Last-Event-ID"), r.URL.Query().Get("from")} {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
				from = n
			}
		}
		serveTerminal(w, r, t, from)
	})
}

// serveTerminal streams t's output from offset from: an "output" event per
// chunk (id = the offset after it, data = base64), "gap" when output was
// lost before from, "end" with the reason when the terminal ends, "bye"
// when the stream reaches its maximum age.
func serveTerminal(w http.ResponseWriter, r *http.Request, t *terminal.Terminal, from int64) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		WriteError(w, ErrUnavailable.Status, ErrUnavailable.Reason)
		return
	}
	detach := t.Attach()
	defer detach()
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "retry: %d\n\n", stream.Retry)
	flusher.Flush()
	ping := time.NewTicker(stream.Heartbeat)
	defer ping.Stop()
	deadline := time.NewTimer(TerminalStreamMaxAge)
	defer deadline.Stop()
	for {
		c, changed := t.Read(from)
		if c.Gap {
			_, _ = fmt.Fprintf(w, "event: gap\ndata: {\"from\":%d}\n\n", c.From)
		}
		if len(c.Data) > 0 {
			_, _ = fmt.Fprintf(w, "event: output\nid: %d\ndata: %s\n\n", c.Next, base64.StdEncoding.EncodeToString(c.Data))
			clear(c.Data)
		}
		from = c.Next
		if c.Ended {
			b, _ := json.Marshal(map[string]string{"reason": c.Reason})
			_, _ = fmt.Fprintf(w, "event: end\ndata: %s\n\n", b)
			flusher.Flush()
			return
		}
		flusher.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-deadline.C:
			_, _ = fmt.Fprint(w, "event: bye\ndata: {}\n\n")
			flusher.Flush()
			return
		case <-ping.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case <-changed:
		}
	}
}
