package contract

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/httpapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/terminal"
)

// T019: the terminal routes' statuses, the SSE output with resume, and
// that another caller's terminal is not found.
func TestTerminalRoutes(t *testing.T) {
	doc := load(t)
	s, e, id, _ := accessTerminalServer(t)
	base := "/api/teleport/v1/clusters/" + id + "/terminals"
	do := func(method, path, token string, body any, status int, reason string) *httptest.ResponseRecorder {
		t.Helper()
		r, rec := call(s, method, path, token, body)
		if rec.Code != status {
			t.Fatalf("%s %s as %s: %d %s", method, path, token, rec.Code, rec.Body)
		}
		if reason != "" && reasonOf(t, rec.Body.Bytes()) != reason {
			t.Fatalf("%s %s as %s: %s, want %s", method, path, token, rec.Body, reason)
		}
		if rec.Header().Get("Content-Type") == "application/json" {
			ValidateResponse(t, doc, r, rec)
		}
		return rec
	}
	open := map[string]any{"node": "node-1", "login": "deploy", "cols": 80, "rows": 24}
	do("POST", base, "viewer", open, 403, "forbidden")
	do("POST", base, "alicepwd", open, 403, "mfa_required")
	do("POST", base, "carol", open, 409, "not_provisioned")
	do("POST", base, "outsider", open, 404, "not_found")
	do("POST", base, "alice", map[string]any{"node": "node-1", "login": "root", "cols": 80, "rows": 24}, 422, "validation_failed")
	do("POST", base, "alice", map[string]any{"node": "bad node", "login": "deploy", "cols": 80, "rows": 24}, 422, "validation_failed")
	do("POST", base, "alice", map[string]any{"node": "node-1", "login": "deploy", "cols": 0, "rows": 24}, 422, "validation_failed")

	rec := do("POST", base, "alice", open, 201, "")
	var v terminal.View
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	tid := base + "/" + v.ID
	in := map[string]any{"data": base64.StdEncoding.EncodeToString([]byte("echo contract\n"))}
	do("POST", tid+"/input", "alice", in, 204, "")
	do("POST", tid+"/resize", "alice", map[string]any{"cols": 100, "rows": 30}, 204, "")
	do("POST", tid+"/resize", "alice", map[string]any{"cols": 1001, "rows": 30}, 422, "validation_failed")
	do("POST", tid+"/keepalive", "alice", nil, 204, "")
	do("POST", tid+"/input", "alice", map[string]any{"data": "!!"}, 422, "validation_failed")
	// Another person (even an administrator of the tenant) does not see it.
	do("POST", tid+"/input", "admin", in, 404, "not_found")
	do("GET", tid+"/output", "admin", nil, 404, "not_found")
	do("DELETE", tid, "admin", nil, 404, "not_found")
	do("GET", base+"/0123456789abcdef0123456789abcdef/output", "alice", nil, 404, "not_found")

	e.Teleport.Shells()[0].Print("contract-output\r\n")
	e.Teleport.Shells()[0].Exit(nil)
	// The stream replays the output, then the end, and returns.
	out := streamUntilEnd(t, s, tid+"/output", "alice")
	if !strings.Contains(out.text, "contract-output") || out.end != `{"reason":"exit"}` || out.lastID == "" {
		t.Fatalf("stream %+v", out)
	}
	// Resume from the last event id: nothing more but the end.
	again := streamUntilEnd(t, s, tid+"/output?from="+out.lastID, "alice")
	if again.text != "" || again.end == "" {
		t.Fatalf("resume %+v", again)
	}
	do("POST", tid+"/input", "alice", in, 409, "terminal_ended")
	do("DELETE", tid, "alice", nil, 204, "")
}

type sse struct {
	text, end, lastID string
}

// streamUntilEnd reads an output stream of an ended terminal (the handler
// returns after the end event) and decodes its events.
func streamUntilEnd(t *testing.T, s *httpapi.Server, path, token string) sse {
	t.Helper()
	_, rec := call(s, "GET", path, token, nil)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body)
	}
	var out sse
	for _, block := range strings.Split(rec.Body.String(), "\n\n") {
		ev, id, data := "", "", ""
		for _, line := range strings.Split(block, "\n") {
			k, v, _ := strings.Cut(line, ": ")
			switch k {
			case "event":
				ev = v
			case "id":
				id = v
			case "data":
				data = v
			}
		}
		switch ev {
		case "output":
			b, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				t.Fatalf("output %q", data)
			}
			out.text += string(b)
			out.lastID = id
		case "end":
			out.end = data
		}
	}
	return out
}
