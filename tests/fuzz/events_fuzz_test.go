package fuzz

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/auditlog"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// FuzzEventNormalization: a Teleport audit event is cluster-supplied data.
// Whatever its type, code and JSON, normalization never panics; raw is valid
// JSON of at most 16 KiB; user, resource and summary are bounded UTF-8 with
// no control characters; a failed login is never reported as a success.
func FuzzEventNormalization(f *testing.F) {
	for _, s := range []struct{ typ, code, raw string }{
		{"user.login", "T1000I", `{"user":"alice","success":true}`},
		{"user.login", "T1000W", `{"user":"mallory","success":false,"error":"bad"}`},
		{"session.start", "T2000I", `{"user":"a","server_hostname":"web-1","sid":"s"}`},
		{"", "TLK00I", `{"name":"l1"}`},
		{"exec", "T3002I", `{"command":"` + strings.Repeat("x", 20000) + `"}`},
		{"x", "", `[1,2,3]`}, {"x", "", `{`}, {"", "", ""}, {"\x00", "\xff", `{"user":"\u0000<script>"}`},
		{"session.end", "T2004I", `{"participants":["a",1,null],"session_start":"bogus"}`},
	} {
		f.Add(s.typ, s.code, []byte(s.raw))
	}
	f.Fuzz(func(t *testing.T, typ, code string, raw []byte) {
		e := auditlog.Normalize(teleportapi.AuditEvent{ID: "id", Type: typ, Code: code, Time: time.Unix(0, 0), Raw: raw})
		if !json.Valid(e.Raw) || len(e.Raw) > auditlog.MaxRaw {
			t.Fatalf("raw: %d bytes, valid %v", len(e.Raw), json.Valid(e.Raw))
		}
		for name, v := range map[string]string{"user": e.User, "resource": e.Resource, "type": e.Type, "code": e.Code} {
			if len(v) > 256 || !utf8.ValidString(v) || strings.IndexFunc(v, unicode.IsControl) >= 0 {
				t.Fatalf("%s %q is not bounded text", name, v)
			}
		}
		if !utf8.ValidString(e.Summary) || strings.IndexFunc(e.Summary, unicode.IsControl) >= 0 || len(e.Summary) > 1024 {
			t.Fatalf("summary %q", e.Summary)
		}
		if e.Type == auditlog.TypeLoginFailure && e.Success {
			t.Fatal("a failed login reported as success")
		}
		if _, err := json.Marshal(e); err != nil {
			t.Fatalf("event does not encode: %v", err)
		}
	})
}
