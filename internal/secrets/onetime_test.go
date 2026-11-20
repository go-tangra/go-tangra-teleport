package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// A one-time value is encoded only by the JSON response that creates it;
// every printing and logging path redacts it.
func TestOneTimeIsEncodedOnlyAsJSON(t *testing.T) {
	o := NewOneTime(NewSecret([]byte(marker)))
	js, err := json.Marshal(struct {
		URL OneTime `json:"url"`
	}{o})
	if err != nil || string(js) != `{"url":"`+marker+`"}` {
		t.Fatalf("json %s %v", js, err)
	}
	var logBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("x", "url", o)
	slog.New(slog.NewTextHandler(&logBuf, nil)).Info("x", "wrapped", struct{ URL OneTime }{o})
	for _, out := range []string{o.String(), o.GoString(), fmt.Sprintf("%v %+v %#v %s", o, o, o, o),
		fmt.Sprintf("%v %+v", struct{ URL OneTime }{o}, struct{ URL OneTime }{o}), logBuf.String()} {
		if strings.Contains(out, marker) {
			t.Fatalf("one-time value leaked: %q", out)
		}
	}
	if string(o.Reveal()) != marker {
		t.Fatal("Reveal")
	}
	if o.IsZero() || !NewOneTime(Secret{}).IsZero() {
		t.Fatal("IsZero")
	}
	if err := json.Unmarshal([]byte(`"x"`), &o); err == nil {
		t.Fatal("a one-time value must not be decodable")
	}
}
