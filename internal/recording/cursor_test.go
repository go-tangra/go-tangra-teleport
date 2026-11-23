package recording

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
)

func signer(now *time.Time) *Signer {
	s := NewSigner()
	s.now = func() time.Time { return *now }
	return s
}

var bind = binding{Tenant: "t1", User: "u1", Cluster: "c1", Session: "s1"}

func TestCursorRoundTrip(t *testing.T) {
	now := t0
	s := signer(&now)
	pos := position{Next: 42, Bytes: 1 << 20, T0: t0.UnixMilli(), Ms: 9000}
	tok := s.sign(bind, pos)
	if len(tok) > MaxCursor || strings.ContainsAny(tok, "+/= ") {
		t.Fatalf("cursor %q", tok)
	}
	for _, id := range []string{"t1", "u1", "c1", "s1"} {
		if strings.Contains(tok, base64.RawURLEncoding.EncodeToString([]byte(id))) {
			t.Fatalf("cursor carries %s", id)
		}
	}
	got, err := s.open(tok, bind)
	if err != nil || got != pos {
		t.Fatalf("open: %+v %v", got, err)
	}
	// Expiry (1 h).
	now = t0.Add(CursorTTL - time.Second)
	if _, err := s.open(tok, bind); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	now = t0.Add(CursorTTL + time.Second)
	if _, err := s.open(tok, bind); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
}

func TestCursorBinding(t *testing.T) {
	now := t0
	s := signer(&now)
	tok := s.sign(bind, position{Next: 1})
	for name, b := range map[string]binding{
		"tenant":  {Tenant: "t2", User: "u1", Cluster: "c1", Session: "s1"},
		"user":    {Tenant: "t1", User: "u2", Cluster: "c1", Session: "s1"},
		"cluster": {Tenant: "t1", User: "u1", Cluster: "c2", Session: "s1"},
		"session": {Tenant: "t1", User: "u1", Cluster: "c1", Session: "s2"},
		// Field boundaries cannot be shifted.
		"shifted": {Tenant: "t1u", User: "1", Cluster: "c1", Session: "s1"},
	} {
		if _, err := s.open(tok, b); !errors.Is(err, ErrExpired) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Another process (another key).
	other := signer(&now)
	if _, err := other.open(tok, bind); !errors.Is(err, ErrExpired) {
		t.Fatalf("other key: %v", err)
	}
}

func TestCursorTamperAndMalformed(t *testing.T) {
	now := t0
	s := signer(&now)
	tok := s.sign(bind, position{Next: 1, Bytes: 10})
	payload, mac, _ := strings.Cut(tok, ".")
	forged := base64.RawURLEncoding.EncodeToString([]byte(`{"n":1,"b":0,"t0":0,"ms":0,"exp":9999999999}`))
	flip := []byte(mac)
	if flip[0] == 'A' {
		flip[0] = 'B'
	} else {
		flip[0] = 'A'
	}
	for name, bad := range map[string]string{"payload": forged + "." + mac, "mac": payload + "." + string(flip)} {
		if _, err := s.open(bad, bind); !errors.Is(err, ErrExpired) {
			t.Errorf("tampered %s: %v", name, err)
		}
	}
	var fe *clusters.FieldError
	for name, bad := range map[string]string{
		"no dot": payload, "bad b64": "!!!." + mac, "bad mac b64": payload + ".***", "short mac": payload + ".AAAA",
		"too long": strings.Repeat("a", MaxCursor+1), "empty": "", "two dots": payload + "." + mac + ".x",
	} {
		if _, err := s.open(bad, bind); !errors.As(err, &fe) || fe.Field != "cursor" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A validly signed payload that is not a position is malformed too.
	junk := base64.RawURLEncoding.EncodeToString([]byte(`[1,2]`))
	if _, err := s.open(junk+"."+s.mac(bind, junk), bind); !errors.As(err, &fe) {
		t.Fatalf("junk payload: %v", err)
	}
	neg := base64.RawURLEncoding.EncodeToString([]byte(`{"n":-1,"b":0,"t0":0,"ms":0,"exp":9999999999}`))
	if _, err := s.open(neg+"."+s.mac(bind, neg), bind); !errors.As(err, &fe) {
		t.Fatalf("negative index: %v", err)
	}
}

func FuzzCursorOpen(f *testing.F) {
	now := t0
	s := signer(&now)
	f.Add(s.sign(bind, position{Next: 3}))
	f.Add("a.b")
	f.Add("")
	f.Fuzz(func(t *testing.T, tok string) {
		pos, err := s.open(tok, bind)
		if err == nil && (pos.Next < 0 || pos.Bytes < 0) {
			t.Fatalf("accepted %+v", pos)
		}
	})
}
