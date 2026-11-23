package recording

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
)

// Cursor bounds (research R4).
const (
	CursorTTL = time.Hour
	MaxCursor = 1024
)

// binding is what a cursor is bound to: it is part of the MAC input, never
// of the cursor itself, so a cursor names no tenant, user, cluster or
// session and only opens for the same ones.
type binding struct{ Tenant, User, Cluster, Session string }

// claims is the signed cursor payload.
type claims struct {
	position
	Exp int64 `json:"exp"` // unix seconds
}

// Signer issues and opens cursors with a per-process random HMAC-SHA256 key:
// a cursor from another module instance or from before a restart does not
// open (410 playback_expired) and the player starts a new, audited playback.
type Signer struct {
	key [32]byte
	now func() time.Time
}

// NewSigner draws a fresh key (crypto/rand never fails on supported
// platforms; it aborts the process if the system source is broken).
func NewSigner() *Signer {
	s := &Signer{now: time.Now}
	_, _ = rand.Read(s.key[:])
	return s
}

func (s *Signer) mac(b binding, payload string) string {
	m := hmac.New(sha256.New, s.key[:])
	for _, f := range []string{"tangra-teleport/recording/v1", b.Tenant, b.User, b.Cluster, b.Session, payload} {
		// Length-prefixed, so field boundaries cannot shift.
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		m.Write(n[:])
		m.Write([]byte(f))
	}
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// sign issues the cursor for pos, valid for CursorTTL.
func (s *Signer) sign(b binding, pos position) string {
	raw, _ := json.Marshal(claims{position: pos, Exp: s.now().Add(CursorTTL).Unix()})
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return payload + "." + s.mac(b, payload)
}

func malformed() error { return &clusters.FieldError{Field: "cursor", Msg: "is not a playback cursor"} }

// open verifies tok for b and returns its position. A cursor that is not
// one is a FieldError (validation_failed); a forged, foreign, rebound or
// expired one is ErrExpired.
func (s *Signer) open(tok string, b binding) (position, error) {
	if tok == "" || len(tok) > MaxCursor {
		return position{}, malformed()
	}
	payload, mac, ok := strings.Cut(tok, ".")
	if !ok || strings.Contains(mac, ".") {
		return position{}, malformed()
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return position{}, malformed()
	}
	sum, err := base64.RawURLEncoding.DecodeString(mac)
	if err != nil || len(sum) != sha256.Size {
		return position{}, malformed()
	}
	if !hmac.Equal([]byte(mac), []byte(s.mac(b, payload))) {
		return position{}, ErrExpired
	}
	var c claims
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil || c.Next < 0 || c.Bytes < 0 || c.Ms < 0 {
		return position{}, malformed()
	}
	if s.now().Unix() > c.Exp {
		return position{}, ErrExpired
	}
	return c.position, nil
}
