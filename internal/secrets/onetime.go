package secrets

import (
	"encoding/json"
	"errors"
	"log/slog"
)

// OneTime is a value only the one response that creates it may carry
// (SR-002): an invite or reset URL, later a join token. JSON encodes the
// value — that is the response — while every printing and logging path
// prints Redacted, so it cannot reach a log line, an event or an audit row
// by accident.
type OneTime struct{ s Secret }

// NewOneTime wraps s.
func NewOneTime(s Secret) OneTime { return OneTime{s: s} }

// IsZero reports an empty value.
func (o OneTime) IsZero() bool { return o.s.IsZero() }

// Reveal returns a copy of the value, for the one channel that delivers it
// besides the creating response (an invite handed to notification).
func (o OneTime) Reveal() []byte { return o.s.Reveal() }

// String implements fmt.Stringer.
func (OneTime) String() string { return Redacted }

// GoString implements fmt.GoStringer (%#v).
func (OneTime) GoString() string { return Redacted }

// LogValue implements slog.LogValuer.
func (OneTime) LogValue() slog.Value { return slog.StringValue(Redacted) }

// MarshalJSON encodes the value (the one response that carries it).
func (o OneTime) MarshalJSON() ([]byte, error) { return json.Marshal(string(o.s.b)) }

// UnmarshalJSON refuses: a one-time value is never read from a request.
func (*OneTime) UnmarshalJSON([]byte) error {
	return errors.New("secrets: a one-time value cannot be decoded")
}
