// Package roleyaml reads and writes Teleport role definitions as YAML
// (research D6): the format Teleport administrators already use with tctl.
//
// Parse accepts one `kind: role` document of version v7 or v8, at most 64
// KiB. It goes YAML → JSON → types.RoleV6 (unknown fields refused) and runs
// the type's own CheckAndSetDefaults, so role semantics are Teleport's, not
// re-implemented here; nothing from Teleport's lib/ (AGPL) is used.
// Normalize renders a role in a stable normal form (sorted keys, defaults
// applied, no revision) and Diff compares two normal forms as a unified
// diff for the preview. Every refusal is an *Error (errors.Is ErrInvalid)
// with a bounded one-line message about the caller's own input.
package roleyaml

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/gravitational/teleport/api/types"
	"gopkg.in/yaml.v3"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// MaxBytes bounds a role definition (64 KiB).
const MaxBytes = 64 << 10

// maxMsg bounds an error message.
const maxMsg = 300

// ErrInvalid marks every refusal of a role definition.
var ErrInvalid = errors.New("roleyaml: invalid role definition")

// Error is a refusal with a readable, bounded, single-line message.
type Error struct{ Msg string }

func (e *Error) Error() string { return "roleyaml: " + e.Msg }

// Is makes every Error an ErrInvalid.
func (e *Error) Is(target error) bool { return target == ErrInvalid }

func invalid(format string, a ...any) error {
	msg := fmt.Sprintf(format, a...)
	if i := strings.IndexAny(msg, "\r\n"); i >= 0 {
		msg = msg[:i]
	}
	if len(msg) > maxMsg {
		msg = msg[:maxMsg] + "…"
	}
	return &Error{Msg: strings.TrimSpace(msg)}
}

// Versions are the accepted role versions.
var Versions = []string{types.V7, types.V8}

// Parse validates src as a role definition and returns the typed role with
// Teleport's defaults applied.
func Parse(src []byte) (*types.RoleV6, error) {
	if len(src) > MaxBytes {
		return nil, invalid("the role definition is larger than 64 KiB")
	}
	dec := yaml.NewDecoder(bytes.NewReader(src))
	var doc any
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, invalid("the role definition is empty")
		}
		return nil, invalid("not valid YAML: %v", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, invalid("exactly one YAML document is expected")
	}
	plain, err := jsonable(doc)
	if err != nil {
		return nil, err
	}
	top, ok := plain.(map[string]any)
	if !ok {
		return nil, invalid("the role definition must be a mapping")
	}
	if k, _ := top["kind"].(string); k != types.KindRole {
		return nil, invalid("kind must be %q", types.KindRole)
	}
	if v, _ := top["version"].(string); v != types.V7 && v != types.V8 {
		return nil, invalid("version must be one of %s", strings.Join(Versions, ", "))
	}
	b, err := json.Marshal(top)
	if err != nil {
		return nil, invalid("the role definition cannot be encoded: %v", err)
	}
	jd := json.NewDecoder(bytes.NewReader(b))
	jd.DisallowUnknownFields()
	var r types.RoleV6
	if err := jd.Decode(&r); err != nil {
		return nil, invalid("%v", err)
	}
	if err := r.CheckAndSetDefaults(); err != nil {
		return nil, invalid("%v", err)
	}
	return &r, nil
}

// jsonable turns a decoded YAML value into one encoding/json accepts:
// string keys only, timestamps as RFC 3339 text.
func jsonable(v any) (any, error) {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			c, err := jsonable(vv)
			if err != nil {
				return nil, err
			}
			out[k] = c
		}
		return out, nil
	case map[any]any:
		return nil, invalid("mapping keys must be strings")
	case []any:
		out := make([]any, len(x))
		for i, vv := range x {
			c, err := jsonable(vv)
			if err != nil {
				return nil, err
			}
			out[i] = c
		}
		return out, nil
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano), nil
	}
	return v, nil
}

// Normalize renders r in its normal form: Teleport defaults applied, the
// revision dropped, keys sorted, two-space indentation. Equal definitions
// have equal normal forms.
func Normalize(r *types.RoleV6) (string, error) {
	c, ok := r.Clone().(*types.RoleV6)
	if !ok {
		return "", invalid("unsupported role type")
	}
	c.SetRevision("")
	if err := c.CheckAndSetDefaults(); err != nil {
		return "", invalid("%v", err)
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "", invalid("the role cannot be encoded: %v", err)
	}
	jd := json.NewDecoder(bytes.NewReader(b))
	jd.UseNumber()
	var v any
	if err := jd.Decode(&v); err != nil {
		return "", invalid("the role cannot be encoded: %v", err)
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(numbers(v)); err != nil {
		return "", invalid("the role cannot be encoded: %v", err)
	}
	if err := enc.Close(); err != nil {
		return "", invalid("the role cannot be encoded: %v", err)
	}
	return out.String(), nil
}

// numbers turns json.Number into int64 (or float64) so YAML writes plain numbers.
func numbers(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			x[k] = numbers(vv)
		}
	case []any:
		for i, vv := range x {
			x[i] = numbers(vv)
		}
	case json.Number:
		if n, err := strconv.ParseInt(string(x), 10, 64); err == nil {
			return n
		}
		if f, err := strconv.ParseFloat(string(x), 64); err == nil {
			return f
		}
		return string(x)
	}
	return v
}

// IsPreset reports a Teleport built-in role (research D6).
func IsPreset(r types.Role) bool { return teleportapi.IsPreset(r) }
