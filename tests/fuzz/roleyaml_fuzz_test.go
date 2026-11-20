package fuzz

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/roleyaml"
)

// FuzzRoleYAML: a role definition is tenant input. Whatever the bytes, the
// parser never panics and refuses only with roleyaml.ErrInvalid (bounded, one
// line). An accepted role is a v7/v8 role whose normal form parses again to
// the same normal form, and a diff against itself is empty.
func FuzzRoleYAML(f *testing.F) {
	for _, s := range []string{
		"kind: role\nversion: v7\nmetadata: {name: dev}\nspec: {allow: {logins: [dev]}}\n",
		"kind: role\nversion: v8\nmetadata: {name: ops}\nspec: {allow: {node_labels: {'*': '*'}}, options: {max_session_ttl: 8h}}\n",
		"kind: user\nversion: v2\nmetadata: {name: alice}\n",
		"kind: role\nversion: v7\nmetadata: {name: dev}\n---\nkind: role\n",
		"&a [*a]", "{", "", "\x00\xff", strings.Repeat("a: ", 1000),
		"kind: role\nversion: v7\nmetadata: {name: dev, expires: 2030-01-01T00:00:00Z}\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		r, err := roleyaml.Parse(raw)
		if err != nil {
			if !errors.Is(err, roleyaml.ErrInvalid) {
				t.Fatalf("unexpected error class: %v", err)
			}
			if len(err.Error()) > 600 || strings.ContainsAny(err.Error(), "\r\n") {
				t.Fatalf("unbounded error %q", err)
			}
			return
		}
		if len(raw) > roleyaml.MaxBytes || (r.GetVersion() != "v7" && r.GetVersion() != "v8") || r.GetName() == "" {
			t.Fatalf("accepted %d bytes, version %q, name %q", len(raw), r.GetVersion(), r.GetName())
		}
		n, err := roleyaml.Normalize(r)
		if err != nil {
			t.Fatalf("normalize: %v", err)
		}
		again, err := roleyaml.Parse([]byte(n))
		if err != nil {
			t.Fatalf("the normal form does not parse: %v\n%s", err, n)
		}
		if n2, _ := roleyaml.Normalize(again); n2 != n {
			t.Fatalf("not idempotent:\n%s\n----\n%s", n, n2)
		}
		if d := roleyaml.Diff(n, n); d != "" {
			t.Fatalf("self diff:\n%s", d)
		}
	})
}
