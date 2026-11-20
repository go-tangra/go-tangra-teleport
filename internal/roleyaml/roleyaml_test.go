package roleyaml

import (
	"errors"
	"strings"
	"testing"

	"github.com/gravitational/teleport/api/types"
)

const devV7 = `kind: role
version: v7
metadata:
  name: dev
  description: Developers
spec:
  allow:
    logins: [dev, '{{internal.logins}}']
    node_labels:
      env: [dev, staging]
  options:
    max_session_ttl: 8h
`

// The same role with keys in another order and other spacing.
const devV7Reordered = `version: v7
spec:
  options: { max_session_ttl: 8h0m0s }
  allow:
    node_labels: { env: [dev, staging] }
    logins:
      - dev
      - '{{internal.logins}}'
metadata: { description: Developers, name: dev }
kind: role
`

const opsV8 = `kind: role
version: v8
metadata: { name: ops }
spec:
  allow:
    logins: [root]
    node_labels: { '*': '*' }
`

func TestParseValidRoles(t *testing.T) {
	r, err := Parse([]byte(devV7))
	if err != nil {
		t.Fatal(err)
	}
	if r.GetName() != "dev" || r.GetVersion() != types.V7 || len(r.GetLogins(types.Allow)) != 2 || r.Spec.Options.MaxSessionTTL.Duration().Hours() != 8 {
		t.Fatalf("parsed %+v", r)
	}
	r, err = Parse([]byte(opsV8))
	if err != nil {
		t.Fatal(err)
	}
	if r.GetName() != "ops" || r.GetVersion() != types.V8 {
		t.Fatalf("parsed %+v", r)
	}
}

func TestParseRefusals(t *testing.T) {
	for name, src := range map[string]string{
		"empty":           "",
		"not yaml":        "kind: [role",
		"not a mapping":   "- kind: role",
		"user kind":       "kind: user\nversion: v2\nmetadata: {name: alice}\n",
		"no kind":         "version: v7\nmetadata: {name: dev}\n",
		"old version":     "kind: role\nversion: v6\nmetadata: {name: dev}\n",
		"no version":      "kind: role\nmetadata: {name: dev}\n",
		"no name":         "kind: role\nversion: v7\nmetadata: {}\n",
		"unknown field":   "kind: role\nversion: v7\nmetadata: {name: dev}\nspec: {allow: {loginz: [x]}}\n",
		"two documents":   devV7 + "---\n" + opsV8,
		"wrong type":      "kind: role\nversion: v7\nmetadata: {name: dev}\nspec: {allow: {logins: 5}}\n",
		"non-string keys": "kind: role\nversion: v7\nmetadata: {name: dev}\nspec: {allow: {node_labels: {1: x}}}\n",
		"bad option":      "kind: role\nversion: v7\nmetadata: {name: dev}\nspec: {options: {create_host_user_mode: 99}}\n",
		"bad label key":   "kind: role\nversion: v7\nmetadata: {name: dev, labels: {'bad key!': x}}\n",
	} {
		if _, err := Parse([]byte(src)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	big := devV7 + "# " + strings.Repeat("x", MaxBytes) + "\n"
	_, err := Parse([]byte(big))
	var e *Error
	if !errors.Is(err, ErrInvalid) || !errors.As(err, &e) || !strings.Contains(e.Msg, "64 KiB") {
		t.Fatalf("oversized: %v", err)
	}
}

func TestErrorsAreBounded(t *testing.T) {
	_, err := Parse([]byte("kind: role\nversion: v7\nmetadata: {name: dev}\nspec: {allow: {" + strings.Repeat("x", 4000) + ": 1}}\n"))
	if err == nil || len(err.Error()) > 600 || strings.ContainsAny(err.Error(), "\r\n") {
		t.Fatalf("error %q", err)
	}
}

func TestNormalizeIsStable(t *testing.T) {
	a, err := Parse([]byte(devV7))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte(devV7Reordered))
	if err != nil {
		t.Fatal(err)
	}
	b.SetRevision("rev-2") // revisions are not part of the definition
	na, err := Normalize(a)
	if err != nil {
		t.Fatal(err)
	}
	nb, _ := Normalize(b)
	if na != nb {
		t.Fatalf("key order or revision changed the normal form:\n%s\n----\n%s", na, nb)
	}
	if strings.Contains(na, "revision") || !strings.HasPrefix(na, "kind: role\n") {
		t.Fatalf("normal form:\n%s", na)
	}
	again, err := Parse([]byte(na))
	if err != nil {
		t.Fatalf("the normal form does not parse: %v\n%s", err, na)
	}
	if n2, _ := Normalize(again); n2 != na {
		t.Fatalf("normalizing is not idempotent:\n%s\n----\n%s", na, n2)
	}
}

// Numbers and timestamps survive the YAML → JSON → YAML round trip.
func TestNormalizeKeepsNumbersAndTimes(t *testing.T) {
	r, err := Parse([]byte("kind: role\nversion: v8\nmetadata: {name: n, expires: 2030-01-02T03:04:05Z}\nspec: {options: {max_connections: 3, max_sessions: 2}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := Normalize(r)
	if err != nil || !strings.Contains(n, "max_connections: 3\n") || !strings.Contains(n, "2030-01-02T03:04:05Z") {
		t.Fatalf("normal form %v:\n%s", err, n)
	}
	if again, err := Parse([]byte(n)); err != nil || again.Spec.Options.MaxConnections != 3 {
		t.Fatalf("reparse %v", err)
	}
	if IsPreset(nil) {
		t.Fatal("nil is preset")
	}
}

func TestDiff(t *testing.T) {
	a, _ := Parse([]byte(devV7))
	b, _ := Parse([]byte(strings.Replace(devV7, "8h", "12h", 1)))
	na, _ := Normalize(a)
	nb, _ := Normalize(b)
	if d := Diff(na, na); d != "" {
		t.Fatalf("no change gives a diff:\n%s", d)
	}
	d := Diff(na, nb)
	if !strings.HasPrefix(d, "--- current\n+++ proposed\n@@ ") || !strings.Contains(d, "-    max_session_ttl: 8h0m0s\n") || !strings.Contains(d, "+    max_session_ttl: 12h0m0s\n") {
		t.Fatalf("diff:\n%s", d)
	}
	if Diff(na, nb) != d {
		t.Fatal("the diff is not stable")
	}
	if c := Diff("", nb); !strings.HasPrefix(c, "--- current\n+++ proposed\n@@ -0,0 +1,") || strings.Contains(c, "\n-") {
		t.Fatalf("creation diff:\n%s", c)
	}
	// Changes far apart give separate hunks with three lines of context.
	long := func(change int) string {
		var lines []string
		for i := range 40 {
			l := "line " + string(rune('a'+i%26))
			if i == change || i == 35 && change >= 0 {
				l += " changed"
			}
			lines = append(lines, l)
		}
		return strings.Join(lines, "\n") + "\n"
	}
	if h := strings.Count(Diff(long(-1), long(2)), "\n@@ "); h != 2 {
		t.Fatalf("hunks %d:\n%s", h, Diff(long(-1), long(2)))
	}
}

func TestIsPreset(t *testing.T) {
	r, _ := Parse([]byte(devV7))
	if IsPreset(r) {
		t.Fatal("a custom role is preset")
	}
	r.SetStaticLabels(map[string]string{types.TeleportInternalResourceType: types.PresetResource})
	if !IsPreset(r) {
		t.Fatal("the preset label is not detected")
	}
}
