package clusters

import (
	"strconv"
	"strings"
	"unicode"
)

// Teleport object names the later stories accept (users, roles, lock
// targets): 1 to 128 characters of letters, digits and . _ @ + - :,
// starting with a letter or digit. Stricter than Teleport, so a name never
// carries whitespace, control characters, path separators or template braces.
const MaxNameLength = 128

func nameChar(r rune, first bool) bool {
	if r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
		return true
	}
	return !first && strings.ContainsRune("._@+-:", r)
}

// ValidName checks one Teleport object name; field names it in the refusal.
func ValidName(field, s string) error {
	if s == "" || len(s) > MaxNameLength {
		return &FieldError{Field: field, Msg: "must be 1 to 128 characters"}
	}
	for i, r := range s {
		if !nameChar(r, i == 0) {
			return &FieldError{Field: field, Msg: "may contain only letters, digits and . _ @ + - : and must start with a letter or digit"}
		}
	}
	return nil
}

// ValidNames checks, de-duplicates and bounds a list of names (in order).
func ValidNames(field string, in []string, minN, maxN int) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if err := ValidName(field, s); err != nil {
			return nil, err
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) < minN || len(out) > maxN {
		if minN > 0 {
			return nil, &FieldError{Field: field, Msg: "must list 1 to " + strconv.Itoa(maxN) + " entries"}
		}
		return nil, &FieldError{Field: field, Msg: "must list at most " + strconv.Itoa(maxN) + " entries"}
	}
	return out, nil
}

// ValidText checks free text (a lock reason): trimmed, 1 to max bytes, no
// control characters.
func ValidText(field, s string, maxLen int) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxLen {
		return "", &FieldError{Field: field, Msg: "must be 1 to " + strconv.Itoa(maxLen) + " characters"}
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", &FieldError{Field: field, Msg: "must not contain control characters"}
		}
	}
	return s, nil
}
