package enroll

import (
	"sort"
	"strings"
	"unicode/utf8"
)

// Label bounds (spec 002 FR-010): Teleport label keys and values, sized so
// the agent's teleport.yaml stays small.
const (
	MaxLabels     = 64
	maxLabelKey   = 63
	maxLabelValue = 255
	labelPrefix   = "tangra.io/"
	tagPrefix     = labelPrefix + "tag."
)

// Facts are the inventory facts a node is labelled with.
type Facts struct {
	HostID       string
	Hostname     string
	OSName       string
	OSVersion    string
	OSArch       string
	Manufacturer string
	Model        string
	Tags         map[string]string
}

// sanitizeKey keeps [A-Za-z0-9._/-] and replaces anything else with "_".
func sanitizeKey(k string) string {
	var b strings.Builder
	for _, r := range k {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._/-", r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// sanitizeValue drops control characters and invalid UTF-8 and trims to
// the value bound on a rune boundary.
func sanitizeValue(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(strings.ToValidUTF8(v, "")))
	if len(v) > maxLabelValue {
		v = v[:maxLabelValue]
		for !utf8.ValidString(v) {
			v = v[:len(v)-1]
		}
	}
	return v
}

// Labels computes the node labels from inventory facts: fixed tangra.io/*
// keys, then tangra.io/tag.<key> for each tag in key order, empty facts
// omitted, at most MaxLabels.
func Labels(f Facts) map[string]string {
	out := map[string]string{}
	add := func(k, v string) {
		k = sanitizeKey(k)
		v = sanitizeValue(v)
		if v == "" || len(k) > maxLabelKey || len(out) >= MaxLabels {
			return
		}
		if _, dup := out[k]; !dup {
			out[k] = v
		}
	}
	add(labelPrefix+"inventory-host", f.HostID)
	add(labelPrefix+"hostname", f.Hostname)
	add(labelPrefix+"os", f.OSName)
	add(labelPrefix+"os-version", f.OSVersion)
	add(labelPrefix+"arch", f.OSArch)
	add(labelPrefix+"manufacturer", f.Manufacturer)
	add(labelPrefix+"model", f.Model)
	keys := make([]string, 0, len(f.Tags))
	for k := range f.Tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.TrimSpace(k) == "" {
			continue
		}
		add(tagPrefix+strings.TrimSpace(k), f.Tags[k])
	}
	return out
}
