package roleyaml

import (
	"fmt"
	"strings"
)

// contextLines is the unified-diff context.
const contextLines = 3

// maxCells bounds the line-matching table; larger changed regions are shown
// as one replacement.
const maxCells = 4 << 20

type op struct {
	kind byte // ' ', '-', '+'
	line string
}

func lines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.SplitAfter(strings.TrimSuffix(s, "\n"), "\n")
}

// edits is the line edit script from a to b: the common prefix and suffix,
// and a longest-common-subsequence match of the middle.
func edits(a, b []string) []op {
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	var out []op
	for _, l := range a[:pre] {
		out = append(out, op{' ', l})
	}
	ma, mb := a[pre:len(a)-suf], b[pre:len(b)-suf]
	if (len(ma)+1)*(len(mb)+1) > maxCells {
		for _, l := range ma {
			out = append(out, op{'-', l})
		}
		for _, l := range mb {
			out = append(out, op{'+', l})
		}
	} else {
		out = append(out, lcs(ma, mb)...)
	}
	for _, l := range a[len(a)-suf:] {
		out = append(out, op{' ', l})
	}
	return out
}

func lcs(a, b []string) []op {
	n, m := len(a), len(b)
	t := make([][]int32, n+1)
	for i := range t {
		t[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				t[i][j] = t[i+1][j+1] + 1
			} else {
				t[i][j] = max(t[i+1][j], t[i][j+1])
			}
		}
	}
	var out []op
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			out = append(out, op{' ', a[i]})
			i++
			j++
		case t[i+1][j] >= t[i][j+1]:
			out = append(out, op{'-', a[i]})
			i++
		default:
			out = append(out, op{'+', b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, op{'-', a[i]})
	}
	for ; j < m; j++ {
		out = append(out, op{'+', b[j]})
	}
	return out
}

// Diff is the unified diff from current to proposed ("" when equal), with
// three lines of context; the headers are "current" and "proposed".
func Diff(current, proposed string) string {
	if current == proposed {
		return ""
	}
	ops := edits(lines(current), lines(proposed))
	var sb strings.Builder
	sb.WriteString("--- current\n+++ proposed\n")
	// Line numbers (1-based) of ops[i] in a and b.
	ai, bi := make([]int, len(ops)+1), make([]int, len(ops)+1)
	ai[0], bi[0] = 1, 1
	for i, o := range ops {
		ai[i+1], bi[i+1] = ai[i], bi[i]
		if o.kind != '+' {
			ai[i+1]++
		}
		if o.kind != '-' {
			bi[i+1]++
		}
	}
	for i := 0; i < len(ops); {
		if ops[i].kind == ' ' {
			i++
			continue
		}
		start := max(0, i-contextLines)
		end := i
		// Extend while the next change is within 2×context of the last one.
		for end < len(ops) {
			if ops[end].kind != ' ' {
				end++
				continue
			}
			k := end
			for k < len(ops) && ops[k].kind == ' ' && k-end < 2*contextLines {
				k++
			}
			if k < len(ops) && ops[k].kind != ' ' {
				end = k
				continue
			}
			end = min(len(ops), end+contextLines)
			break
		}
		na, nb := 0, 0
		for _, o := range ops[start:end] {
			if o.kind != '+' {
				na++
			}
			if o.kind != '-' {
				nb++
			}
		}
		fmt.Fprintf(&sb, "@@ -%s +%s @@\n", rng(ai[start], na), rng(bi[start], nb))
		for _, o := range ops[start:end] {
			sb.WriteByte(o.kind)
			sb.WriteString(o.line)
			if !strings.HasSuffix(o.line, "\n") {
				sb.WriteString("\n\\ No newline at end of file\n")
			}
		}
		i = end
	}
	return sb.String()
}

// rng formats a hunk range; an empty range starts at the line before.
func rng(start, n int) string {
	if n == 0 {
		return fmt.Sprintf("%d,0", start-1)
	}
	return fmt.Sprintf("%d,%d", start, n)
}
