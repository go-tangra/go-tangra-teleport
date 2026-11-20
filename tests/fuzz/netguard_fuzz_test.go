// Package fuzz holds the fuzz targets of every parser that sees untrusted
// input (plan Testing; Constitution IV). `make fuzz` runs each for FUZZTIME;
// the seed corpus runs in the unit suite.
package fuzz

import (
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
)

// FuzzParseHostPort: a cluster proxy address is tenant input. Whatever the
// input, the parser either refuses it or returns a lower-case host without
// separators or control bytes and a non-zero port that round-trip through
// net.JoinHostPort / ParseHostPort unchanged.
func FuzzParseHostPort(f *testing.F) {
	for _, s := range []string{"teleport.example.com", "teleport.example.com:3080", "[2606:4700::1]:443", "8.8.8.8",
		"127.0.0.1:443", "host:0", "[::1", "a..b", "user@host:443", "xn--bcher-kva.example", "\x00", "[fe80::1%eth0]:443"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		host, port, err := netguard.ParseHostPort(in, 443)
		if err != nil {
			if host != "" || port != 0 {
				t.Fatalf("refusal returned values: %q %d", host, port)
			}
			return
		}
		if host == "" || port == 0 {
			t.Fatalf("accepted %q as %q:%d", in, host, port)
		}
		if host != strings.ToLower(host) || strings.ContainsAny(host, "/@?#% \t\r\n[]") {
			t.Fatalf("host %q from %q is not canonical", host, in)
		}
		for _, r := range host {
			if r < 0x21 || r > 0x7e {
				t.Fatalf("host %q from %q carries a non-printable byte", host, in)
			}
		}
		again := net.JoinHostPort(host, strconv.Itoa(int(port)))
		h2, p2, err := netguard.ParseHostPort(again, 1)
		if err != nil || h2 != host || p2 != port {
			t.Fatalf("round trip of %q: %q %d %v", again, h2, p2, err)
		}
	})
}
