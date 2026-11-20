#!/usr/bin/env bash
# Principle VI / research D1: the module may depend on the Apache-2.0
# github.com/gravitational/teleport/api module only. The main Teleport module
# (github.com/gravitational/teleport, AGPL-3.0, which holds lib/ and tbot) and
# any other known AGPL module must never enter the module graph or the import
# graph. Fails with the offending module paths.
set -euo pipefail
cd "$(dirname "$0")/.."
# Known AGPL-3.0 modules (extend when a new one is identified).
AGPL_RE='^github\.com/gravitational/teleport( |$)|^github\.com/gravitational/teleport/(lib|tool|e)(/| |$)'
fail=0
mods=$(GOFLAGS=-mod=readonly go list -m all)
if bad=$(printf '%s\n' "$mods" | grep -E "$AGPL_RE"); then
  echo "license-check: AGPL module in the module graph:" >&2
  printf '  %s\n' "$bad" >&2
  fail=1
fi
# The import graph is checked too: a package path under teleport/lib could only
# come from the AGPL main module.
imports=$(GOFLAGS=-mod=readonly go list -deps -test ./... 2>/dev/null | grep '^github.com/gravitational/teleport' || true)
if bad=$(printf '%s\n' "$imports" | grep -vE '^github\.com/gravitational/teleport/api(/|$)' | grep -v '^$'); then
  echo "license-check: non-api Teleport package imported:" >&2
  printf '  %s\n' "$bad" >&2
  fail=1
fi
[[ $fail -eq 0 ]] && echo "license-check: ok ($(printf '%s\n' "$mods" | wc -l) modules, no AGPL module)"
exit $fail
