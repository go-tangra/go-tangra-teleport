# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report privately through GitHub's private vulnerability reporting on
[go-tangra/go-tangra-teleport](https://github.com/go-tangra/go-tangra-teleport/security/advisories/new).
Include a description, affected versions, and a proof of concept if you have
one. You will receive an acknowledgement within 2 business days.

Do not attach real Teleport identity files, join tokens, invite links or
audit-log exports to a report. Redact them, or reproduce the issue against a
throwaway Community Edition cluster.

## Response targets

Per the platform constitution (Development Workflow & Quality Gates):

- Confirmed vulnerabilities in supported versions are fixed in a **PATCH release
  within 72 hours** of confirmation.
- The changelog entry names the vulnerability, the affected versions, and every
  default that changed.

## Supported versions

| Version | Supported |
|---------|-----------|
| 4.x     | yes       |
| < 4.0   | no        |

## Security-relevant design points

- Management credentials (Teleport identity files) are kept only as `warden:`
  references; the module database never holds secret material.
- Outbound connections to tenant-supplied addresses go through `internal/netguard`
  (resolved-IP checks, pinned dialler, port allow-list; research D12).
- Only the Apache-2.0 `github.com/gravitational/teleport/api` module is used.
  `scripts/license-check.sh` fails the build if an AGPL Teleport module enters
  the module graph.

## Known, mitigated upstream issues

- **GO-2026-5471 / GHSA-jj45-xvq5-rhh9** (go-kratos `transport/http` falls back
  to `http.DefaultServeMux`): mitigated in the platform `transport/http.NewServer`.
  The allow-list entry in `scripts/vulncheck.sh` expires on 2026-12-31.
