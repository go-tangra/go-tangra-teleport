# Implementation Plan: Play recorded SSH sessions in the module

**Branch**: `003-session-playback` | **Date**: 2026-11-23 | **Spec**: [spec.md](spec.md)

## Summary

A permitted user opens a recorded SSH session from the Sessions tab and
watches it in an xterm.js player. The module reads the recording live from
the cluster with the management identity (`StreamSessionEvents`), converts
print and resize events into compact chunks and relays them page by page
behind a signed cursor; it keeps nothing. Playback needs the new
`sessions:play` permission (administrators only) and the first page of each
playback writes one audit row.

## Technical context

- Go 1.26, existing layering: `teleportapi` (Teleport client wrapper + Fake),
  domain service behind `clusters.Service.Client` (authz + pooled client),
  `httpapi` (OpenAPI-declared routes, `x-freya-permission`), `audit.Recorder`.
- New package `internal/recording` (service, chunking, cursor, limits); new
  client method `teleportapi.Client.StreamRecording`.
- Teleport API (`github.com/gravitational/teleport/api`, pinned in go.mod):
  `Client.StreamSessionEvents(ctx, sid, startIndex)` → `session.start`
  (`TerminalSize "W:H"`), `print` (`Data`, `DelayMilliseconds`),
  `resize` (`TerminalSize`), `session.end`.
- UI: Vue 3 + `@go-tangra/ui`; new dependency `@xterm/xterm` pinned exactly
  (5.5.0). Portal CSP allows inline styles (xterm's DOM renderer).
- Storage: none. No migration.
- Management role: already has `session: [list, read]`
  (`internal/deploy/templates/tangra-manager-role.yaml.tmpl`, go-tangra-docker
  `configs/teleport/tangra-manager-role.yaml`), which is what reading a
  recording needs; FR-017 is satisfied without a role change. FR-018 still
  maps an access-denied stream to a named error.

## Constitution check

| Principle | How this plan complies |
| --- | --- |
| I. Secure by default | New permission held by administrators only; no worker or module access; recordings never stored |
| II. Zero trust | Recordings read with the cluster's own least-privilege identity; tenant checked by `clusters.Service.Client` |
| III. Boundary validation | `sid` and cursor validated; cursor HMAC-signed and bound to tenant, user, cluster, session; output size and page size bounded |
| IV. Test-first | Unit tests for chunking, cursor, limits, error mapping; contract test for the route (403/404/429/410); UI unit tests for the player model; Fake-backed tests for the stream |
| V. Observability & audit | One `session.played` audit row per playback; metrics with outcome only, never content |
| VI. Supply chain | One UI dependency, `@xterm/xterm`, pinned exactly, no add-ons |
| VII. Simplicity | No storage, no new service; stateless pages; per-process limits |

Result: pass, no deviations.

## Decisions (research)

| # | Decision | Choice | Why / alternatives |
| --- | --- | --- | --- |
| R1 | Source | `StreamSessionEvents(sid, startIndex)` on each page request, reading from `startIndex` | The only API that returns recordings; a single long stream would exceed the gateway route timeout (≤ 5 min) |
| R2 | Page format | JSON `{width, height, events: [[ms, "o", base64] \| [ms, "r", "WxH"]], next, done, bytes}`, `ms` from session start | asciicast-like and trivially replayable; base64 because output is not always UTF-8 |
| R3 | Page bounds | Stop a page at 1 MiB of output, 4000 events or 15 s of reading, whichever first | Keeps each response small and fast; the client prefetches the next page while playing |
| R4 | Cursor | Opaque `base64url(payload).hmac`, payload = tenant, user, cluster, session, next event index, bytes so far, expiry (1 h); HMAC-SHA256 with a per-process random key | Unforgeable, so pages after the first cannot be fetched without the audited first request; a restart or other replica answers 410 `playback_expired` and the player restarts (a new audited playback) — chosen over shared key config for simplicity |
| R5 | Audit | First page (no cursor) records `session.played` (cluster, sid) before streaming; later pages do not | FR-011; content never in the row |
| R6 | Kind check | Playable only if the stream starts with `session.start` without `kubernetes_cluster`; desktop/db/app sessions → 422 `not_playable` | FR-007; the list also hides Play for non-SSH kinds |
| R7 | Size limit | `bytes` (sum of output) > 500 MiB (config `recording.max_bytes`, lowerable) → 413 `recording_too_large` | FR-016 |
| R8 | Concurrency | Per process: 8 concurrent page reads; per user: 2; beyond → 429 `rate_limited` with Retry-After | FR-015 |
| R9 | Errors | Teleport NotFound → 404 `recording_not_found`; AccessDenied → 409 `recording_access_denied` (message names the role fix); unreachable → existing `cluster_unreachable` | FR-018, FR-019 |
| R10 | Total duration | From the list row when opened from it (passed as route query), else grows as pages load and is final at `done` | No cheap get-by-id for a session end event; direct links still work |
| R11 | Seek | Client keeps loaded events; seek = `reset()` + write all output up to t in one batch, then resume | Exact screen state (FR-003) without server keyframes |
| R12 | Rendering safety | xterm only, `linkHandler` off, no add-ons, no `allowProposedApi`; data written as bytes | FR-006: escape sequences affect only the terminal |
| R13 | Permission | `sessions:play` in OpenAPI and `authz`; administrator role gets it via `PermissionRefs()`; other roles are built from `:read` permissions, so they don't; not in `workerAllowed`/`moduleAllowed` | FR-009, FR-010 |

## Data model

No persistent entities. Transient:

- **Recording page** (response): `width`, `height` (initial terminal size,
  first page only), `events[]` (`[ms, "o", base64]` output, `[ms, "r",
  "WxH"]` resize), `next` (cursor, empty when `done`), `done`, `bytes`
  (output relayed so far).
- **Cursor** (opaque to the client): see R4.
- **Audit row** `session.played`: actor, tenant, resource `cluster/<id>`,
  detail `{session_id}`; outcome ok/denied/not_found.

## Contract

`GET /api/teleport/v1/clusters/{id}/sessions/{sid}/recording?cursor=`
— `x-freya-permission: sessions:play`, route timeout 60 s.

| Status | Reason | When |
| --- | --- | --- |
| 200 | — | a page (R2) |
| 400 | validation_failed | bad `sid` or malformed cursor |
| 403 | forbidden | no `sessions:play` |
| 404 | not_found / recording_not_found | cluster not in tenant / no recording |
| 409 | recording_access_denied | management identity cannot read recordings |
| 410 | playback_expired | cursor expired, other process, or bound to another user/session |
| 413 | recording_too_large | over the size limit |
| 422 | not_playable | not an SSH terminal session |
| 429 | rate_limited | concurrency bound |
| 503 | cluster_unreachable | as elsewhere |

The sessions list item gains `playable: bool` (SSH kind) for the UI.

## Project structure

```
internal/teleportapi/   recording.go (+ fake), limited wrapper
internal/recording/     service.go, page.go, cursor.go, limits.go (+ tests)
internal/httpapi/       recording.go (+ contract test in tests/contract)
internal/authz/         SessionsPlay
api/openapi/teleport.yaml  route + RecordingPage schema + playable
ui/src/pages/clusters/  SessionPlayer.vue, tabs/SessionsTab.vue (Play action)
ui/src/player/          model.ts (timeline, speed, idle skip, seek) + tests
docs/help/              sessions playback page, permissions table
```

## Quickstart (validation)

1. `make test` (Go), `npm run lint && npx vitest run` (UI).
2. Integration (`sg docker -c "make integration"`): record a session on the
   test Teleport 18 container, fetch all pages, check output equals the
   recording and the audit row exists once.
3. Manual, production: as admin open Teleport → cluster → Sessions → Play on
   an SSH session; check pause/speed/seek/skip idle; as a user with only
   `audit:read` confirm no Play and 403 on the route; check the audit list
   shows `session.played`.
