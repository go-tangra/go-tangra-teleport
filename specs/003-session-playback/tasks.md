# Tasks: Play recorded SSH sessions in the module

**Input**: [plan.md](plan.md), [spec.md](spec.md) · Tests are required
(constitution IV).

## Phase 1: Setup

- [ ] T001 Add `@xterm/xterm` pinned to an exact version in ui/package.json and ui/package-lock.json

## Phase 2: Foundational

- [ ] T002 Add permission `SessionsPlay = "sessions:play"` to internal/authz/authz.go (Permissions; not in workerAllowed/moduleAllowed)
- [ ] T003 Declare `GET /api/teleport/v1/clusters/{id}/sessions/{sid}/recording` (`x-freya-permission: sessions:play`, timeout 60s), schema `RecordingPage`, and `playable` on the session item in api/openapi/teleport.yaml
- [ ] T004 Add `StreamRecording(ctx, sid, startIndex)` to the Teleport client interface with the real implementation over `StreamSessionEvents`, the limited wrapper and the Fake in internal/teleportapi/recording.go, internal/teleportapi/fake_enroll.go
- [ ] T005 [P] Test the manifest gives `sessions:play` to the administrator role and the owner/admin grants only, in pkg/teleportmanifest/manifest_test.go

## Phase 3: US1 + US2 – watch a session, progressive loading (P1)

- [ ] T006 [P] [US1] Tests for page building (print/resize/start events, base64 output, page bounds of 1 MiB / 4000 events / 15 s, done, size limit, non-SSH refusal) in internal/recording/page_test.go
- [ ] T007 [P] [US1] Tests for the cursor (round trip, tamper, expiry, bound to tenant/user/cluster/session) in internal/recording/cursor_test.go
- [ ] T008 [US1] Implement page building in internal/recording/page.go
- [ ] T009 [US1] Implement the signed cursor in internal/recording/cursor.go
- [ ] T010 [US1] Implement `recording.Service.Page` (cluster client with `sessions:play`, sid validation, cursor, stream from index, error mapping R9) in internal/recording/service.go
- [ ] T011 [US1] Mount the route and map errors (400/404/409/410/413/422/429) in internal/httpapi/recording.go; wire the service in internal/httpapi/deps.go and internal/app/app.go
- [ ] T012 [US1] Set `playable` on SSH sessions in internal/auditlog/search.go
- [ ] T013 [P] [US1] Tests for the player model (timeline, speed, skip idle > 3 s, seek reproduces output up to t, resize) in ui/src/player/model.test.ts
- [ ] T014 [US1] Implement the player model in ui/src/player/model.ts
- [ ] T015 [US1] Implement SessionPlayer.vue (xterm, controls, progressive loading, prefetch, loading state on seek past loaded, stop on close) in ui/src/pages/clusters/SessionPlayer.vue; API call in ui/src/stores
- [ ] T016 [US1] Add the route `/teleport/clusters/:id/sessions/:sid/play` and the Play action on playable sessions (permission-gated) in ui/src/pages/clusters/tabs/SessionsTab.vue and the module router

## Phase 4: US3 – permission and audit (P1)

- [ ] T017 [P] [US3] Contract tests: 403 without `sessions:play`, 404 other tenant, one audit row per playback (none for later pages), 410 for a cursor of another user in tests/contract/recording_test.go
- [ ] T018 [US3] Record `session.played` on the first page in internal/recording/service.go
- [ ] T019 [US3] Per-process (8) and per-user (2) concurrency limits with 429 + Retry-After in internal/recording/limits.go (+ limits_test.go)
- [ ] T020 [P] [US3] Test that no recording content reaches logs, audit or events (SC-005) in internal/recording/service_test.go

## Phase 5: US4 – other kinds keep the link (P3)

- [ ] T021 [US4] Hide Play for non-playable sessions, keep the Teleport link for all, in ui/src/pages/clusters/tabs/SessionsTab.vue (+ test)

## Phase 6: Polish

- [ ] T022 [P] Help: sessions playback page and permissions table in docs/help/
- [ ] T023 [P] Spec 001 note: replay now in 003, in specs/001-teleport-cluster-management/spec.md assumptions
- [ ] T024 Integration test against Teleport 18: record a session, page through, compare output in tests/integration/recording_test.go
- [ ] T025 Run gates: go vet, staticcheck, go test, coverage gate, UI lint/tests/build

## Dependencies

T001–T004 before Phase 3; T006–T011 before T015; T017–T020 after T010/T011;
US4 after T016.
