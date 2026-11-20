# Tasks: Agent SSH enrollment (teleport module side)

Inventory and agent tasks (FR-008, FR-009, FR-012…014, US4) are in the
inventory repository, feature `038-teleport-join-delivery`.

## Phase 1: Foundation

- [X] T001 Depend on the inventory SDK with the 038 contract in `go.mod`
- [X] T002 `teleportapi.Client.CAPins` (real via `GetClusterCACert`, limiter, fake) and `CAPinsOf` in `internal/teleportapi/enroll.go`
- [X] T003 Permission `resources:enroll` (authz, worker set, manifest permission, operator role, CASL ability) and docs/help/reference/permissions.md
- [X] T004 `repo.Enrollment`, `repo.Enrollments` and states in `internal/repo/repo.go`
- [X] T005 Migration `internal/store/migrations/0004_enrollment.sql` (RLS, grants)
- [X] T006 memstore and `internal/repodb/enrollments.go`; conformance case `enrollments` in `internal/repotest/suite.go`
- [X] T007 Audit actions `teleport.enrollment.*`, target `enrollment`; event `teleport.enrollment.changed`

## Phase 2: User Story 1 - Enroll an inventory host (P1)

- [X] T010 [US1] Labels (FR-010) in `internal/enroll/labels.go`
- [X] T011 [US1] Targets, Create (refusal reasons, withdrawal on store failure) in `internal/enroll/service.go`
- [X] T012 [US1] Render: single-use Node token, `join_token` row, CA pins, version, labels; render budget 5
- [X] T013 [US1] `inventory.v1.TeleportJoinSource` server with the svc/inventory peer check in `internal/grpcapi/source.go`; policy rule `inventory-join-source` and its test
- [X] T014 [US1] HTTP routes and OpenAPI (`enrollment-targets`, `enrollments`); contract tests `tests/contract/enrollments_test.go`
- [X] T015 [US1] App wiring: lazy inventory connection, discovery `inventory` in `deploy/container.yaml`
- [X] T016 [US1] UI: `InventoryEnrollDialog.vue` from the Resources tab
- [X] T017 [US1] Security test with the redaction sentinel `tests/security/join_source_security_test.go`

## Phase 3: User Story 2 - Follow and retry (P2)

- [X] T020 [US2] Progress from `GetTeleportJoins` on list and in the leased `enrollment-sweep`; expiry of unknown items; no backward moves
- [X] T021 [US2] Confirmed inventory link on joined (retried until expiry)
- [X] T022 [US2] Cancel and Retry (routes, audit, UI)
- [X] T023 [US2] Help: docs/help/guides/enroll-resources.md, docs/help/reference/api.md

## Phase 4: User Story 3 - Label refresh (P3)

- [ ] T030 [US3] Re-render labels when inventory facts change and send a label update to the agent (needs an inventory label-update command)

## Phase 5: Integration

- [ ] T040 Run the repodb conformance suite and the redaction scan with Docker (`make test-integration`, `make redaction-scan`)
- [ ] T041 docker-compose: inventory `teleport_join` config and policies (go-tangra-docker)
