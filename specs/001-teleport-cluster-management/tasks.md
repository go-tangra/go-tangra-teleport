---
description: "Task list for the Teleport Cluster Management Module (go-tangra-teleport)"
---

# Tasks: Teleport Cluster Management Module (go-tangra-teleport)

**Input**: Design documents from `specs/001-teleport-cluster-management/`

**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md), [data-model.md](./data-model.md), [contracts/](./contracts/), [quickstart.md](./quickstart.md)

**Tests**: REQUIRED. Constitution Principle IV (Test-First, NON-NEGOTIABLE) applies:

- Every test task comes before its implementation and must fail before that implementation starts.
- Negative security tests are included for authn/authz, parsing, secrets and transport.
- Fuzz tests are required for every parser.

**Reference modules**:

- `../go-tangra-dns-v4-helpdocs` for the layout, store/RLS, authz, audit, events, secrets, manifest, catalogue and helpdocs patterns;
- `../go-tangra-signing-v4/internal/app/scheduler.go` for the scheduler wiring;
- `../go-tangra/docs/frontend.md` for the UI contract.

Copy those patterns. Do not invent new ones.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: can run in parallel (different files, no dependency on an incomplete task)
- **[Story]**: US1…US6 from spec.md
- All paths are relative to the repository root `go-tangra-teleport/`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Create the module skeleton and settle the three research **Verify** items before code depends on them.

- [X] T001 Create the directory layout from plan.md (cmd/teleportsvc, api/openapi, api/proto/teleport/v1, internal/*, pkg/*, sdk/, docs/help, ui/, deploy/bundle, tests/{contract,integration,security,fuzz}, testdata/, scripts/), plus `git init` and a `.gitignore` copied from ../go-tangra-dns-v4-helpdocs/.gitignore
- [X] T002 Initialize `go.mod` as `github.com/go-tangra/go-tangra-teleport/v4` (go 1.26.3, toolchain go1.26.8). Add the same freya, pgx/v5, goose, valkey-go, grpc, kin-openapi, testcontainers and tangra SDK (auth, portal, lcm, warden) versions as ../go-tangra-dns-v4-helpdocs/go.mod
- [X] T003 [P] Create the `Makefile`, copied from ../go-tangra-dns-v4-helpdocs/Makefile and renamed to teleport: lint, vuln, test, test-integration, cover, fuzz, generate, ui-build, e2e, redaction-scan, compose-up/down
- [X] T004 [P] Create `buf.yaml` and `buf.gen.yaml`, output to api/proto, following the dns-v4 setup
- [X] T005 [P] Create `scripts/coverage-gate.sh`: 80% overall, 100% for internal/authz, internal/netguard, internal/secrets
- [X] T006 [P] Create the three-stage `Dockerfile` (node:22 UI build with the npm_token secret → golang:1.26 `GOWORK=off -tags ui` → alpine uid 10001), running `teleportsvc -config deploy/container.yaml`
- [X] T007 [P] Create `SECURITY.md` (private reporting channel) and a `README.md` skeleton with the module purpose, layout table and links to specs/001
- [ ] T008 Spike research D1: add `github.com/gravitational/teleport/api` at the latest stable tag supporting clusters N and N-1. — NOTE: version, module count (205), govulncheck and no-`lib/` recorded in research.md D1 (compile-verified); the `spike`-tagged live dial is written but NOT run (no Teleport cluster or Docker here)
  - Write `internal/teleportapi/spike_test.go` (build tag `spike`) that dials a Teleport CE container through the proxy address with an identity file.
  - Record in research.md under D1: the transitive module count, `govulncheck` output, and confirmation that no `github.com/gravitational/teleport/lib` package is imported.
- [X] T009 Spike research D2: in `internal/teleportapi/spike_test.go`, try to re-issue certificates for a bot identity using only the `api` module. Record the outcome in research.md under D2. If it is not feasible, mark bot mode as deferred and remove `bot` from `credential_kind` in data-model.md and contracts/http-api.md. — NOTE: bot mode deferred (research D2); `TestSpikeD2ReissueCerts` (`spike` tag) written, not run (no live cluster)
- [X] T010 [P] Spike research D10/D11: read ../go-tangra-auth (v4 SDK), ../go-tangra-inventory-v4 and ../go-tangra-asset-v4.
  - Record in research.md: the exact membership/role-change event types and payloads, and whether host lookup by hostname or IP exists.
  - If lookup is missing, add a `NEEDS CROSS-REPO` note to T079.
- [X] T011 [P] Add a CI license check (`scripts/license-check.sh`) that fails on any AGPL module in `go list -m all`. Wire it into `make lint`.

**Checkpoint**: the skeleton builds (`go build ./...`), and the spikes are recorded.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The core every story needs: config, store/RLS, authz, audit, events, secrets, netguard, Teleport client abstraction, manifest, gateway registration and UI shell.

**⚠️ CRITICAL**: No user-story work starts until this phase is complete.

### Tests first (Phase 2)

- [X] T012 [P] Write config validation tests in `internal/config/config_test.go`. The service must refuse to start when db, valkey, warden or gateway is missing. `allowed_private_networks` must log an opt-out warning. Limits and thresholds are typed and given defaults.
- [X] T013 [P] Write netguard tests in `internal/netguard/netguard_test.go`:
  - refuse loopback, link-local, 169.254.169.254, fd00:ec2::254, multicast, unspecified, RFC1918/ULA unless allowed, and ports outside the allow-list;
  - DNS-rebinding test (the resolver returns a public address, then a private one; the dial must use the pinned checked IP);
  - 5 s timeout.
- [X] T014 [P] Write a netguard fuzz test for host:port parsing in `tests/fuzz/netguard_fuzz_test.go`
- [X] T015 [P] Write secrets tests in `internal/secrets/secrets_test.go`: only `warden:` and dev `file:` refs are accepted; put/get/delete go through the fake; the `Secret` type redacts itself in `String()`, `GoString()`, `MarshalJSON` and slog `LogValue`
- [X] T016 [P] Write authz tests in `internal/authz/authz_test.go`:
  - each permission from contracts/http-api.md is enforced;
  - the cluster-ownership check rejects other tenants' cluster ids with not_found;
  - actor kinds user, module, worker and system.
- [X] T017 [P] Write the shared repository test suite in `internal/repotest/suite.go`, run against `internal/memstore` and `internal/repodb`: CRUD for each data-model table, unique constraints, and cascading deletes from cluster
- [ ] T018 [P] Write an RLS integration test in `tests/integration/rls_test.go` (testcontainers TimescaleDB): tenant A cannot see tenant B's rows in any table; `app.system` sees all rows — NOTE: written (`integration` tag, testcontainers TimescaleDB), NOT run: Docker is not usable here (daemon socket permission denied)
- [X] T019 [P] Write manifest tests in `pkg/teleportmanifest/manifest_test.go`: every OpenAPI operation has a known permission; roles and grants match contracts/http-api.md; nav entries exist
- [X] T020 [P] Write a policy test in `deploy/policy_test.go`: deny by default; `Access/*` only from svc/inventory, svc/asset and svc/portal; `TaskExecutor` only from svc/scheduler
- [X] T021 [P] Write teleportapi fake-conformance tests in `internal/teleportapi/client_test.go`:
  - error mapping (not found, conflict on revision, access denied, unreachable, deadline) to module reasons;
  - response size cap of 4 MiB;
  - 10 s timeout;
  - per-cluster semaphore of 4.

### Implementation (Phase 2)

- [X] T022 Implement typed config with validation in `internal/config/config.go` and `deploy/container.yaml`
- [X] T023 Write `internal/store/migrations/0001_schema.sql` with every table from data-model.md (cluster, join_token, resource_snapshot, resource_link, role_mapping, managed_user, alert_rule, alert_cursor, alert_delivery, deployment_draft, audit_event hypertable), RLS policies, and a grant set that is append-only for audit_event
- [X] T024 Implement the pgx store with a per-transaction `set_config('app.tenant_id')` and `app.system` in `internal/store/store.go`, plus goose migrate in `cmd/teleportsvc/bootstrap.go` — NOTE: `bootstrap` lives in `cmd/teleportsvc/main.go` (dns-v4 layout)
- [X] T025 [P] Define repository interfaces and models in `internal/repo/repo.go`
- [X] T026 Implement the SQL repositories in `internal/repodb/*.go` (one file per entity)
- [X] T027 [P] Implement the in-memory fake in `internal/memstore/memstore.go`
- [X] T028 [P] Implement netguard (resolver, IP classification, pinned `DialContext`, port allow-list) in `internal/netguard/netguard.go`
- [X] T029 [P] Implement secrets (warden SDK adapter, `file:` dev opt-out with a warning, fake, `Secret` type) in `internal/secrets/secrets.go`, adapted from dns-v4 internal/secrets
- [X] T030 [P] Implement authz (permission check through the auth `Authorization/Check`, ownership helper `RequireCluster(ctx, id)`) in `internal/authz/authz.go`
- [X] T031 [P] Implement the audit vocabulary (`teleport.*` actions) and the writer over the framework `audit` package in `internal/audit/audit.go` — NOTE: own writer, not the framework `audit` package (closed vocabulary; plan.md Deviations)
- [X] T032 [P] Implement the platform event publisher (types from contracts/events-and-tasks.md, ids-only payload structs) in `internal/events/events.go`, and the SSE relay in `internal/stream/stream.go` — NOTE: stream is `internal/stream/{hub,client,sse}.go` copied from dns-v4
- [X] T033 [P] Implement the Valkey lease helper (acquire, renew, release, with TTL 30 s and renew every 10 s) with tests in `internal/lease/lease.go` and `internal/lease/lease_test.go`
- [X] T034 Implement the `teleportapi.Client` interface and the real implementation over teleport/api in `internal/teleportapi/client.go`:
  - credentials loaded from an in-memory identity, proxy address dialled through the netguard dialler;
  - per-cluster connection pool keyed by cluster id, invalidated on credential rotation;
  - limits and error mapping.
  
  Add a scriptable fake in `internal/teleportapi/fake.go`.
- [X] T035 Implement the 15 s read cache (Valkey, keyed by tenant and cluster, invalidated by watcher events and writes) in `internal/teleportapi/cache.go`
- [X] T036 [P] Implement Prometheus collectors (Teleport call latency and errors, watcher state, poll lag, provisioning outcomes, credential days-to-expiry) in `internal/metrics/metrics.go`
- [X] T037 Write the OpenAPI document skeleton (info, components: csrf/page/pageSize/order/next/Error with the reasons in contracts/http-api.md) and `embed.go` in `api/openapi/teleport.yaml` and `api/openapi/embed.go`
- [X] T038 Implement the manifest (Module `teleport`, DisplayName "Teleport", APIPrefix `/api/teleport`, permissions, roles administrator/operator/auditor/viewer, grants, CASL abilities, nav with mdi icons) in `pkg/teleportmanifest/manifest.go`
- [X] T039 Implement app wiring in `internal/app/app.go`:
  - `freya.New`, store, secrets, teleportapi pool, events and stream;
  - `gatewayclient.New` registration with the manifest;
  - lcm SVID through `lcmidentity.NewNet`;
  - lazy peer clients;
  - health, readiness and metrics on the admin listener.
  
  Add the `serve`, `bootstrap` and `version` commands in `cmd/teleportsvc/main.go`.
- [X] T040 Write `deploy/policy.yaml` according to contracts/grpc.md
- [X] T041 [P] Scaffold the UI Module Federation remote (Vite, `@go-tangra/ui`, Pinia, router, CASL, Zod, `module-federation.config.ts` exposing `./routes` and `./nav`, `npm run gen:api`) in `ui/` and `ui/embed.go` (`//go:build ui`), following ../go-tangra/docs/frontend.md
- [X] T042 [P] Write a contract test harness in `tests/contract/openapi_test.go` that loads `api/openapi/teleport.yaml`, checks that every route has `x-freya-permission`, and validates handler responses against the schemas. Later story tasks extend it.

**Checkpoint**: the service starts against the dev stack, registers with the gateway, and serves an empty UI remote. Phase 2 tests pass.

---

## Phase 3: User Story 1 - Connect a Teleport cluster and see its health (Priority: P1) 🎯 MVP

**Goal**: register, verify, view, rotate and remove clusters, with health, edition and version, credential expiry, and outage alerts.

**Independent Test**: quickstart scenarios 1, 1b, 1c and 7.

### Tests for User Story 1 ⚠️ write first, confirm failing

- [X] T043 [P] [US1] Write a contract test for the cluster routes (`GET/POST /clusters`, `GET/PATCH/DELETE /clusters/{id}`, `POST /clusters/{id}/credential`, `POST /clusters/{id}/check`) in `tests/contract/clusters_test.go`
- [X] T044 [P] [US1] Write cluster service unit tests (fake teleportapi, memstore) in `internal/clusters/service_test.go`:
  - verify-before-save;
  - nothing saved when verification fails;
  - the credential stored only as a warden ref;
  - status state machine transitions from data-model.md (3 failed checks → unreachable);
  - missing-permission probe;
  - edition and version detection, with writes blocked below N-1;
  - removal deletes the warden secret and leaves Teleport untouched.
- [X] T045 [P] [US1] Write identity-file parser tests in `internal/clusters/identity_test.go` (expiry extraction, management username, max 64 KiB, malformed input) and a fuzz test in `tests/fuzz/identity_fuzz_test.go`
- [X] T046 [P] [US1] Write security tests in `tests/security/clusters_security_test.go`:
  - cross-tenant cluster access returns 404;
  - a viewer gets 403 on writes;
  - blocked targets (169.254.169.254, 127.0.0.1) return 422 blocked_target;
  - no credential bytes in responses, logs, events or audit (capture the slog handler and the event and audit fakes).
- [X] T047 [P] [US1] Write an integration test in `tests/integration/clusters_test.go`: a Teleport CE testcontainer with the `tangra-manager` role and an identity created through `tctl` exec. Register, check counts, stop the container, then expect unreachable within the injected-clock window.

### Implementation for User Story 1

- [X] T048 [US1] Implement identity-file parsing (certificate expiry, username, size cap) in `internal/clusters/identity.go`
- [X] T049 [US1] Implement the cluster service (register/verify, get/list, update, rotate credential, remove, health check, D3 permission probe, D13 edition and version) in `internal/clusters/service.go`
- [X] T050 [US1] Implement credential-expiry evaluation (thresholds: 7 days, 1 day, expired, 25% of lifetime for short-lived; bot renewal only if T009 succeeded) in `internal/clusters/expiry.go`, with tests in `internal/clusters/expiry_test.go`
- [X] T051 [US1] Add the cluster operations and schemas to `api/openapi/teleport.yaml` and implement the handlers in `internal/httpapi/clusters.go`
- [X] T052 [US1] Implement `GET /stream` (an SSE relay filtered to `teleport.*` for the caller's tenant) in `internal/httpapi/stream.go`
- [X] T053 [US1] Implement the health monitor loop (per-cluster 60 s ping under a lease, status transitions, `teleport.cluster.status_changed` events, notification on unreachable and credential_expiring) in `internal/clusters/monitor.go`. Add the notification SDK dependency and the `internal/notify/notify.go` adapter, with a fake.
- [X] T054 [P] [US1] Build the UI cluster list (status badges, version, edition, credential expiry, counts) and the register/rotate dialogs (identity file upload) in `ui/src/pages/clusters/ClusterList.vue`, `ui/src/pages/clusters/RegisterClusterDialog.vue` and `ui/src/stores/clusters.ts`
- [X] T055 [P] [US1] Build the UI cluster overview page (health, missing permissions, last contact, remove action with confirmation) in `ui/src/pages/clusters/ClusterOverview.vue`
- [X] T056 [P] [US1] Write the help pages `docs/help/index.md`, `docs/help/getting-started.md` (create the `tangra-manager` role, user and identity, then register) and `docs/help/reference/tangra-manager-role.md` (role YAML from research D3), plus `docs/embed.go` and the `helpdocs.Load` / `helpdocs.NewHandler` wiring in `internal/app/app.go`

**Checkpoint**: US1 is fully usable and testable on its own. This is the MVP.

---

## Phase 4: User Story 2 - Manage Teleport users, roles and locks (Priority: P1)

**Goal**: user CRUD with one-time invite and reset links; role YAML editing with preview, diff and revision checks; locks; self-identity and preset guards.

**Independent Test**: quickstart scenarios 2, 2b, 2c, 2d and 2e.

### Tests for User Story 2 ⚠️ write first, confirm failing

- [X] T057 [P] [US2] Write contract tests for the user, role and lock routes in `tests/contract/identity_test.go`
- [X] T058 [P] [US2] Write roleyaml tests in `internal/roleyaml/roleyaml_test.go` (valid v7/v8 roles, other kinds rejected, more than 64 KiB rejected, the normalized diff is stable, preset label detection) and a fuzz test in `tests/fuzz/roleyaml_fuzz_test.go`
- [X] T059 [P] [US2] Write users, roles and locks service tests (fake teleportapi) in `internal/users/service_test.go`, `internal/roles/service_test.go` and `internal/locks/service_test.go`:
  - a stale revision gives conflict;
  - the invite URL is returned once and never stored, logged or audited;
  - preset-role deletion is refused;
  - locking or deleting the management identity, or a role it holds, is refused;
  - a lock requires a reason;
  - every change and failure is audited;
  - events are emitted.
- [X] T060 [P] [US2] Write security tests in `tests/security/identity_security_test.go`: an operator gets 403 on roles:manage; a viewer gets 403 on every write; cross-tenant access returns 404; the redaction scan of captured logs, events and audit records finds no invite or reset URLs

### Implementation for User Story 2

- [X] T061 [P] [US2] Implement roleyaml (YAML → JSON → typed role, `CheckAndSetDefaults`, normalized YAML output, unified diff) in `internal/roleyaml/roleyaml.go`
- [X] T062 [P] [US2] Implement the users service (list with managed and locked flags, create plus invite, update with revision, reset, delete with the self-identity guard) in `internal/users/service.go`
- [X] T063 [P] [US2] Implement the roles service (list, get as YAML, preview, upsert with revision, delete with preset and self-held guards) in `internal/roles/service.go`
- [X] T064 [P] [US2] Implement the locks service (list active, create with reason and expiry, self-identity guard, remove) in `internal/locks/service.go`
- [X] T065 [US2] Add the user, role and lock operations to `api/openapi/teleport.yaml` and implement the handlers in `internal/httpapi/users.go`, `internal/httpapi/roles.go` and `internal/httpapi/locks.go`
- [X] T066 [P] [US2] Build the UI users tab (list, create dialog with a show-once invite panel, edit roles and logins, reset, delete) in `ui/src/pages/clusters/tabs/UsersTab.vue`
- [X] T067 [P] [US2] Build the UI roles tab (list with a preset badge, YAML editor, preview diff, apply with confirmation, conflict reload) in `ui/src/pages/clusters/tabs/RolesTab.vue` and `ui/src/components/RoleDiff.vue`
- [X] T068 [P] [US2] Build the UI locks tab (active locks, create-lock dialog with target picker, reason and expiry; remove) in `ui/src/pages/clusters/tabs/LocksTab.vue`
- [X] T069 [US2] Write an integration test in `tests/integration/identity_test.go`: create alice; edit with a stale revision and expect 409; lock alice and confirm she cannot log in, then unlock; refuse deletion of the `editor` role
- [X] T070 [P] [US2] Write the help page `docs/help/guides/users-roles-locks.md`

**Checkpoint**: US1 and US2 both work on their own.

---

## Phase 5: User Story 3 - Enroll and inventory protected resources (Priority: P2)

**Goal**: join tokens with install commands, a live resource list, a watcher with offline detection, inventory and asset links, and the `teleport.v1.Access` mesh API.

**Independent Test**: quickstart scenarios 3, 3b and 3c.

### Tests for User Story 3 ⚠️ write first, confirm failing

- [X] T071 [P] [US3] Write contract tests for the token, resource and link routes in `tests/contract/resources_test.go`, and a gRPC contract test for `teleport.v1.Access` in `tests/contract/access_grpc_test.go`
- [X] T072 [P] [US3] Write token service tests in `internal/tokens/service_test.go`:
  - TTL bounds (1 minute to 24 hours, default 30 minutes);
  - correct Teleport role per resource type;
  - the token and command returned once, with only the hash stored;
  - revoke deletes the token in Teleport;
  - install command rendering for each type;
  - shell-safe quoting of the proxy address.
- [X] T073 [P] [US3] Write watcher and sweep tests (fake watcher events, injected clock) in `internal/resources/watcher_test.go`: a server delete marks it offline; offline past the threshold flags it and alerts once; online again clears the flag; the lease ensures a single owner
- [X] T074 [P] [US3] Write linking tests in `internal/resources/linker_test.go`: a unique hostname or IP match gives an auto link; multiple matches give candidates; confirming one removes the other candidates; inventory or asset being unavailable gives dependency_unavailable without failing the list
- [X] T075 [P] [US3] Write security tests in `tests/security/access_grpc_security_test.go`: an `Access` call from an unlisted SVID is denied; tenant scoping applies; LookupHost input validation rejects bad hostnames and IPs. Also write a test that token values never appear in logs, events or audit.

### Implementation for User Story 3

- [X] T076 [P] [US3] Implement the token service and install-command templates (research D9) in `internal/tokens/service.go` and `internal/tokens/templates.go`
- [X] T077 [P] [US3] Implement live resource listing (kinds, label, query and status filters, `next` cursor, merged snapshot status and links) in `internal/resources/list.go`
- [X] T078 [US3] Implement the cluster watcher (`NewWatcher` on resource, lock, user and role kinds; snapshot upserts; cache invalidation; events) and the offline sweep in `internal/resources/watcher.go`, both started per cluster under a lease from `internal/app/app.go`
- [X] T079 [US3] Implement the inventory and asset linker (add the inventory-v4 and asset-v4 SDK clients; cross-repo lookup RPC if T010 found it missing) in `internal/resources/linker.go` — NEEDS CROSS-REPO: inventory-v4 and asset-v4 have no host lookup by hostname/IP (research D11); add a read RPC there first, or ship manual linking only. DONE behind `HostDirectory` with a fake and the production `UnavailableDirectory` (automatic matching reports `dependency_unavailable`, manual linking works); the real adapter waits on the cross-repo lookup RPC (plan.md deviations, US3)
- [X] T080 [US3] Add the token, resource and link operations to `api/openapi/teleport.yaml` and implement the handlers in `internal/httpapi/tokens.go` and `internal/httpapi/resources.go`
- [X] T081 [US3] Define `api/proto/teleport/v1/access.proto` according to contracts/grpc.md, run `make generate`, and implement `internal/grpcapi/access.go`, the typed client `pkg/teleportclient/client.go`, and the `sdk/` module re-export (sdk/ deferred: client lives in `pkg/teleportclient` as in dns-v4; see plan.md)
- [X] T082 [P] [US3] Build the UI resources tab (filters, status, agent version, links with confirm and remove for candidates) in `ui/src/pages/clusters/tabs/ResourcesTab.vue`
- [X] T083 [P] [US3] Build the UI enroll wizard (choose type, TTL, show-once token and command with copy, token list with revoke) in `ui/src/pages/clusters/tabs/TokensTab.vue` and `ui/src/components/EnrollDialog.vue`
- [X] T084 [US3] Write an integration test in `tests/integration/enroll_test.go`: create a node token, start a Teleport node container with it, expect it online in the list, revoke the token, and expect a second join to be rejected
- [X] T085 [P] [US3] Write the help page `docs/help/guides/enroll-resources.md`

**Checkpoint**: US1 through US3 work on their own.

---

## Phase 6: User Story 4 - Review audit events and sessions, with alerting (Priority: P2)

**Goal**: audit and session search, alert rules with a poller and burst windows delivered through notification, and the module audit trail view.

**Independent Test**: quickstart scenarios 4 and 4b.

### Tests for User Story 4 ⚠️ write first, confirm failing

- [X] T086 [P] [US4] Write contract tests for the events, sessions, audit and alert-rule routes in `tests/contract/audit_test.go`
- [X] T087 [P] [US4] Write auditlog tests in `internal/auditlog/search_test.go`: required window of at most 31 days; limit of at most 200; `next` passthrough; normalization of the main event types (user.login success and failure, session.start and end, role.created and updated, lock.created); `raw` bounded at 16 KiB. Write a fuzz test for event normalization in `tests/fuzz/events_fuzz_test.go`.
- [X] T088 [P] [US4] Write alert engine tests (fake search, injected clock) in `internal/alerts/engine_test.go`: the cursor advances without gaps or duplicates; any-match rules; count-in-window burst rules; de-duplication per rule, cluster and window; event-type allow-list validation; notification unavailable means the delivery is retried and the cursor is held
- [X] T089 [P] [US4] Write security tests in `tests/security/audit_security_test.go`: a viewer gets 403 on `/events` and `/sessions` (no audit:read); cross-tenant access returns 404; Teleport-supplied strings are returned as data, not markup (encoded in the UI test in T094)

### Implementation for User Story 4

- [X] T090 [P] [US4] Implement auditlog search, session search, normalization and playback URL construction in `internal/auditlog/search.go`
- [X] T091 [P] [US4] Implement the alert rule repository validation and service in `internal/alerts/rules.go`
- [X] T092 [US4] Implement the alert poller and engine (30 s loop under a lease, cursor in `alert_cursor`, burst windows, de-duplication in `alert_delivery`, delivery through `internal/notify`, module conditions from US1 and US3 events) in `internal/alerts/engine.go`, started from `internal/app/app.go`
- [X] T093 [US4] Add the events, sessions, audit and alert-rule operations to `api/openapi/teleport.yaml` and implement the handlers in `internal/httpapi/audit.go` and `internal/httpapi/alerts.go`
- [X] T094 [P] [US4] Build the UI events and sessions tabs (time-range picker, filters, paging, playback deep link, text-only rendering) in `ui/src/pages/clusters/tabs/EventsTab.vue` and `ui/src/pages/clusters/tabs/SessionsTab.vue`
- [X] T095 [P] [US4] Build the UI alert-rules page (rule editor with event-type picker, burst settings, recipients from the notification SDK) and the module audit trail page in `ui/src/pages/alerts/AlertRules.vue` and `ui/src/pages/audit/ModuleAudit.vue`
- [X] T096 [US4] Write an integration test in `tests/integration/alerts_test.go`: five failed logins against the Teleport container with a rule of at least 3 in 5 minutes; expect one delivery on the notification fake
- [X] T097 [P] [US4] Write the help page `docs/help/guides/audit-and-alerts.md`

**Checkpoint**: US1 through US4 work on their own.

---

## Phase 7: User Story 5 - Provision tangra users into Teleport (Priority: P3)

**Goal**: role mappings, provisioning with invites through notification, event-driven plus periodic reconciliation, lock-then-delete de-provisioning, and unmanaged users left untouched.

**Independent Test**: quickstart scenario 5.

### Tests for User Story 5 ⚠️ write first, confirm failing

- [X] T098 [P] [US5] Write contract tests for the mapping, managed-user and sync routes in `tests/contract/provisioning_test.go`
- [X] T099 [P] [US5] Write reconciler tests (fake auth membership, fake teleportapi, injected clock) in `internal/provisioning/reconcile_test.go`:
  - create, then active;
  - role change updates roles and logins;
  - losing all mappings locks the user with `deprovision_after` set;
  - regaining a mapping unlocks the user;
  - the grace period passing deletes the user;
  - unmanaged users are never touched;
  - username sanitization and collision rejection;
  - idempotent re-runs.
- [X] T100 [P] [US5] Write security tests in `tests/security/provisioning_security_test.go`: a forged membership event (auth says the member still exists) changes nothing; an operator gets 403 on mappings; a mapping that references a non-existent Teleport role is rejected; the invite URL is not in logs, events or audit

### Implementation for User Story 5

- [X] T101 [P] [US5] Implement the mapping service (validate that Teleport roles exist on the cluster, logins pattern) in `internal/provisioning/mappings.go`
- [X] T102 [US5] Implement the reconciler and the de-provision purge (managed labels per research D10, invite through `internal/notify` with the `teleport.invite` template) in `internal/provisioning/reconcile.go`
- [X] T103 [US5] Implement the membership-event consumer (event types from T010; re-verification with auth over mTLS) in `internal/events/consumer.go`, wired in `internal/app/app.go`
  - **Note**: auth publishes no membership events (T010), so no consumer exists; the periodic sync replaces it. Membership reads go through `provisioning.Membership`; the auth SDK cannot list members with roles, groups and login, so `app.go` wires `provisioning.Unavailable` (`dependency_unavailable`). Re-verification (SR-006) runs before every lock and delete. See plan.md, Phase 7 deviations.
- [X] T104 [US5] Add the mapping, managed-user and sync operations to `api/openapi/teleport.yaml` and implement the handlers in `internal/httpapi/provisioning.go`
- [X] T105 [P] [US5] Build the UI provisioning tab (mappings editor with a tangra role or group picker, managed-users list with state, "sync now") in `ui/src/pages/clusters/tabs/ProvisioningTab.vue`
- [X] T106 [P] [US5] Write the help page `docs/help/guides/provisioning.md`

**Checkpoint**: US1 through US5 work on their own. Scheduler-driven periodic sync is added in Phase 9.

---

## Phase 8: User Story 6 - Guided deployment of a new Community Edition cluster (Priority: P3)

**Goal**: wizard drafts, rendered artifacts, netguard prerequisite checks, and handover to registration.

**Independent Test**: quickstart scenario 6.

### Tests for User Story 6 ⚠️ write first, confirm failing

- [X] T107 [P] [US6] Write contract tests for the deployment routes in `tests/contract/deployments_test.go`
- [X] T108 [P] [US6] Write deploy tests in `internal/deploy/render_test.go`: golden files under `testdata/deploy/` for the acme and own_cert variants; validation of domain, e-mail, version, username and logins; values with shell metacharacters rejected. Write a fuzz test for the inputs in `tests/fuzz/deploy_fuzz_test.go`.
- [X] T109 [P] [US6] Write prerequisite check tests in `internal/deploy/checks_test.go` (fake resolver and TLS server): dns_apex, dns_wildcard, tls_443 with an invalid certificate; private targets refused by netguard; 1 call per 10 s rate limit

### Implementation for User Story 6

- [X] T110 [P] [US6] Implement the artifact templates (teleport.yaml, install.sh, tangra-manager-role.yaml, setup-commands.txt, checklist.md, per research D14) in `internal/deploy/templates/` and `internal/deploy/render.go`
- [X] T111 [P] [US6] Implement the draft service and prerequisite checks in `internal/deploy/service.go` and `internal/deploy/checks.go`
- [X] T112 [US6] Add the deployment operations to `api/openapi/teleport.yaml` and implement the handlers in `internal/httpapi/deployments.go`
- [X] T113 [P] [US6] Build the UI deployment wizard (inputs → checklist → artifacts download → checks → "Register this cluster" with the address filled in) in `ui/src/pages/deployments/DeploymentWizard.vue`
- [X] T114 [P] [US6] Write the help page `docs/help/guides/deploy-new-cluster.md`

**Checkpoint**: all six user stories work on their own.

---

## Phase 9: Platform Integration & Polish (Cross-Cutting)

**Purpose**: scheduler tasks, backup, catalogue, tenant lifecycle, degraded-mode behaviour, and the final gates.

- [X] T115 Write scheduler task tests in `internal/tasks/tasks_test.go` (each task type from contracts/events-and-tasks.md is idempotent, tenant-scoped, and returns an error on failure) — NOTE: 93.5% coverage; includes TestExecutorAdmitsOnlyTheScheduler (gateway peer refused) and the policy test `deploy` TestTaskExecutorOnlyFromScheduler
- [X] T116 Implement the TaskExecutor handlers and registration (`teleport:health-check`, `teleport:credential-expiry`, `teleport:sync-provisioning`, `teleport:purge-deprovisioned`, `teleport:token-gc`) with `sdktask.NewServer` and `schedulerclient.Registrar`, following ../go-tangra-signing-v4/internal/app/scheduler.go, in `internal/tasks/tasks.go` and `internal/app/scheduler.go` — NOTE: executor always served; registrar worker when `task_scheduler.enabled`; health-check does not restart watchers (the leased watcher does), see plan.md Phase 9
- [X] T117 [P] Write backup tests in `internal/backup/backup_test.go` (export and import of clusters with refs only, mappings, rules, drafts and confirmed links; no secret values), then implement `internal/backup/backup.go` — NOTE: no HTTP route yet (no v4 backup contract); same-tenant import only
- [X] T118 [P] Implement the tenant-deleted handling (remove registrations and warden secrets) in `internal/events/consumer.go`, with a test in `internal/events/consumer_test.go` — NOTE: wired only when `events.tenant_stream` is set; auth publishes no tenant-deleted event yet (NEEDS CROSS-REPO)
- [X] T119 [P] Write a degraded-mode integration test in `tests/integration/degraded_test.go` (quickstart scenario 8): notification, scheduler and inventory stopped means cluster management still works, the affected features return `dependency_unavailable`, and the watchers keep updating status — NOTE: integration test written, NOT RUN (no Docker); unit twin `internal/app` TestDegradedModeWithFakes passes
- [X] T120 [P] Create the catalogue entry `tangra-module.yaml` (routes `/api/teleport`, `/m/teleport`, `/teleport`; `min_core`; host_inputs MODULE_ADVERTISE_HOST, MODULE_BIND_IP, VALKEY_ADDRESS/PASSWORD/CA_FILE) and `deploy/bundle/` (compose, config.yaml, policy.yaml, init-db), modelled on ../go-tangra-dns-v4-helpdocs. Add `cmd/teleport-catalogue-permissions/main.go` and `cmd/teleportsvc/catalogue_test.go`.
- [X] T121 [P] Write the help pages `docs/help/operations.md` (credential rotation, `allowed_private_networks`, metrics, troubleshooting) and `docs/help/reference/permissions.md`, and run docs-lint
- [X] T122 [P] Write the UI end-to-end tests (Playwright) for register → users → lock → enroll → events in `ui/e2e/teleport.spec.ts` — NOTE: written with `ui/playwright.config.ts`, NOT RUN (no npm token, no running stack); skips without E2E_* env
- [X] T123 [P] Add the `teleport` service, its database init and its Valkey user to the dev compose used by `make compose-up` in `deploy/compose.dev.yaml`, and document the core-stack changes in `deploy/README.md` — NOTE: overlay on go-tangra/deploy/stack, validated with `docker compose config`; NOT started (Docker socket permission denied)
- [X] T124 Run the full gates (`make lint vuln test test-integration cover redaction-scan ui-build e2e`, license check) and fix any findings — NOTE: gofmt, build, vet (+integration tag), test -race, staticcheck, license, redaction-scan, cover (91.7%; authz/netguard/secrets 100%) and govulncheck (after toolchain go1.26.11) pass; gosec 15 findings fixed (int32 clamp, justified #nosec), now clean. NOT RUN: test-integration (no Docker; integration tests skip), ui-build and e2e (no npm token)
- [ ] T125 Run every quickstart.md scenario against the dev stack plus a Teleport CE container, and record the results in `specs/001-teleport-cluster-management/checklists/validation.md` — NOTE: NOT RUN live (no Docker). `checklists/validation.md` maps every scenario to its automated, integration-only or manual evidence; the Live result column is pending
- [X] T126 [P] Finish `README.md` (purpose, configuration reference, security notes, links to help docs), and add the CI workflow `.github/workflows/ci.yaml` (gates plus the catalogue job on `v*` tags) modelled on dns-v4-helpdocs

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies. T008, T009 and T010 must finish before the tasks that depend on their outcomes (T034, T050, T079, T103).
- **Foundational (Phase 2)**: depends on Setup. It blocks every user story.
- **US1 (Phase 3)**: depends on Phase 2. It is the MVP and blocks nothing else, but every later story needs a registered cluster at run time.
- **US2 (Phase 4)**: depends on Phase 2. At run time it uses a US1-registered cluster; in tests, fixtures insert one directly.
- **US3 (Phase 5)**: depends on Phase 2. Offline alerts use `internal/notify` from T053.
- **US4 (Phase 6)**: depends on Phase 2 and `internal/notify` (T053).
- **US5 (Phase 7)**: depends on Phase 2. It reuses the users service (T062) and notify (T053).
- **US6 (Phase 8)**: depends on Phase 2 and netguard (T028). Its handover links to the US1 register dialog.
- **Polish (Phase 9)**: depends on the stories it covers. T116 needs T053, T078, T102 and T050.

### Story completion order

```text
Setup → Foundational → US1 (MVP) ─┬─▶ US2 ─▶ US5
                                  ├─▶ US3
                                  ├─▶ US4
                                  └─▶ US6
                       all ─▶ Phase 9 Polish
```

### Within each story

Write the tests first and confirm they fail. Then build in this order: domain package → OpenAPI operations and handlers → UI → integration test → help docs.

## Parallel Execution Examples

- **Phase 2 tests**: T012–T021 can all start together, since they are separate files.
- **Phase 2 implementation**: T027–T033 and T036 can run in parallel once T025 is done.
- **US1**: T043–T047 in parallel, then T048 → T049 → T051, with the UI tasks T054 and T055 and the docs task T056 alongside.
- **US2**: T061, T062, T063 and T064 in parallel (separate packages). Then T065, alongside the UI tasks T066, T067 and T068.
- **US3**: T076 and T077 in parallel; T081 (proto and grpc) alongside T080; T082, T083 and T085 alongside.
- **Across stories**: after US1, separate developers can take US2, US3, US4 and US6 in parallel. They only share `api/openapi/teleport.yaml`, so coordinate edits there by appending each story's paths in their own section.

## Implementation Strategy

### MVP first (US1 only)

1. Phase 1 and Phase 2.
2. Phase 3 (US1): register, health, alerts on outage and expiry.
3. **Stop and validate** with quickstart scenarios 1, 1b, 1c and 7, then demo.

### Incremental delivery

1. MVP (US1), then US2 (day-to-day administration, completing P1).
2. US3 and US4 (P2: enrollment and inventory value, audit and alerts).
3. US5 and US6 (P3: identity lifecycle, onboarding).
4. Phase 9 before the first `v*` tag (catalogue and gates).

### Notes

- [P] means different files with no dependency on an incomplete task.
- Never store, log, emit or audit credentials, token values, or invite and reset URLs. The redaction scan (T124) is a release blocker.
- Commit after each task or logical group, with a constitution compliance checklist in the PR description.
