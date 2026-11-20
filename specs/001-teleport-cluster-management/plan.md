# Implementation Plan: Teleport Cluster Management Module (go-tangra-teleport)

**Branch**: `001-teleport-cluster-management` | **Date**: 2026-11-19 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/001-teleport-cluster-management/spec.md`

## Summary

A new tangra v4 module, `teleport`, that manages self-hosted Teleport Community Edition clusters from the tangra portal. It does the following:

- registers clusters with a least-privilege management identity stored in warden;
- shows health;
- manages Teleport users, roles, locks and join tokens;
- lists enrolled resources and links them to inventory and asset records;
- searches audit events and sessions, with alert rules delivered through notification;
- provisions tangra users into Teleport from role mappings;
- runs a guided deployment wizard for new clusters.

The module talks to each cluster through the official `github.com/gravitational/teleport/api` Go client over the cluster's proxy address (port 443). Teleport stays the source of truth. The module stores only registrations, links, mappings, rules, drafts and token metadata.

The module follows the current v4 module pattern (go-tangra-dns-v4-helpdocs; scheduler wiring as in go-tangra-signing-v4):

- the freya framework;
- OpenAPI-first browser API and buf gRPC mesh API;
- pgx and RLS;
- Valkey events;
- SPIFFE mTLS;
- gateway manifest, catalogue and helpdocs;
- a Vue 3 Module Federation UI.

## Technical Context

**Language/Version**: Go 1.26.7 (toolchain go1.26.8; see Deviations); TypeScript + Vue 3 for `ui/`

**Primary Dependencies**:

- **Framework**: `github.com/go-tangra/go-tangra/v4` (freya, Kratos v3).
- **Tangra SDKs (sdk/v4)**: auth, portal (gatewayclient), lcm, warden, notification, scheduler, inventory, asset.
- **New dependency**: `github.com/gravitational/teleport/api`, justified in research D1.
- **Data and transport**: `jackc/pgx/v5`, `pressly/goose/v3`, `valkey-io/valkey-go`, `google.golang.org/grpc`, `getkin/kin-openapi`, `gopkg.in/yaml.v3`.
- **UI**: `@go-tangra/ui` (FlyonUI + Tailwind 4), Pinia, vue-router, CASL, Zod, Vite Module Federation.

**Storage**:

- **Postgres/TimescaleDB**: own database `teleport`, with RLS on `app.tenant_id` and an audit hypertable.
- **Valkey**: event stream, watcher leases, 15 s read cache.
- **warden**: credentials.

**Testing**:

- **Go**: `go test -race`; contract tests from the OpenAPI document and the proto files; integration tests with testcontainers (Postgres, Valkey, Teleport CE image); fuzz tests for every parser (role YAML, proxy address, identity file, event normalization, deployment inputs).
- **UI**: Vitest for the UI and Playwright for end-to-end runs.
- **Gates**: `scripts/coverage-gate.sh` (≥ 80% overall, 100% for `authz`, `netguard`, `secrets`).

**Target Platform**: Linux container (alpine, uid 10001), `ghcr.io/go-tangra/go-tangra-teleport`, joined to a tangra core through the catalogue bundle.

**Project Type**: web service (tangra module: Go backend + federated UI remote)

**Performance Goals**:

- First page of a 24-hour event search in under 3 s at 100k events/day (SC-006).
- Lock enforced within 30 s (SC-004).
- Outage and credential alerts within 5 minutes (SC-005).

**Constraints**:

- Platform defaults: 1 MiB body (identity-file and role uploads ≤ 64 KiB), 30 s request timeout, TLS 1.3.
- Teleport calls: 10 s timeout, 4 MiB max message, 4 concurrent calls per cluster.
- No secret persisted outside warden.

**Scale/Scope**: up to 50 clusters per tenant and 10k enrolled resources per cluster; 6 user stories; about 45 HTTP operations; 1 mesh service.

No NEEDS CLARIFICATION items remain. Unknowns are settled in [research.md](./research.md), and three are marked **Verify** and assigned to spike tasks: the API dependency footprint (D1), bot credential renewal (D2), and the auth and inventory event/lookup contracts (D10/D11).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Constitution: `.specify/memory/constitution.md` v1.0.0. This is the tangra platform constitution, adopted for this module because the project copy was still an unfilled template.

- **I. Secure by Default**: the service refuses to start without its database, Valkey, warden and gateway configuration.
  - Private-network cluster addresses and probes are blocked unless `allowed_private_networks` is set, and that opt-out logs a warning.
  - Write actions are blocked on clusters with an expired credential or an unsupported version.
  - Probes can never reach loopback, link-local or metadata addresses (netguard).
  - **PASS**.
- **II. Zero Trust Service Communication**: browser calls go through the gateway platform token with a permission on every route, re-checked in `internal/authz`. Mesh calls use SPIFFE mTLS with a deny-by-default `deploy/policy.yaml`:
  - `Access/*` only from inventory, asset and portal;
  - `TaskExecutor` only from the scheduler.
  
  Membership events are re-verified with auth before acting. Each Teleport cluster is an external system reached with its own mTLS identity (Teleport certificates), never with a platform credential. Bot credentials renew automatically; identity files are time-limited and alerted on (D2). **PASS**.
- **III. Boundary Validation & Defense in Depth**: validation runs at every layer.
  - **Edge**: OpenAPI and proto schemas.
  - **Typed validators**: proxy address, role YAML (size, kind, type validation), logins, TTLs, time windows, event-type allow-list.
  - **Teleport responses**: bounded and decoded into typed structures; Teleport-supplied text encoded in the UI.
  - **Access control**: gateway permission, module authz, RLS and cluster-ownership check on every call.
  - **SSRF**: netguard with a pinned dialler (D12).
  - **PASS**.
- **IV. Test-First with Security Verification (NON-NEGOTIABLE)**: tasks write contract, unit and integration tests first. Negative tests cover:
  - cross-tenant access;
  - forged SVIDs and membership events;
  - operator role or mapping edits;
  - self-lockout and preset-role deletion;
  - SSRF targets;
  - oversized and malformed identity files and role YAML;
  - stale revisions;
  - secret leakage (redaction scan).
  
  Fuzz tests cover every parser, and the coverage gate applies. **PASS**.
- **V. Observability & Auditability**: there is an append-only audit trail for every change or attempt (SR-007) and structured logs with correlation ids. Secret values use a redacting type and are never placed in logged structs.
  - **Prometheus metrics**: Teleport call latency and errors per cluster, watcher state, alert-poll lag, provisioning outcomes, credential days-to-expiry.
  - **Endpoints**: health, readiness and metrics on the admin listener.
  - **PASS**.
- **VI. Supply Chain Integrity & Minimal Dependencies**: one new direct dependency (Teleport `api`, Apache-2.0) is justified in research D1, with a spike to measure its transitive footprint and run `govulncheck`. `lib/` (AGPL) is explicitly excluded, and a CI license check enforces this. The Teleport test image is pinned by digest. `go.sum` is committed and `GOFLAGS=-mod=readonly`. **PASS** (recorded in Complexity Tracking).
- **VII. Simplicity & Explicit Configuration**: the wiring is explicit in `internal/app`.
  - Teleport access sits behind one small `teleportapi.Client` interface with a fake.
  - There is no local mirror of Teleport state.
  - Watchers and pollers are small loops with an injected clock.
  - Configuration is typed and validated at startup.
  - **PASS**.

**Post-design re-check (after Phase 1)**: **PASS**. The data model stores no secrets. The contracts keep secret values to single responses (🔑 fields). The mesh surface is read-only for peers. Background workers are listed in Complexity Tracking.

## Project Structure

### Documentation (this feature)

```text
specs/001-teleport-cluster-management/
├── plan.md              # This file
├── research.md          # Phase 0: D1–D14, supply chain, STRIDE
├── data-model.md        # Phase 1
├── quickstart.md        # Phase 1: validation scenarios
├── contracts/           # Phase 1: http-api.md, grpc.md, events-and-tasks.md
├── checklists/requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks)
```

### Source Code (repository root)

```text
go-tangra-teleport/
├── go.mod                       # module github.com/go-tangra/go-tangra-teleport/v4
├── cmd/teleportsvc/             # serve | bootstrap (migrate, seed permissions) | version
├── api/
│   ├── openapi/teleport.yaml    # browser routes (x-freya-permission), embed.go
│   └── proto/teleport/v1/       # Access service (+ generated code)
├── internal/
│   ├── app/                     # wiring: freya.New, store, warden, teleport pool, watchers, pollers, gateway, scheduler, consumers
│   ├── config/                  # typed config + validation (db, valkey, gateway, warden, limits, allowed_private_networks, thresholds)
│   ├── store/                   # pgx pool, tx with set_config(app.tenant_id), migrations/0001_schema.sql
│   ├── repo/ repodb/ repotest/  # repository interfaces, SQL implementation, shared repo test suite
│   ├── memstore/                # in-memory repo fake
│   ├── authz/                   # permission + cluster-ownership checks, actor kinds
│   ├── audit/                   # audit vocabulary + writer
│   ├── events/ stream/          # platform event publisher, SSE relay, membership-event consumer
│   ├── secrets/                 # warden refs (put/get/delete) + fake; redacting Secret type
│   ├── netguard/                # SSRF-safe resolver/dialler (D12)
│   ├── teleportapi/             # Client interface over teleport/api (+ fake), connection pool per cluster, limits, error mapping
│   ├── clusters/                # register/verify/rotate/remove, health, edition/version, credential expiry/renewal
│   ├── users/ roles/ locks/     # Teleport identity management (revision checks, self-identity + preset guards)
│   ├── roleyaml/                # YAML ⇄ typed role, validation, normalized diff
│   ├── tokens/                  # join tokens + install command rendering
│   ├── resources/               # live listing, snapshots, watcher, offline sweep, inventory/asset linking
│   ├── auditlog/                # Teleport event/session search + normalization
│   ├── alerts/                  # rules, poller, burst windows, de-dup, notification delivery
│   ├── provisioning/            # mappings, reconcile, de-provision, invite delivery
│   ├── deploy/                  # wizard drafts, artifact templates, prerequisite checks
│   ├── lease/                   # Valkey lease helper for watcher/poller ownership
│   ├── tasks/                   # scheduler TaskExecutor handlers
│   ├── backup/                  # export/import
│   ├── metrics/                 # Prometheus collectors
│   ├── httpapi/                 # OpenAPI handlers
│   └── grpcapi/                 # teleport.v1.Access
├── pkg/
│   ├── teleportmanifest/        # module, permissions, roles, grants, abilities, nav
│   └── teleportclient/          # typed mesh client (re-exported by sdk/)
├── sdk/                         # github.com/go-tangra/go-tangra-teleport/sdk/v4
├── docs/help/                   # index, getting-started, guides/*, operations, reference (tangra-manager role) + embed.go
├── ui/                          # MF remote: clusters, cluster detail (overview/users/roles/locks/resources/tokens/events/sessions/provisioning), alerts, deployments
├── deploy/                      # policy.yaml (+ policy_test.go), container.yaml, bundle/ (compose, config, policy, init-db), README
├── tests/{contract,integration,security,fuzz}/
├── testdata/                    # Teleport response fixtures, identity-file fixtures (test CA only), role YAML corpus
├── scripts/coverage-gate.sh
├── tangra-module.yaml           # catalogue entry (routes /api/teleport, /m/teleport, /teleport)
├── Dockerfile Makefile buf.yaml buf.gen.yaml README.md SECURITY.md
```

**Structure Decision**:

- **Single-repository v4 module**, mirroring go-tangra-dns-v4-helpdocs: layout, store + RLS, memstore, authz, audit, events/stream, secrets, manifest, catalogue, helpdocs, coverage gate.
- **Scheduler wiring** as in go-tangra-signing-v4 (`internal/tasks` + `schedulerclient.Registrar`).
- **Teleport-specific packages** (`teleportapi`, `roleyaml`, `netguard`, `deploy`) sit behind small interfaces with fakes, so unit tests run offline.
- **Optional cross-repo changes**: a host-lookup read RPC in inventory-v4 and asset-v4, if research D11 shows one is missing, and the `teleport` entries in the core compose stack. These are tracked as separate tasks.

## Complexity Tracking

| Item | Why needed | Simpler alternative rejected because |
|---|---|---|
| New dependency `github.com/gravitational/teleport/api` | Typed, supported access to Teleport gRPC (all user stories) | `tctl` shell-out is untyped and widens the attack surface; hand-written gRPC tracks Teleport's internal protos and drifts (D1). The license check blocks `lib/` (AGPL) |
| Background workers (cluster watchers, alert pollers, offline sweep) under Valkey leases | SC-004, SC-005, FR-020, FR-023, and FR-034 (alerts must not depend on the scheduler) | Scheduler-only polling cannot meet the latency targets and stops when the scheduler is down. Each worker is a small loop with an injected clock and fakes |
| Outbound connections to tenant-supplied addresses (cluster proxies, deployment probes) | FR-001, FR-031 | Unavoidable for a management tool. Compensated by netguard (resolved-IP checks, pinned dialler, port allow-list, private ranges as an explicit opt-out) and per-cluster limits (D12) |
| Teleport clusters are not SPIFFE mesh peers | Teleport has its own CA and mTLS | Not possible upstream. Compensated by mutual TLS with the cluster-issued identity, least-privilege role (D3), and credentials kept in warden |

## Deviations found during implementation (Phase 1–2)

Where the real framework or peers differ from this plan, the code follows them. These are the deviations:

| Plan | Implementation | Why |
|---|---|---|
| Go 1.26.3 | `go 1.26.7` (toolchain go1.26.8) | The pinned `teleport/api` pseudo-version requires go 1.26.7 (research D1). Build with go ≥ 1.26.11 to clear the stdlib govulncheck findings |
| `teleport/api` at a stable tag | Pseudo-version `v0.0.0-20260825163510-1283425b60ec` (19.0.0-prealpha.2) | The `api` module is not semver-tagged; re-pin to the 19.0.0 GA commit (research D1) |
| Two credential kinds | `identity_file` only | Bot renewal needs `tbot` and `lib/` (AGPL); bot mode is deferred (research D2) |
| secrets: warden put/get/delete | warden **get** only; `Put`/`Delete` return `ErrWriteUnsupported`. A development `FileStore` (`secrets.allow_file`, refused in production) is routed by `secrets.Router` | The warden SDK has no write RPC (research D11). Production cluster registration needs a cross-repo warden write RPC |
| audit through the framework `audit` package | The module's own `internal/audit` writer (closed `teleport.*` vocabulary, redaction, batched, append-only table) | The framework audit vocabulary is closed and cannot carry module actions (research D11) |
| Membership-event consumer | Periodic `teleport:sync-provisioning` only (optionally watching auth `Sessions` revocations) | auth publishes no membership or role-change events (research D10) |
| inventory/asset host lookup | Not available; T079 is marked NEEDS CROSS-REPO | Neither SDK has a hostname/IP lookup (research D11) |
| `internal/events/ stream/` with one `stream.go` | `internal/stream` copied from dns-v4 (`hub.go`, `client.go`, `sse.go`, `valkeykv/`). `valkeykv.Dial` exposes the raw connection, shared by the read cache and the leases | Follow the dns-v4 code as it is |
| Valkey cache and lease inside `teleportapi` and `lease` | Adapters in subpackages: `internal/teleportapi/valkeycache` and `internal/lease/valkeylease` | Keep the core packages Valkey-free and unit-testable with in-memory fakes |
| Browser API under `/api/teleport` | Paths are `/api/teleport/v1/...`; the gateway prefix stays `/api/teleport` | The dns-v4 convention |
| `deploy/policy.yaml` per contracts/grpc.md | Same, plus `/scheduler.v1.TaskExecutor/ExecuteTask` from `svc/scheduler` only, and gateway HTTP operations only | contracts/grpc.md requires the TaskExecutor rule; this is its exact method name |
| `cmd/teleportsvc` with `serve` | `teleportsvc -config <path>` serves; `bootstrap` migrates; `version` prints | The dns-v4 command layout |
| Permission checker in `internal/app` | `authz.AuthChecker` (auth `Authorization/Check`, fail closed) | Keeps all access decisions in the 100%-covered `authz` package |

## Deviations found during implementation (Phase 3, US1)

- **Notification recipients**: the auth SDK cannot resolve tenant module
  administrators to addresses, so outage and expiry notifications go to the
  recipients of the tenant's enabled alert rules for `cluster_unreachable` /
  `credential_expiring` (`clusters.RuleRecipients`). With no rule the module
  only logs.
- **Failure counts and announced expiry stages** are kept in memory on the
  lease-holding replica; a lease handover restarts the 3-failure count and may
  re-announce the current expiry stage once.
- **SSE filter**: `GET /stream` is the existing relay with
  `stream.Config.TypePrefix = "teleport."`, applied to replay and live dispatch.
- **credential_issued_at** (migration 0002) was added so the 25 % short-lived
  threshold can be computed.
- **Registration in production** answers `503 dependency_unavailable`
  (`detail.dependency = "secret_store"`) until warden has a write API; the
  credential is never stored elsewhere.
- **UI layout**: pages live in `ui/src/pages/clusters/` (per tasks.md); the
  scaffold's `ui/src/views/` placeholder was removed. The npm build and
  vue-tsc were not run (no registry token).

## Deviations found during implementation (Phase 4, US2)

- **Revision checks** (research D5): `teleportapi` reads the current user or
  role and compares its revision before writing (`trace.CompareFailed` →
  `409 conflict`), and also sends the revision with the write. Teleport's
  user and role updates are not all conditional server-side, so a write
  racing within that window is last-write-wins on the cluster.
- **Guards** answer `403 forbidden` with `detail.guard` (`self_identity`,
  `preset_role`, `management_role`) rather than a new top-level reason, so the
  closed reason vocabulary is unchanged. The management identity cannot be
  updated or reset either (FR-013), not only deleted. Editing a role the
  identity holds is allowed (contract); deleting or locking it is refused.
- **Invite rollback**: when the invite token cannot be issued, the new user
  is deleted again so no user is left without a way to sign in.
- **Lock author**: Teleport records its own author (the management
  identity) in `CreatedBy`; the tangra author is kept in the lock label
  `tangra.io/created-by` and returned as `created_by`.
- **One-time values** are `secrets.OneTime`: JSON-encoded in the issuing
  response only, redacted in every `fmt`/`slog` path.
- **Names** of users, roles, logins and lock targets are restricted to
  `^[A-Za-z0-9][A-Za-z0-9._@+:-]{0,127}$` (stricter than Teleport).
- **List filtering**: `q` on users filters the page read from Teleport (the
  users API has no server-side name search).
- **UI**: tabs in `ui/src/pages/clusters/tabs/` plus `components/RoleDiff.vue`
  and `components/OneTimeLink.vue`; the npm build and vue-tsc were not run (no
  registry token).

## Deviations found during implementation (Phase 5, US3)

- **Token revocation by hash**: only the SHA-256 of a join token is stored,
  so revoking lists the cluster's provision tokens (≤ 20 pages of 500) and
  deletes the one whose hash matches; a token already gone from Teleport is
  marked revoked. Token errors from Teleport are made opaque (the token name
  is the secret and Teleport quotes it), keeping only the reason.
- **One watcher worker**: all cluster watches run under one leased worker
  (`resource-watcher`, lease `teleport:lease:resource-watcher`) that starts a
  goroutine per registered cluster and re-reads the cluster list every 30 s,
  instead of one lease per cluster. The offline sweep is a second leased
  worker (`offline-sweep`, every minute).
- **Offline detection**: Teleport deletes a server whose heartbeat expired,
  so a watch `OpDelete` marks the snapshot offline; every (re)opened watch
  resynchronises from a full listing. Lock, user and role events invalidate
  the read cache.
- **Linking (T079)**: inventory-v4 and asset-v4 have no host lookup by
  hostname/IP (research D11). The linker sits behind `resources.HostDirectory`;
  production wires `UnavailableDirectory`, so automatic matching reports
  `link_status: dependency_unavailable` while manual confirm/remove works.
  The real adapter waits on that cross-repo RPC. Matching runs only for new
  snapshots or a changed hostname/address, so a removed automatic link is
  not recreated on the next heartbeat.
- **Alerts from the sweep** go through `resources.Alerter`; US3 wires
  `NotifyAlerter` (rule recipients, `teleport.alert`). The app resolves
  `App.Alerter` at alert time so US4's engine (with alert_delivery
  de-duplication) can replace it.
- **gRPC tenant**: `teleport.v1.Access` requests carry `tenant_id` (dns-v4
  pattern) rather than a tenant in call metadata; `HostAccess` also returns
  `resource_id` and `kind` (contracts/grpc.md updated).
- **sdk/ module** was not created: like dns-v4 the typed client is
  `pkg/teleportclient` in the main module; a separate `sdk/` module (as
  notification-v4) can re-export it once a consumer needs a lighter
  dependency.
- **Snapshot labels** are bounded to 64 per resource; the resource list's
  `id` is the snapshot id, created on first listing if the watcher has not
  seen the resource yet.
- **UI**: `ResourcesTab.vue`, `TokensTab.vue` and `components/EnrollDialog.vue`;
  the npm build and vue-tsc were not run (no registry token).

## Deviations found during implementation (Phase 6, US4)

- **Normalized event types**: the allow-list (`auditlog.EventTypes`, the
  OpenAPI `EventType` enum) holds normalized types. Teleport's `user.login`
  with a failure code (`…W`/`…E`, or `success: false`) becomes
  `user.login.failure`, so filters and alert rules can name failed sign-ins.
  An event without a type is named from its code (`T1000W`, `TLK00I`, …).
  Searches cover allow-listed types only (all of them when `types` is
  absent).
- **Filters on the page read**: Teleport's event search has no user or
  resource filter, so `user`, `resource` and the failure split filter the
  events read. When they drop events, up to 5 Teleport pages are read per
  call, each sized to what is still missing, so `next` stays exact.
- **`types` parameter**: repeatable `types` (OpenAPI form/explode) instead of
  `types[]` (contracts/http-api.md updated). Event items carry `id`; session
  items carry `user`; `playback_url` is left out for unsafe session ids.
- **raw**: always a JSON object of at most 16 KiB; a larger event keeps its
  top-level scalar fields (strings bounded to 256 bytes) and
  `"truncated": true`; a non-object is `{}`.
- **Alert cursor**: polls read oldest first from the cursor to now − 10 s
  (`Settle`, for late indexing). With no new events the cursor moves to that
  point (id ""), so a rule enabled later never replays old events; a cluster
  without a cursor starts 5 minutes back. Events at the cursor's instant are
  skipped up to the cursor event (times compared at microsecond precision).
- **Delivery claims**: `repo.AlertState.ReleaseDelivery` was added (memstore,
  repodb and the shared repotest suite). A window is claimed in
  `alert_delivery` before sending and released when the send fails, so the
  cursor is held and the next poll retries. Delivery is at least once: a
  recipient reached before a failure can get the alert again. A delivery
  still refused after `MaxHold` (1 hour) is dropped and logged, so one
  broken recipient cannot stall a cluster.
- **Burst windows** are fixed windows of the rule's length
  (`burst:<user>:<window start>`), counted over the preceding W minutes, so
  a burst alerts at most once per user and window. The history is in
  memory per cluster; after a restart or lease handover it is rebuilt by
  reading the largest burst window before the cursor once.
- **Recipients**: deliveries go to `recipients.user_ids` (at least one is
  required). `channel_ids` are stored but not delivered to, because the
  notification SDK sends a system template to one recipient. The UI takes
  user ids as text: there is no recipient directory for the browser yet.
- **Module conditions**: the engine is `App.Alerter`, so the offline sweep's
  `resource_offline` alerts go through rules with `alert_delivery`
  de-duplication. US1's outage and expiry notifications stay in
  `clusters.Service` (their own templates and `RuleRecipients`).
- **Delivery pruning**: the poller prunes deliveries older than 30 days
  hourly, so it does not depend on `teleport:token-gc` (FR-034).
- **Audit**: successful deliveries are audited (`teleport.alert.deliver`,
  worker actor); failed sends are logged only, to avoid a row every 30 s
  during an outage. Alert-rule changes and failed attempts are audited.
- **Test harness**: `clusterstest.Auditor` (the auditor module role) was
  added.
- **UI**: `EventsTab.vue`, `SessionsTab.vue`, `pages/alerts/AlertRules.vue`,
  `pages/audit/ModuleAudit.vue` and `stores/audit.ts`; the npm build and
  vue-tsc were not run (no registry token).
- **Integration test** (T096): failed sign-ins go to the proxy's web login
  (`POST /v1/webapi/sessions/web`). It compiles under `-tags integration`
  but was not run here (no Docker).

## Deviations found during implementation (Phase 7, US5)

- **Membership source (T103)**: auth publishes no membership events (D10,
  T010), so there is no event consumer and `internal/events/consumer.go` was
  not created. Membership is read through `provisioning.Membership`
  (list members with module roles, groups and login; re-read one member).
  The auth SDK v4.1.0 cannot back it: `Profiles.ListMembers` returns active
  ids only (and its policy admits the notification module only), and no RPC
  returns a member's module roles, groups or login. Production wires
  `provisioning.Unavailable`: sync and provision answer `503
  dependency_unavailable` (`detail.dependency = "auth"`) and change nothing;
  mappings work. NEEDS CROSS-REPO: a member-detail listing in auth.
  `FakeMembership` drives the tests.
- **Re-verification (SR-006)**: every lock and delete re-reads the member
  with `Membership.Member`; a member still entitled is left alone, a failed
  read fails closed (counted as an error).
- **Ownership check**: the module writes (updates, locks, deletes) only a
  Teleport user carrying `tangra.io/managed=true` with the expected
  `tangra.io/tenant` and `tangra.io/user`; anything else, including the
  management identity, is a collision and never touched.
- **Invite delivery**: `teleport.invite` goes to the tangra user id (`To`)
  with vars `invite_url, expires_at, teleport_username, cluster_id,
  display_name, cluster_name`. `secrets.OneTime.Reveal` was added for this
  hand-off. When the send fails the Teleport user is deleted again and the
  row goes to `error` (retried by the next sync or by POST
  /managed-users).
- **Sync scope**: `POST /provisioning/sync` also deletes the users whose
  grace period has passed on that cluster; the summary gained `unlocked`
  (contracts/http-api.md updated). Mapping subjects are immutable (PUT
  replaces roles and logins only, matching `repo.UpdateMapping`).
- **Grace period**: `thresholds.deprovision_grace_days` (days; 0 means the
  7-day default). Runs on one cluster are serialised per replica.
- **Entry points for Phase 9**: `Service.Reconcile(ctx, tenant, cluster)`
  and `Service.PurgeDeprovisioned(ctx, tenant)`; without a caller in ctx they
  run as `authz.Worker(tenant, "provisioning-sync")`.
- **UI**: `ProvisioningTab.vue` takes the tangra role slug, group id and
  user id as text (no role, group or user directory for the browser yet).
  The npm build and vue-tsc were not run (no registry token).

## Deviations found during implementation (Phase 8, US6)

- **install.sh** installs the downloaded `teleport.yaml` (next to the
  script) instead of running `teleport configure`; the YAML is the
  `teleport configure --acme …` equivalent (or the own-certificate variant
  with `https_keypairs` under `/etc/teleport/tls/`). The script checks
  `teleport version` against the pinned version before configuring.
- **Validation** is stricter than RFC 5321 for the ACME e-mail (letters,
  digits and `. _ -` before the `@`), and admin logins require 1 to 32
  entries. Version components are limited to 4 digits. Templates quote every
  value anyway (`shq` for the shell, JSON strings for YAML).
- **Checks** resolve `tangra-wildcard-check.<domain>` for dns_wildcard and
  verify the 443 certificate against the system roots. They use the same
  netguard policy as cluster addresses (`allowed_private_networks`, port
  allow-list). The 10 s per-draft limit is per replica (in memory).
- **Handover**: `PUT /deployments/{id}` accepts `registered_cluster_id`
  (validated against the tenant's clusters); responses carry `proxy_addr`,
  which the wizard passes to the register dialog (new `proxyAddr` and
  `displayName` props).
- **Role artifact**: `tangra-manager-role.yaml` is kept identical to
  `docs/help/reference/tangra-manager-role.md` by a unit test.
- **UI**: `pages/deployments/DeploymentWizard.vue` (route
  `/teleport/deployments`, already in the manifest nav), `stores/deployments.ts`
  and `schemas/deployments.ts`; the npm build and vue-tsc were not run (no
  registry token).


## Deviations found during implementation (Phase 9)

- **Tenant-scoped GC**: the scheduler calls `teleport:token-gc` once per
  tenant, so the repository gained `PruneTenantJoinTokens` and
  `PruneTenantDeliveries` (explicit `tenant_id` predicate under the tenant
  scope, covered by the repotest conformance suite). Retention: expired token
  metadata 7 days, alert deliveries 30 days.
- **Credential expiry without dialling**: `clusters.Service.CheckCredential`
  re-evaluates the stored expiry (warning, then `credential_invalid` and a
  pool invalidation) and writes only on a change; the task uses it.
- **Health-check task**: checks every cluster of the tenant but does not
  restart watchers; the leased resource watcher rescans every 30 s and
  reopens dead watches itself. The task and the leased monitor share the
  failure counter, so with both running a cluster can reach `unreachable`
  after fewer wall-clock minutes (still 3 failed checks).
- **Executor admission**: `scheduler.v1.TaskExecutor` is always served (the
  policy admits `svc/scheduler` only and the SDK re-checks the verified
  peer); `task_scheduler.enabled` only controls the registrar worker. All
  task types are tenant-scoped (no platform tasks).
- **Tenant deletion**: auth publishes no tenant-deleted event yet, so the
  consumer (`events.tenant_stream`, type `auth.tenant.deleted`, payload
  `{"tenant_id"}`) is wired only when configured. `PurgeTenant` also removes
  alert rules and drafts; a cluster whose secret cannot be deleted is kept
  and the entry retried (the cursor does not pass a failed entry).
- **Backup**: `internal/backup` is wired as `App.Backup` but has no HTTP
  route or OpenAPI operation (no v4 backup-orchestrator contract to follow
  yet). Import is into the caller's tenant only; restored clusters are
  `unreachable` until checked; a confirmed link whose resource snapshot is
  missing gets a placeholder snapshot until the watcher refreshes it.
- **Join bundle**: runs with `env: dev` because production refuses `file:`
  credential references and warden has no write RPC for modules. Extra host
  inputs `WARDEN_GRPC`, `NOTIFICATION_GRPC`, `SCHEDULER_GRPC`.
- **Dev compose**: `deploy/compose.dev.yaml` is an overlay on
  `go-tangra/deploy/stack/compose.yaml` (no change to that repo): one-shot
  services create the database, add the Valkey user with `ACL SETUSER`
  (lost on a valkey restart), apply the gateway allow-list and mint the join
  token; profile `teleport-ce` adds a test cluster (`deploy/teleport-ce.yaml`).
  The Makefile `compose-up`/`compose-down` now use it (`CORE_STACK`).
- **E2E**: the Playwright suite lives in `ui/e2e/` (config
  `ui/playwright.config.ts`), not `ui/tests/e2e/`; it skips without
  `E2E_OPERATOR_PASSWORD`, `E2E_TELEPORT_PROXY`, `E2E_TELEPORT_IDENTITY`.
- **Toolchain**: `toolchain go1.26.11` (was go1.26.8): govulncheck reported
  15 reachable standard-library advisories fixed in go1.26.9–1.26.11.
- **CI**: `ui/package-lock.json` is not committed (needs the registry token
  to generate), so the UI job falls back to `npm install` until it is.
