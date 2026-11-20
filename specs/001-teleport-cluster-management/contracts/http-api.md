# Contract: Browser HTTP API (`/api/teleport`)

The source of truth is `api/openapi/teleport.yaml` (OpenAPI 3.1), served by the gateway under `/api/teleport`. These rules apply to every route:

- Every operation declares `x-freya-permission`.
- Mutating operations require the platform `X-CSRF-Token` header.
- Lists follow the platform list contract (`page`, `page_size` ≤ 200, `order`). Teleport-backed lists use an opaque `next` cursor instead of a page number.
- Errors use `{reason, message, detail}` with these reasons:
  - `bad_request`, `validation_failed`, `not_found`, `conflict`, `forbidden`, `unauthenticated`;
  - `cluster_unreachable`, `credential_invalid`, `unsupported_version`, `enterprise_only`, `teleport_rejected`, `dependency_unavailable`, `blocked_target`.
- Error bodies never include Teleport stack traces or credential material.
- Fields marked 🔑 appear **only** in that response. They are never logged, cached or stored.

## Permissions (`pkg/teleportmanifest`)

| Permission | Grants |
|---|---|
| `clusters:read` | List and view clusters and health |
| `clusters:manage` | Register, edit, remove, rotate credential |
| `users:read` / `users:manage` | Teleport users |
| `roles:read` / `roles:manage` | Teleport roles (SR-005: administrator only) |
| `locks:read` / `locks:manage` | Locks |
| `tokens:manage` | Create, list and revoke join tokens |
| `resources:read` / `resources:link` | Resource list; confirm or remove inventory/asset links |
| `resources:enroll` | Enroll inventory hosts as SSH nodes through their agent (spec 002) |
| `audit:read` | Teleport audit events, sessions, module audit |
| `alerts:read` / `alerts:manage` | Alert rules |
| `provisioning:manage` | Role mappings, provision and de-provision |
| `deployments:manage` | Deployment wizard drafts and checks |

Module roles map to permissions as follows:

| Module role | Permissions |
|---|---|
| **administrator** | all |
| **operator** | `*:read` + `tokens:manage` + `locks:manage` + `resources:link` + `resources:enroll` |
| **auditor** | `*:read` |
| **viewer** | `*:read` except `audit:read` |

Built-in grants: owner/admin → administrator, operator → operator, auditor → auditor, member → viewer.

## Routes

### Clusters (US1)

| Method & path | Permission | Notes |
|---|---|---|
| `GET /clusters` | clusters:read | Health summary per cluster; `page, page_size, sort (display_name\|status\|created_at), order` → `{items, total, page, page_size, sort, order}` |
| `POST /clusters` | clusters:manage | Body: `{display_name, proxy_addr, credential_kind ("identity_file" only; bot mode deferred, research D2), credential (identity file, ≤ 64 KiB)}`. Verifies first: `422 blocked_target` (netguard), `422 credential_invalid`, `422 cluster_unreachable`. Stores the credential in warden; while warden has no write API this is `503 dependency_unavailable` with `detail {dependency: "secret_store"}` and nothing is stored anywhere. `409 conflict` on a duplicate name. `201` returns the cluster without the credential |
| `GET /clusters/{id}` | clusters:read | Includes `missing_permissions` (`kind:read`), `counts`, `edition`, `status_reason`, `writes_blocked` (true below N-1), `credential_identity`, `credential_expires_at?`, `last_contact_at?`. Never a credential or secret ref |
| `PATCH /clusters/{id}` | clusters:manage | `display_name`, `settings` |
| `POST /clusters/{id}/credential` | clusters:manage | Rotates the credential: verify, then store a new warden version |
| `POST /clusters/{id}/check` | clusters:read | Runs a health check now |
| `DELETE /clusters/{id}` | clusters:manage | Removes the registration, links, mappings and warden secret. Teleport is untouched |

### Users (US2)

| Method & path | Permission | Notes |
|---|---|---|
| `GET /clusters/{id}/users` | users:read | `?q=&next=&page_size=` → `{items, next?}`; each item: `name, roles, logins, created?, managed (bool), tangra_user_id?, locked (bool), revision`. `q` matches names within the page read from Teleport |
| `POST /clusters/{id}/users` | users:manage | `{name, roles[1..32], logins[0..32]}` → `201 {user, invite_url 🔑, invite_expires_at}`. Roles the cluster lacks are `422 validation_failed`; an existing user is `409 conflict`. When the invite cannot be issued the user is deleted again |
| `PUT /clusters/{id}/users/{name}` | users:manage | `{roles[], logins[], revision}` (revision required) → `409 conflict` on a stale revision |
| `POST /clusters/{id}/users/{name}/reset` | users:manage | → `{reset_url 🔑, expires_at}` |
| `DELETE /clusters/{id}/users/{name}` | users:manage | |

The management identity (`credential_identity`) cannot be updated, reset or
deleted: `403 forbidden` with `detail.guard = "self_identity"`.

### Roles (US2)

| Method & path | Permission | Notes |
|---|---|---|
| `GET /clusters/{id}/roles` | roles:read | `?next=&page_size=` → `{items, next?}`; items: `name, preset (bool), revision` |
| `GET /clusters/{id}/roles/{name}` | roles:read | `{yaml, revision, preset}`; `yaml` is the normalized form (sorted keys, defaults applied, no revision) |
| `POST /clusters/{id}/roles/preview` | roles:manage | `{yaml (≤ 64 KiB), revision?}` → `200 {valid, errors[], diff}`, with no side effects and no audit row. An invalid definition, a stale `revision`, or a missing `revision` for an existing role is `valid: false` with an explanation in `errors` |
| `PUT /clusters/{id}/roles/{name}` | roles:manage | `{yaml, revision?}`; an empty `revision` creates the role (`409 conflict` if it exists), otherwise updates it if `revision` is current (`409 conflict` if stale). `metadata.name` must match the path. An invalid definition is `422 validation_failed` with `detail {field: "yaml", message}`; a Teleport refusal is `422 teleport_rejected` with `detail.message` (Teleport's first line, bounded, no stack trace) |
| `DELETE /clusters/{id}/roles/{name}` | roles:manage | `403 forbidden` for preset roles (`detail.guard = "preset_role"`) and for roles held by the management identity (`detail.guard = "management_role"`) |

### Locks (US2)

| Method & path | Permission | Notes |
|---|---|---|
| `GET /clusters/{id}/locks` | locks:read | Active locks `{items}`: `name, target_kind, target {user\|role\|server_id}, message, created_by, expires_at?`. `created_by` is the tangra author (lock label `tangra.io/created-by`) |
| `POST /clusters/{id}/locks` | locks:manage | `{target_kind, target, reason (required, ≤ 256), expires_at? (future)}` → `201` lock. Refuses the management identity (`detail.guard = "self_identity"`) and roles it holds (`detail.guard = "management_role"`); when the identity's roles cannot be read the lock is refused (fail closed) |
| `DELETE /clusters/{id}/locks/{name}` | locks:manage | `404 not_found` for an unknown lock |

Guard refusals (`403 forbidden`) carry `{reason: "forbidden", message, detail: {guard, message}}`; no permission overrides them. Writes to an `unsupported_version` cluster are `422 unsupported_version`.

### Resources and tokens (US3)

| Method & path | Permission | Notes |
|---|---|---|
| `GET /clusters/{id}/resources` | resources:read | `?kind=&label=k=v&q=&status=online\|offline\|flagged&next=&page_size=` (≤ 200); each item includes `id` (snapshot id = `{rid}`) and `links[]`; the page carries `link_status` (`ok` \| `dependency_unavailable`) |
| `POST /clusters/{id}/resources/{rid}/links` | resources:link | Confirms a candidate or adds a manual link: `{target_module, target_id}` → 201 link; removes that module's other candidates |
| `DELETE /clusters/{id}/resources/{rid}/links/{lid}` | resources:link | |
| `GET /clusters/{id}/tokens` | tokens:manage | Metadata only: `id, resource_type, created_by, created_at, expires_at, expired, revoked, revoked_at?` |
| `POST /clusters/{id}/tokens` | tokens:manage | `{resource_type, ttl_minutes (1–1440, default 30)}` → `{id, resource_type, token 🔑, expires_at, install_command 🔑, config_snippet 🔑}` (`Cache-Control: no-store`) |
| `DELETE /clusters/{id}/tokens/{tid}` | tokens:manage | Revokes the token in Teleport and sets `revoked_at` |

### Audit and alerts (US4)

| Method & path | Permission | Notes |
|---|---|---|
| `GET /clusters/{id}/events` | audit:read | Required `from`, `to` (≤ 31 days); `types` (repeatable, allow-listed `EventType`; absent = all of them), `user` (exact, case-insensitive), `resource` (substring), `limit` ≤ 200 (default 50), `next` (Teleport's opaque cursor, passed through). Returns `{items, next?}`, newest first, of normalized `{id, time, type, code, user, resource, success, summary, raw}`; `raw` is a JSON object of at most 16 KiB (larger: top-level scalars only plus `"truncated": true`). A failed sign-in is the type `user.login.failure` |
| `GET /clusters/{id}/sessions` | audit:read | Same window rules (`from`, `to`, `limit`, `next`); items: `sid, participants[], user, target, kind (ssh\|kube\|db\|app\|desktop), started_at, duration_s, playback_url?` (absent when the session id is unsafe) |
| `GET /audit` | audit:read | Module audit trail (platform list contract, `sort=time`); filters `cluster_id`, `action`, `outcome`, `from`, `to`. Items: `id, time, actor_kind, actor_id, cluster_id?, action, target_kind, target_name, outcome, reason?, correlation_id?, detail` |
| `GET /alert-rules`, `POST /alert-rules`, `PUT /alert-rules/{id}`, `DELETE /alert-rules/{id}` | alerts:read / alerts:manage | Schema per data-model `alert_rule`; `event_types` validated against the allow-list (only for `teleport_event`); `threshold_count` and `window_minutes` are set together or not at all; `recipients.user_ids` 1–50 (channel ids stored, not delivered to); PUT replaces every field and cannot change `cluster_id`. A `cluster_id` outside the tenant is `422 validation_failed` |

### Provisioning (US5)

| Method & path | Permission | Notes |
|---|---|---|
| `GET /clusters/{id}/mappings` | users:read | `{items}`: `id, cluster_id, subject_kind (module_role\|group), subject_ref, teleport_roles, logins, created_by, created_at, updated_at` |
| `POST /clusters/{id}/mappings` | provisioning:manage | `{subject_kind, subject_ref, teleport_roles[1..16], logins[0..32]}` → `201`. Teleport roles are validated to exist on the cluster (`422 validation_failed`, `detail.field = "teleport_roles"`); logins match `^[A-Za-z_][A-Za-z0-9._-]{0,31}$`; the same subject twice is `409 conflict` |
| `PUT /clusters/{id}/mappings/{mid}` | provisioning:manage | `{teleport_roles, logins}`; the subject cannot change |
| `DELETE /clusters/{id}/mappings/{mid}` | provisioning:manage | Users it provisioned are locked at the next sync when no other mapping matches |
| `GET /clusters/{id}/managed-users` | users:read | `{items}`: `id, tangra_user_id, teleport_username, state, applied_roles, applied_logins, locked, deprovision_after?, last_synced_at?, created_at` |
| `POST /clusters/{id}/managed-users` | provisioning:manage | `{tangra_user_id}`: re-verifies the member with auth and provisions now → `201` managed user; the invite goes through notification and is never in a response. Not a member or no matching mapping: `422 validation_failed`; already managed: `409 conflict` (a user in `error` is retried instead) |
| `POST /clusters/{id}/provisioning/sync` | provisioning:manage | Runs a sync now (including deletions whose grace period has passed); returns `{created, updated, locked, unlocked, deleted, errors}` |

Provisioning refusals for a missing dependency are `503 dependency_unavailable`
with `detail.dependency` = `auth` (the tenant's membership cannot be read;
nothing is changed) or `notification` (the invite could not be delivered; the
Teleport user is removed again).

### Deployment wizard (US6)

| Method & path | Permission | Notes |
|---|---|---|
| `GET/POST /deployments`, `GET/PUT/DELETE /deployments/{id}` | deployments:manage | Draft per data-model. Body `{domain, cert_mode, acme_email?, teleport_version, admin_username, admin_logins[1..32], registered_cluster_id? (PUT only, a cluster of the tenant)}`; strict validation (`422 validation_failed` with `detail.field`). Responses add `checks`, `proxy_addr` (`<domain>:443`, the registration prefill) and `artifacts`; a new domain clears the stored checks. Human administrators only (workers are refused) |
| `GET /deployments/{id}/artifacts/{name}` | deployments:manage | `name` ∈ `teleport.yaml`, `install.sh`, `tangra-manager-role.yaml`, `setup-commands.txt`, `checklist.md`; `text/plain` attachment (`Content-Disposition: attachment`, `Cache-Control: no-store`), rendered per request, never stored |
| `POST /deployments/{id}/checks` | deployments:manage | Runs the dns_apex, dns_wildcard (`tangra-wildcard-check.<domain>`) and tls_443 checks through netguard and stores them; at most 1 call per 10 s per draft (`429 rate_limited`, `Retry-After: 10`). Details name the outcome class, never a resolved address |

### Live updates

`GET /stream` (`clusters:read`) is a server-sent events (SSE) relay of `teleport.*` platform events for the caller's tenant (ids only). The UI re-fetches when events arrive.
