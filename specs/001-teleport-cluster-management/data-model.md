# Data Model: Teleport Cluster Management Module

**Feature**: [spec.md](./spec.md) | **Research**: [research.md](./research.md)

These conventions apply to every table:

- Postgres/TimescaleDB, with migrations in `internal/store/migrations/0001_schema.sql` (goose).
- Every tenant table has `tenant_id uuid NOT NULL` and row-level security `USING (tenant_id = current_setting('app.tenant_id')::uuid OR current_setting('app.system', true) = 'on')`.
- Ids are UUIDv7.
- Timestamps are `timestamptz`.
- No table stores a secret value. Credentials are kept only as `warden:` references.

Teleport-owned objects (users, roles, locks, tokens, resources, audit events, sessions) are **not** stored here. They are read live from the cluster (research D4).

## cluster

A tenant's registration of one Teleport cluster (US1, FR-001…006).

| Field | Type | Rules |
|---|---|---|
| id | uuid | PK |
| tenant_id | uuid | RLS |
| display_name | text | 1–64 chars, unique per tenant |
| proxy_addr | text | `host[:port]`, port defaults to 443; netguard-validated (D12) |
| cluster_name | text | from the cluster ping, read-only |
| edition | text | `community` \| `enterprise` \| `unknown` |
| server_version | text | from the cluster ping |
| credential_ref | text | `warden:…` only; never returned by the API |
| credential_kind | text | `identity_file` (bot mode deferred, research D2) |
| credential_identity | text | Teleport username of the management identity (self-lockout guard, FR-013) |
| credential_expires_at | timestamptz | parsed from the certificate |
| credential_issued_at | timestamptz | certificate NotBefore (migration 0002); the lifetime drives the 25 % short-lived warning threshold |
| status | text | see the state machine below |
| status_reason | text | human-readable, ≤ 512 chars, no secrets |
| missing_permissions | text[] | from the D3 probe |
| last_contact_at | timestamptz | |
| counts | jsonb | `{users, roles, nodes, apps, dbs, kube, desktops}` from the last health check |
| settings | jsonb | `{offline_threshold_minutes (default 15), alerts_enabled}` |
| created_by, created_at, updated_at | | |

**Status state machine**:

```text
(register) ──verify fails──▶ rejected, nothing saved
(register) ──verify ok──▶ connected
connected ──≥ 3 failed checks (≤ 5 min)──▶ unreachable ──contact restored──▶ connected
connected ──cert within threshold──▶ credential_expiring ──rotated/renewed──▶ connected
any ──cert expired / auth rejected──▶ credential_invalid ──rotated──▶ connected
connected ──version older than N-1──▶ unsupported_version (writes blocked) ──upgraded──▶ connected
```

## join_token

Metadata only. The token value is returned once and then discarded (FR-016…018).

| Field | Type | Rules |
|---|---|---|
| id | uuid | PK |
| tenant_id, cluster_id | uuid | FK cluster ON DELETE CASCADE |
| token_hash | bytea | SHA-256 of the token name, used for revocation lookup |
| resource_type | text | `node` \| `app` \| `db` \| `kube` \| `desktop` |
| expires_at | timestamptz | `now()+ttl`, 1 minute ≤ ttl ≤ 24 hours |
| revoked_at | timestamptz | nullable |
| created_by, created_at | | |

## resource_snapshot

The last-known state of an enrolled resource. It is used for offline detection and links (FR-015, FR-019, FR-020).

| Field | Type | Rules |
|---|---|---|
| id | uuid | PK |
| tenant_id, cluster_id | uuid | |
| kind | text | `node` \| `app` \| `db` \| `kube` \| `desktop` |
| teleport_name | text | unique (cluster_id, kind, teleport_name) |
| hostname, addr | text | nullable |
| labels | jsonb | bounded to 64 keys |
| agent_version | text | |
| online | bool | |
| last_seen_at, offline_since, flagged_at | timestamptz | |

## resource_link

Links a Teleport resource to a tangra inventory or asset record (FR-019).

| Field | Type | Rules |
|---|---|---|
| id | uuid | PK |
| tenant_id | uuid | |
| snapshot_id | uuid | FK resource_snapshot ON DELETE CASCADE |
| target_module | text | `inventory` \| `asset` |
| target_id | text | the id in the target module |
| match | text | `auto` \| `confirmed` \| `candidate` |
| matched_on | text | `hostname` \| `ip` |
| created_at | | unique (snapshot_id, target_module, target_id) |

`candidate` rows are ambiguous matches waiting for confirmation. Confirming one promotes it to `confirmed` and deletes the other candidates.

## role_mapping

Maps a tangra role or group to Teleport roles and logins on one cluster (FR-026).

| Field | Type | Rules |
|---|---|---|
| id | uuid | PK |
| tenant_id, cluster_id | uuid | |
| subject_kind | text | `module_role` \| `group` |
| subject_ref | text | tangra role or group id |
| teleport_roles | text[] | 1–16 entries; each must exist on the cluster at save time |
| logins | text[] | 0–32 entries, POSIX login pattern |
| created_by, created_at, updated_at | | unique (cluster_id, subject_kind, subject_ref) |

## managed_user

Links a tangra user to the Teleport user the module created (FR-027…029).

| Field | Type | Rules |
|---|---|---|
| id | uuid | PK |
| tenant_id, cluster_id | uuid | |
| tangra_user_id | uuid | unique (cluster_id, tangra_user_id) |
| teleport_username | text | unique (cluster_id, teleport_username) |
| state | text | see below |
| applied_roles, applied_logins | text[] | the last set the module applied |
| lock_name | text | nullable; set while locked |
| deprovision_after | timestamptz | `locked_at + grace` (default 7 days) |
| last_synced_at, created_at | | |

**State machine**: `provisioning → active → locked_pending_deletion → deleted (row removed)`. A user who regains a mapped role goes from `locked_pending_deletion` back to `active`, and the module lock is removed. A failed create goes to `error` and is retried at the next sync.

## alert_rule, alert_cursor and alert_delivery

Alert rules (FR-023), the poll cursor per cluster, and the de-duplication record (research D8).

| alert_rule field | Type | Rules |
|---|---|---|
| id, tenant_id | uuid | |
| cluster_id | uuid | nullable means all of the tenant's clusters |
| name | text | 1–64 chars |
| condition_kind | text | `teleport_event` \| `cluster_unreachable` \| `credential_expiring` \| `resource_offline` |
| event_types | text[] | required for `teleport_event`; an allow-listed Teleport event type set |
| threshold_count, window_minutes | int | optional burst rule: 1 ≤ count ≤ 1000, 1 ≤ window ≤ 1440 |
| recipients | jsonb | notification recipients/channels by reference (user ids, channel ids) |
| enabled | bool | |
| created_by, created_at, updated_at | | |

- **alert_cursor**: (cluster_id PK, tenant_id, last_event_time, last_event_id, updated_at).
- **alert_delivery**: (id, tenant_id, rule_id, cluster_id, window_key, delivered_at), unique (rule_id, cluster_id, window_key). Rows are pruned after 30 days. A window is claimed before sending and released again (deleted) when the send fails, so it is retried. Window keys: `event:<event id>` (any match), `burst:<user>:<window start>` (burst rules), `<condition>:<occurrence key>` (module conditions); keys over 128 characters are stored as `sha256:<hex>`.

## deployment_draft

Wizard state for a planned cluster (FR-030/031).

| Field | Type | Rules |
|---|---|---|
| id, tenant_id | uuid | |
| domain | text | RFC 1123 FQDN |
| cert_mode | text | `acme` \| `own_cert` |
| acme_email | text | required if acme |
| teleport_version | text | `^\d+\.\d+\.\d+$` |
| admin_username, admin_logins | text, text[] | validated patterns |
| checks | jsonb | `[{name, ok, detail, checked_at}]` for dns_apex, dns_wildcard, tls_443 |
| registered_cluster_id | uuid | nullable; set once the cluster is registered |
| created_by, created_at, updated_at | | |

Generated artifacts are rendered on request from these fields. They are not stored.

## audit_event (hypertable)

The module audit trail (FR-024, SR-007), written through the framework `audit` package with the timescale contrib.

Columns:

- `time`, `tenant_id`, `actor_kind`, `actor_id`, `cluster_id`;
- `action`, for example `teleport.user.create`, `teleport.role.update`, `teleport.lock.create`, `teleport.token.create`, `teleport.cluster.register`, `teleport.credential.rotate`;
- `target_kind`, `target_name`;
- `outcome` (`success` | `failure` | `unknown`), `reason`, `correlation_id`;
- `detail jsonb` (no secrets; role changes record before/after SHA-256 hashes).

The table is append-only: no UPDATE or DELETE grants for the module role.

## Relationships

```text
cluster 1─* join_token
cluster 1─* resource_snapshot 1─* resource_link ──▶ inventory/asset record (external id)
cluster 1─* role_mapping
cluster 1─* managed_user ──▶ tangra user (auth)
cluster 1─1 alert_cursor
alert_rule *─0..1 cluster ; alert_rule 1─* alert_delivery
deployment_draft 0..1─▶ cluster
```

Backup export (FR-035) covers cluster (with `credential_ref` only), role_mapping, alert_rule, deployment_draft and resource_link (confirmed links only). Snapshots, cursors and deliveries are rebuilt after a restore.
