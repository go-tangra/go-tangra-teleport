# go-tangra-teleport

A tangra v4 module, `teleport`, that manages self-hosted **Teleport Community
Edition** clusters from the tangra portal:

- register clusters with a least-privilege management identity kept in warden,
  and watch their health;
- manage Teleport users, roles, locks and join tokens;
- list enrolled resources and link them to inventory and asset records;
- search audit events and sessions, with alert rules delivered through notification;
- provision tangra users into Teleport from role mappings;
- guide the deployment of a new cluster.

Teleport stays the source of truth. The module talks to each cluster through
the official `github.com/gravitational/teleport/api` Go client over the
cluster's proxy address and stores only registrations, links, mappings, rules,
drafts and token metadata.

The specification, plan, research and contracts are in
[specs/001-teleport-cluster-management](specs/001-teleport-cluster-management/):
[spec](specs/001-teleport-cluster-management/spec.md),
[plan](specs/001-teleport-cluster-management/plan.md),
[research](specs/001-teleport-cluster-management/research.md),
[data model](specs/001-teleport-cluster-management/data-model.md),
[contracts](specs/001-teleport-cluster-management/contracts/),
[tasks](specs/001-teleport-cluster-management/tasks.md).

## Help pages

The user and operator documentation ships in the binary (`docs/help`) and is
served through the gateway's help centre:

- [Overview](docs/help/index.md) and [Get started](docs/help/getting-started.md)
- Guides: [users, roles and locks](docs/help/guides/users-roles-locks.md),
  [enroll resources](docs/help/guides/enroll-resources.md),
  [audit and alerts](docs/help/guides/audit-and-alerts.md),
  [provisioning](docs/help/guides/provisioning.md),
  [deploy a new cluster](docs/help/guides/deploy-new-cluster.md)
- Reference: [the tangra-manager role](docs/help/reference/tangra-manager-role.md),
  [permissions](docs/help/reference/permissions.md),
  [operations](docs/help/operations.md) (configuration, credential rotation,
  scheduled tasks, metrics, troubleshooting)

Deployment notes (dev stack, join bundle, peers): [deploy/README.md](deploy/README.md).

## Configuration reference

`teleportsvc -config <file>` reads one YAML file: the freya framework keys
(`service_name`, `trust_domain`, `env`, `identity`, `authz`, `server`,
`admin`, `discovery`, `limits`) plus the module sections below. Every value
is validated at start; insecure opt-outs are named and logged, and refused
when `env: production`. Example: [deploy/container.yaml](deploy/container.yaml).

| Key | Default | Meaning |
|---|---|---|
| `db.dsn`, `db.migrate_dsn`, `db.max_conns` | —, `dsn`, 16 | PostgreSQL/TimescaleDB (RLS). Production requires `sslmode=verify-full` or `verify-ca` |
| `valkey.addresses`, `username`, `password`, `ca_file`, `allow_plaintext` | —, —, —, —, false | Event bus, leases and read cache. Plaintext is refused in production |
| `secrets.warden_service`, `token_file` | `warden`, — | Where management credentials are resolved (`warden:` references) |
| `secrets.allow_file`, `file_dir` | false, — | Development: credentials as files (`file:` references); refused in production |
| `gateway.service`, `gateway.issuer` | `gateway`, — | Gateway registration and the platform token issuer (https) |
| `mesh_enroll.*` | off | Enrol with lcm for the mesh SVID; `insecure` is refused in production |
| `events.enabled` | true | Publish `teleport.*` events to `platform:events:<tenant>` |
| `events.tenant_stream`, `tenant_deleted_type` | —, `auth.tenant.deleted` | Optional tenant-deleted consumer (removes a deleted tenant's registrations and credentials) |
| `task_scheduler.enabled`, `service` | false, `scheduler` | Register the `teleport:*` task types with the scheduler |
| `teleport.allowed_private_networks` | `[]` | RFC 1918/CGNAT/ULA prefixes cluster addresses may resolve to (logged SSRF opt-out) |
| `teleport.allowed_ports` | `[443, 3080]` | Proxy ports that may be dialled |
| `teleport.call_timeout_seconds`, `max_message_bytes`, `max_concurrent_per_cluster` | 10, 4 MiB, 4 | Bounds on every Teleport call |
| `teleport.cache_ttl_seconds`, `probe_timeout_seconds` | 15, 5 | Read cache and deployment-check bounds |
| `thresholds.credential_warn_days` | 7 | Credential expiry warning (or 25 % of a short lifetime) |
| `thresholds.unreachable_after_failures` | 3 | Failed health checks before *unreachable* |
| `thresholds.offline_minutes` | 15 | Default resource offline threshold |
| `thresholds.deprovision_grace_days` | 7 | Lock-to-delete grace period of de-provisioned users |
| `limits_teleport.max_request_bytes`, `max_upload_bytes`, `max_page_size` | 1 MiB, 64 KiB, 200 | Browser request bounds |

## Security notes

- **Credentials are references.** A cluster's management identity is stored
  in warden (or, in development only, a `0600` file) and resolved at use
  time; the database, events, audit rows, logs, API responses and backups
  carry only the `warden:`/`file:` reference. Join tokens are stored as a
  SHA-256 hash; invite and reset links and token values are shown once and
  never stored or logged. `make redaction-scan` (SC-007) enforces this.
- **Least privilege on the cluster.** The module signs in as one Teleport
  user holding the documented `tangra-manager` role; the module refuses to
  delete, lock or reset that identity or its role, and refuses to delete
  Teleport's preset roles.
- **SSRF guard.** Every proxy address and deployment check is resolved and
  checked by `internal/netguard` (private, loopback, link-local and metadata
  addresses refused unless explicitly opened) and the connection is pinned
  to the checked address.
- **Tenant isolation.** Every table has row-level security; every route
  checks the caller's permission and the cluster's tenant; other tenants'
  clusters answer `404`.
- **Mesh policy.** Deny by default: the gateway reaches the HTTP surface
  only, inventory/asset/portal reach `teleport.v1.Access` read-only, the
  scheduler alone reaches the task executor.
- **Licensing.** Only the Apache-2.0 `github.com/gravitational/teleport/api`
  module is used; `make license` fails if any AGPL `teleport/lib` package
  enters the module graph.

Known cross-repository gaps (see plan.md, "Deviations"): warden has no
write RPC (production registration answers `dependency_unavailable`) and
inventory/asset have no host lookup (automatic linking answers
`dependency_unavailable`). Provisioning reads members from auth
`Profiles.Members` (auth policy rule `teleport-directory`).

## Layout

| Path | Contents |
|---|---|
| `cmd/teleportsvc` | `serve` (default), `bootstrap` (migrations) and `version` |
| `cmd/teleport-catalogue-permissions` | Prints the permission list for the catalogue entry |
| `api/openapi` | Browser API (`teleport.yaml`, every route with `x-freya-permission`) |
| `api/proto/teleport/v1` | Mesh API (`teleport.v1.Access`) |
| `internal/app` | Explicit wiring: freya, store, secrets, Teleport pool, events, gateway |
| `internal/config` | Typed, validated configuration |
| `internal/store`, `internal/repo`, `internal/repodb`, `internal/memstore`, `internal/repotest` | pgx + RLS store, repository contract, SQL and in-memory implementations, shared conformance suite |
| `internal/authz` | Permission and cluster-ownership checks |
| `internal/audit`, `internal/events`, `internal/stream` | Audit vocabulary and writer, platform events, SSE relay |
| `internal/secrets` | Secret references (`warden:`, dev `file:`) and the redacting `Secret` type |
| `internal/netguard` | SSRF-safe resolver and pinned dialler |
| `internal/teleportapi` | `Client` interface over teleport/api, fake, pool, limits, cache |
| `internal/lease` | Valkey leases for watcher and poller ownership |
| `internal/metrics` | Prometheus instruments |
| `internal/tasks` | Scheduler task types (`teleport:*`) |
| `internal/backup` | Tenant configuration export/import (references only) |
| `internal/httpapi`, `internal/grpcapi` | OpenAPI handlers, mesh gRPC |
| `pkg/teleportmanifest` | Gateway manifest: permissions, roles, grants, abilities, nav |
| `deploy` | Mesh policy (`policy.yaml` + test), container config, dev compose overlay, join bundle (`bundle/`) |
| `tangra-module.yaml` | Catalogue descriptor (spec 035) |
| `ui` | Vue 3 Module Federation remote |
| `tests/{contract,integration,security,fuzz}` | Cross-package suites |

## Development

```sh
make test              # unit tests (race detector)
make test-integration  # testcontainers suites (needs Docker)
make cover             # coverage gate (80% overall, 100% authz/netguard/secrets)
make lint              # vet, staticcheck, gosec and the license check
make vuln              # govulncheck
make redaction-scan    # no credential, token or invite link in captured output
make ui-build e2e      # federated UI build and Playwright suite (npm token, running stack)
make compose-up        # the module on the core dev stack (deploy/README.md)
```

CI (`.github/workflows/ci.yaml`) runs the help-page lint, vet, the unit and
coverage gates, the license and redaction checks, govulncheck, the UI lint
and unit tests, buf lint, the image build, and on `v*` tags the catalogue
entry.

Security reports: see [SECURITY.md](SECURITY.md).
