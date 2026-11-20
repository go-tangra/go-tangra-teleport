# Implementation Plan: Agent SSH enrollment

**Branch**: `002-agent-ssh-enrollment` | **Spec**: [spec.md](spec.md)

## Summary

An operator picks inventory hosts; the teleport module asks inventory
(`TeleportJoinDeliveryService/CreateTeleportJoin`) to queue a
reference-only `COMMAND_TYPE_TELEPORT_JOIN` for each host's agent. When the
agent fetches the item, inventory calls back
`inventory.v1.TeleportJoinSource/RenderTeleportJoin` on the module, which
mints a single-use Node token (30 minutes) and returns it with the proxy
address, the cluster's CA pins, its Teleport version and the labels
computed from the host's current inventory facts. The agent installs the
release tarball, joins and reports to inventory; the module reads the
progress back (`GetTeleportJoins`) on list and in a leased sweep and
confirms the inventory link when the node has joined.

## Technical context

- Go 1.26, the module's existing layering: `repo` (+ memstore, repodb,
  conformance suite), domain services behind `clusters.Service` (authz and
  pooled Teleport client), `httpapi` (OpenAPI-declared routes),
  `grpcapi` (mesh servers with a peer re-check), leased workers.
- Contract: the inventory SDK `github.com/go-tangra/go-tangra-inventory/sdk/v4`
  at the `038-teleport-join-delivery` pseudo-version. The Source service is
  defined there and implemented here, so the dependency only points
  teleport → inventory SDK.
- Storage: migration `0004_enrollment.sql` (RLS like every tenant table).
  No token column: the issued token is recorded as an ordinary
  `join_token` row (hash only, `created_by = enrollment:<id>`), so it shows
  in the Tokens tab and can be revoked.

## Decisions

| Decision | Choice | Why |
| --- | --- | --- |
| Progress path | Module polls `GetTeleportJoins` (list + 1-minute sweep) | Inventory never needs to call the module except to render; one direction for writes |
| Render caller | `authz.Worker(tenant, "enrollment-render")` with `resources:enroll` in the worker set | The agent acts on a request a user made; no user is present at fetch time |
| Render refusals | All `NotFound` (wrong host, item, tenant, finished, expired, 5 renders spent) | Inventory fails the item on NotFound; the caller learns nothing more |
| CA pins | `GetClusterCACert`, SHA-256 of each TLS CA's SPKI (`sha256:<hex>`) | What `teleport start --ca-pin` expects; needs no extra role rule |
| Labels | Computed at render time from `ListTeleportJoinTargets(host_ids)`; fallback to host id + stored hostname | Facts are fresh when the node is configured |
| State order | Unfinished states never move backwards | A render moves the row to `fetched` before inventory says so |
| Action routes | `/enrollments/{eid}/cancel` and `/retry` | Go's ServeMux matches whole segments (`{eid}:cancel` is not a pattern) |
| Link | Confirmed `inventory` link on the node's snapshot (`teleport_name = host UUID`), retried by the sweep until expiry | The watcher may see the node after inventory reports `joined` |

## Deviations

- US3 (label refresh on fact change) is not implemented: labels are set
  once at join. Tracked in tasks.md.
- Agent-side work (FR-012…014, US4) and inventory-side work (FR-008, FR-009)
  live in the inventory repository (feature 038).
