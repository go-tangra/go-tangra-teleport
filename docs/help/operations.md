---
title: Operate Teleport
summary: Configuration keys and defaults, credential rotation, the private-network opt-out, scheduled tasks, metrics, troubleshooting and service policies.
kind: reference
order: 90
tags: [teleport, operations, configuration, policy, metrics, troubleshooting]
audience: operator
---
Teleport runs as `teleportsvc` (image `ghcr.io/go-tangra/go-tangra-teleport`).
It needs PostgreSQL (with row-level security), Valkey and the platform's
auth, warden and gateway services. Notification, the scheduler and
inventory/asset are optional at run time: without them the affected
features report `dependency_unavailable` and everything else keeps working.

## Configuration

- `teleport.allowed_private_networks` — private CIDR ranges cluster proxy
  addresses and deployment checks may resolve to (see below).
- `teleport.allowed_ports` — proxy ports that may be dialled (default 443 and
  3080).
- `teleport.call_timeout_seconds`, `teleport.max_message_bytes`,
  `teleport.max_concurrent_per_cluster` — bounds on every Teleport call.
- `teleport.cache_ttl_seconds` — how long list pages read from Teleport are
  cached (default 15).
- `secrets.warden_service` — where cluster credentials are kept. File-backed
  credentials (`secrets.allow_file`, `secrets.file_dir`) are for development
  only and are refused in production.
- `thresholds.credential_warn_days` (default 7),
  `thresholds.unreachable_after_failures` (default 3),
  `thresholds.offline_minutes` (default 15),
  `thresholds.deprovision_grace_days` (default 7) — when a cluster is shown as
  *credential expiring* or *unreachable*, when a resource is flagged offline,
  and how long a de-provisioned user stays locked before it is deleted.
- `task_scheduler.enabled`, `task_scheduler.service` — register the
  scheduled tasks with the scheduler module (see below).
- `events.tenant_stream`, `events.tenant_deleted_type` — optional: the
  platform stream carrying tenant-deleted events. Empty by default.

## Private networks (`allowed_private_networks`)

Cluster addresses are resolved and checked before every connection: private
(RFC 1918, CGNAT, ULA), loopback, link-local and metadata addresses are
refused with `blocked_target`, and the connection is pinned to the checked
address. To manage a lab cluster on a private network, list its prefix:

```yaml
teleport:
  allowed_private_networks: ["10.20.0.0/16"]
```

Only RFC 1918, CGNAT and ULA prefixes are accepted; loopback and link-local
can never be opened. The opt-out is logged as a warning at every start. The
deployment wizard's prerequisite checks use the same policy.

## Rotate a management credential

1. On the cluster, issue a new identity for the management user:

   ```bash
   tctl auth sign --user=tangra-mgmt --format=file --ttl=720h --out=tangra-mgmt.identity
   ```

2. On the cluster page, choose **Rotate credential** and upload the file. The
   module signs in with it first (it must reach the same Teleport cluster)
   and only then replaces the stored one; a failed verification keeps the
   old credential.
3. The cluster's status is re-evaluated and the expiry warning clears.
   The rotation is audited (`teleport.credential.rotate`) and published as
   `teleport.credential.rotated`; the identity itself is never shown again.

A warning is sent at the threshold (7 days, or a quarter of the lifetime for
short-lived identities) and again one day before expiry. An expired
credential moves the cluster to *credential invalid*: writes are refused
until you rotate.

## Scheduled tasks

With `task_scheduler.enabled`, the module registers these tenant-scoped task
types with the scheduler. Each is idempotent and reports a retryable failure
when a step fails.

| Task | Default schedule | What it does |
|---|---|---|
| `teleport:health-check` | every minute | Pings each cluster; records status, counts, version and edition |
| `teleport:credential-expiry` | hourly | Warns before credentials expire and marks expired ones |
| `teleport:sync-provisioning` | every 15 minutes | Reconciles managed users with the role mappings |
| `teleport:purge-deprovisioned` | hourly | Deletes managed users past their grace period |
| `teleport:token-gc` | hourly | Prunes token metadata (7 days) and alert deliveries (30 days) |

Health checks, resource watchers, alert polling and the offline sweep also
run inside the module, one replica at a time, so alerting keeps working
while the scheduler is down. Only the scheduler may call the task executor.

## Metrics

| Metric | Meaning |
|---|---|
| `teleport.api.calls` | Teleport API calls by operation and result |
| `teleport.api.call` | Teleport API call latency (seconds) |
| `teleport.watchers` | Resource watchers by state |
| `teleport.alert.poll.lag` | How far audit polling is behind now (seconds) |
| `teleport.provisioning` | Provisioning outcomes by action and result |
| `teleport.credential.days_to_expiry.min` | Days until the soonest credential expiry |

Metric attributes carry identifiers only, never credentials or user names.

## Troubleshooting

- **`blocked_target` on registration** — the address resolves to a private,
  loopback or metadata address. Use the public proxy address, or open the
  range with `allowed_private_networks`.
- **Cluster stays *unreachable*** — the proxy did not answer three checks in
  a row. Check that the module's host reaches the proxy port (443 or 3080)
  and that the proxy certificate is valid; **Check now** on the cluster page
  runs a check at once.
- **`missing_permissions` on the cluster page** — the `tangra-manager` role
  lacks a grant; compare it with
  [the tangra-manager role](reference/tangra-manager-role.md).
- **Provisioning answers `dependency_unavailable` (auth)** — the platform's
  membership listing is not available yet; mappings can still be edited and
  nothing is changed on the cluster.
- **Links show `dependency_unavailable`** — automatic matching needs a host
  lookup in inventory and asset that is not available yet; confirm links by
  hand.
- **No notifications** — alerts and outage messages go to the recipients of
  the tenant's enabled alert rules; with no rule, or with notification down,
  the module only logs.

## Known limitations

warden has no write API yet, so in production cluster registration and
credential rotation answer `dependency_unavailable` and nothing is stored —
the identity is never kept anywhere else. Development stacks and the join
bundle set `secrets.allow_file: true` to store identities as files instead.
This and the other current limits (provisioning, automatic linking,
identity-file credentials, session playback) are listed in
[Known limitations](known-limitations.md).

## Backup

The module's configuration (cluster registrations with their credential
reference, role mappings, alert rules, deployment drafts and confirmed
links) is exported and restored by reference: no credential ever enters a
backup, so the referenced secrets must exist where the reference points.

## Service policy

`deploy/policy.yaml` admits the gateway to the HTTP surface, inventory, asset
and portal to the `Access` service, and the scheduler to the task executor;
everything else is denied.
