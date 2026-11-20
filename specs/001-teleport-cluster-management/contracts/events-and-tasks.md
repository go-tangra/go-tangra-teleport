# Contract: Platform Events and Scheduler Tasks

## Events published on `platform:events:<tenant_id>` (Valkey stream)

The envelope follows the framework `events` package: `{id, type, tenant_id, time, actor, data}`. The `data` field carries **identifiers only**: no secrets, no role YAML, no invite links, no token values (FR-025).

| Type | `data` |
|---|---|
| `teleport.cluster.registered` / `.updated` / `.removed` | `{cluster_id}` |
| `teleport.cluster.status_changed` | `{cluster_id, status}` |
| `teleport.credential.expiring` / `.rotated` | `{cluster_id, expires_at}` |
| `teleport.user.created` / `.updated` / `.deleted` | `{cluster_id, username}` |
| `teleport.role.changed` / `.deleted` | `{cluster_id, role}` |
| `teleport.lock.created` / `.removed` | `{cluster_id, lock_name, target_kind}` |
| `teleport.token.created` / `.revoked` | `{cluster_id, token_id, resource_type}` |
| `teleport.enrollment.changed` | `{cluster_id, enrollment_id, host_id, state}` (spec 002) |
| `teleport.resource.online` / `.offline` / `.flagged` | `{cluster_id, resource_id, kind}` |
| `teleport.resource.linked` / `.unlinked` | `{resource_id, target_module, target_id}` |
| `teleport.provisioning.changed` | `{cluster_id, tangra_user_id, state}` |

## Events consumed

| Source | Types | Handling |
|---|---|---|
| auth | Tenant membership removal and module-role/group changes | **None published** (research D10, T010): the periodic `teleport:sync-provisioning` alone meets SC-008. Every lock and delete re-verifies the member with auth first (SR-006). |
| auth | Tenant deleted | Remove all of the tenant's registrations and warden secrets. Teleport is untouched. |
| inventory / asset | Record created, updated or deleted (if published) | Re-run link matching for affected hostnames and IPs. Without these events, matching runs on snapshot changes and at `teleport:health-check`. |

## Scheduler task types (registered with `schedulerclient.Registrar`)

| Task type | Default schedule | Behaviour | Idempotent |
|---|---|---|---|
| `teleport:health-check` | every 1 min | Ping each cluster. Update status, counts, version and edition. Restart dead watchers. This is the backstop for D7 | yes |
| `teleport:credential-expiry` | hourly | Warn at the configured threshold, renew bot identities, mark expired credentials | yes |
| `teleport:sync-provisioning` | every 15 min | Full reconcile of managed users against mappings and memberships | yes |
| `teleport:purge-deprovisioned` | hourly | Delete managed users whose grace period has passed, and remove their lock | yes |
| `teleport:token-gc` | hourly | Prune token metadata expired more than 7 days ago, and alert deliveries older than 30 days | yes |

Each task runs per tenant, using the tenant carried in the task. The provisioning
tasks call `provisioning.Service.Reconcile(ctx, tenantID, clusterID)` (once per
cluster of the tenant) and `provisioning.Service.PurgeDeprovisioned(ctx,
tenantID)`; a context without a caller runs as the worker
`provisioning-sync` of that tenant. A failed run returns an error to the scheduler, which applies its retry policy. Watchers, alert pollers and the offline sweep run inside the module under Valkey leases, so alerting keeps working when the scheduler is unavailable (FR-034).

## Notifications (through the notification module)

| Template key | Trigger | Recipients |
|---|---|---|
| `teleport.alert` | Alert rule match (Teleport events: vars `condition, rule_id, rule_name, cluster_id, display_name, cluster_name, event_id, event_type, event_code, user, resource, summary, time, count, window_minutes`; module conditions: the caller's vars plus `condition, rule_id, rule_name`) | Rule recipients (`user_ids`) |
| `teleport.cluster_unreachable` | Status changes to unreachable | Rule recipients, or else the tenant's module administrators |
| `teleport.credential_expiring` | Threshold reached, or expired | Module administrators |
| `teleport.invite` | Managed user provisioned or reset | The tangra user. The invite URL is in the message body only, and the notification module's log redaction applies to it |
