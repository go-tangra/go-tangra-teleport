---
title: Teleport permissions
summary: Every permission of the Teleport module, what it allows, and which module role holds it.
kind: reference
order: 80
tags: [teleport, permissions, roles, access]
requires: clusters:read
---
Access to the Teleport module is granted with module roles. Each role is a
set of the permissions below; the platform's built-in roles map to them
(owner and admin → administrator, operator → operator, auditor → auditor,
member → viewer).

## Permissions

| Permission | Allows |
|---|---|
| `clusters:read` | List and view clusters and their health, and the live event stream |
| `clusters:manage` | Register, edit and remove clusters and rotate their credential |
| `users:read` | List and view Teleport users, managed users and role mappings |
| `users:manage` | Create, edit, reset and delete Teleport users |
| `roles:read` | List and view Teleport roles |
| `roles:manage` | Create, edit and delete Teleport roles (administrators only) |
| `locks:read` | List active locks |
| `locks:manage` | Create and remove locks |
| `tokens:manage` | Create, list and revoke join tokens |
| `resources:read` | List enrolled resources and their inventory and asset links |
| `resources:link` | Confirm or remove inventory and asset links |
| `resources:enroll` | Enroll inventory hosts as SSH nodes through their inventory agent |
| `audit:read` | Read Teleport audit events and sessions and the module audit trail |
| `alerts:read` | List alert rules |
| `alerts:manage` | Create, edit and delete alert rules |
| `provisioning:manage` | Manage role mappings and provision or de-provision tangra users |
| `deployments:manage` | Use the deployment wizard: drafts, artifacts and checks |
| `access:terminal` | See your own Teleport access on a cluster, list the nodes you can reach and open terminals in the portal as your provisioned Teleport user (needs an MFA portal session) |
| `access:download` | Download a short-lived identity file for `tsh` as your provisioned Teleport user (needs an MFA portal session) |
| `sessions:play` | Play recorded SSH sessions in the portal. A recording shows everything that was on the terminal, so this is separate from `audit:read`, which only lists sessions; every playback is audited |

## Module roles

| Role | Permissions |
|---|---|
| Administrator | Every permission above, including `sessions:play` and `access:download` (the only role that holds them) |
| Operator | Every `:read` permission, plus `tokens:manage`, `locks:manage`, `resources:link`, `resources:enroll` and `access:terminal` |
| Auditor | Every `:read` permission, including `audit:read` |
| Viewer | Every `:read` permission except `audit:read` |

Writes are also refused, whatever the role, for the management identity and
its role (it cannot be deleted, locked or reset) and for Teleport's preset
roles (they cannot be deleted). Every refused request is recorded in the
module audit trail.

## Related

- [The tangra-manager role](tangra-manager-role.md) — what the platform
  itself may do on each cluster.
- [Operate Teleport](../operations.md) — configuration and service policies.
- [HTTP API](api.md) — the permission each route needs.
