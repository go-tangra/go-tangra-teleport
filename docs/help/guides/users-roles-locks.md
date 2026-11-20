---
title: Manage users, roles and locks
summary: Create Teleport users with a one-time invite link, edit roles as YAML with a preview, and lock a user, role or server during an incident.
kind: guide
order: 20
tags: [teleport, users, roles, locks, invite, incident]
requires: users:read
---
Open a cluster and choose the **Users**, **Roles** or **Locks** tab. Lists
are read live from Teleport, so changes made with `tctl` show up within a
few seconds.

Who can do what:

| Task | Permission | Module roles |
|---|---|---|
| View users, roles and locks | `users:read`, `roles:read`, `locks:read` | administrator, operator, auditor, viewer |
| Create, edit, reset and delete users | `users:manage` | administrator |
| Create, edit and delete roles | `roles:manage` | administrator only |
| Create and remove locks | `locks:manage` | administrator, operator |

## Users

1. Choose **New user**, enter the username, one or more roles (for example
   `access`) and the OS logins the user may use (for example `ubuntu`).
2. Choose **Create and invite**. The dialog shows the sign-up link and when
   it expires.

The invite link is shown **once**. Copy it and send it to the user over a
trusted channel. The platform does not store, log or audit it, and it cannot
be shown again. If the link is lost or expires, use **Reset** on the user to
issue a new one-time link (this also resets their password and second
factors).

To change a user's roles or logins choose **Edit**. If someone changed the
user in Teleport after you opened it, the platform refuses the save and
reloads the current values; review them and save again.

Users the platform provisions from tangra identities carry a **managed**
badge. A **locked** badge means a lock on that user is in force.

## Roles

Roles are edited as YAML, the format `tctl get role/<name>` prints. Only
`kind: role` with `version: v7` or `v8` is accepted, at most 64 KiB.

1. Select a role to open its definition, or choose **New role**.
2. Edit the YAML and choose **Preview changes**. The platform validates the
   definition with Teleport's own rules and shows a diff against the current
   role. Nothing changes yet.
3. Choose **Apply** and confirm. Teleport applies the role at once to every
   user who holds it.

If the role changed in Teleport since you opened it, **Apply** is refused;
choose **Reload** to start from the current definition. When Teleport itself
rejects a definition, its message is shown.

Built-in Teleport roles (such as `access`, `editor` and `auditor`) carry a
**built-in** badge. They can be edited but not deleted.

## Locks

A lock cuts off a user, every holder of a role, or one server, including
sessions already open. Use it first during an incident.

1. Choose **Create lock**, pick the target kind and enter the user, role or
   server host ID.
2. Enter the reason (required). Teleport shows it to the locked-out user and
   the platform records it in the audit trail.
3. Optionally set an expiry; otherwise the lock stays until you remove it.

Teleport enforces a new lock within seconds. The list shows each active lock
with its reason, author and expiry. Choose **Remove lock** to lift it.

## What the platform refuses

The platform manages the cluster through one management identity (shown on
the cluster page). To keep the platform connected it refuses to:

- edit, reset, delete or lock the management identity;
- delete or lock a role the management identity holds (`tangra-manager`);
- delete a built-in Teleport role.

Change the management identity with `tctl` on the cluster instead. Clusters
running an unsupported Teleport version are read-only until upgraded.

Every change, and every refused change, is recorded in the module audit
trail with who did it, the cluster and the target. Role changes record a
fingerprint of the definition before and after, never the YAML itself.

## Examples

- [Onboard a user and adjust a role](../examples/users-and-roles.md)
- [Respond to an incident with locks](../examples/incident-response.md)
