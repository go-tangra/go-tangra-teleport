---
title: Provision tangra users into Teleport
summary: Map tangra roles or groups to Teleport roles and logins, provision members with an invite through notifications, and de-provision them automatically when they leave.
kind: guide
order: 50
tags: [teleport, provisioning, mappings, invite, de-provisioning, lock, sync]
requires: users:read
---
Provisioning keeps a cluster's Teleport users in line with tangra: members
who hold a mapped tangra role or group get a Teleport user with the mapped
roles and logins, and lose it when they leave the tenant or the role.
Anyone with the **users** read permission sees the mappings and the managed
users. Only **administrators** (`provisioning:manage`) can change mappings,
provision a user or run a sync; operators cannot.

## Map tangra roles to Teleport roles

Open a cluster and choose the **Provisioning** tab, then **Add mapping**.

1. Choose what to map: a tangra **module role** (its slug, for example
   `operator`) or a tangra **group** (its id).
2. Enter the **Teleport roles** to grant, separated by commas. Each one must
   already exist on the cluster; a role the cluster lacks is refused.
3. Optionally enter **logins** (for example `ubuntu`): the operating-system
   users the member may connect as. Logins are letters, digits, `.`, `_` and
   `-`, and start with a letter or `_`.

A member who matches several mappings gets the union of their roles and
logins. **Edit** changes a mapping's roles and logins; to change what it
maps, remove it and add a new one.

## Provision users

Members are provisioned at each **sync** (every 15 minutes once the
platform scheduler runs the task, or now with **Sync now**). To provision one
member at once, choose **Provision user** and enter their tangra user id.

- The Teleport username is the member's tangra login in lower case, with any
  character other than letters, digits, `.`, `_`, `@` and `-` replaced by
  `-`. If that name is already taken by a Teleport user tangra did not
  create, or by the cluster's management identity, the member is **not**
  provisioned: the conflict is counted and recorded in the audit trail.
- The member receives the **invite link** through tangra notifications. The
  link is never shown on this page, logged or stored. If the invite cannot
  be delivered, the Teleport user is removed again and the member shows
  **Error** until the next sync retries.
- Users tangra creates carry the labels `tangra.io/managed`,
  `tangra.io/tenant` and `tangra.io/user`. Only users with these labels are
  ever changed automatically; users created by hand are left alone.

## De-provisioning

When a member leaves the tenant or no longer matches any mapping, the next
sync **locks** their Teleport user (lock message `tangra de-provisioned`),
which ends their sessions within seconds. The user is **deleted** after the
grace period (7 days by default, set by the operator of the deployment), and
the lock is removed with it. If the member regains a mapped role before
then, the next sync removes the lock and the user is **Active** again.

Before any lock or delete the module asks the auth service again whether
the member really lost access, so a stale or forged change never locks
anyone.

## When provisioning is unavailable

Provisioning needs the auth service to list the tenant's members with their
roles and groups. When that is not possible, **Sync now** and **Provision
user** answer *dependency unavailable* and nothing is changed; mappings can
still be edited. In this release the auth service does not yet offer that
listing, so provisioning stays unavailable until it does.

## Managed users

The **Managed users** table shows each Teleport user tangra provisioned,
its tangra user, its state (**Active**, **Locked, pending deletion** with the
deletion time, or **Error**) and when it was last synced. The sync summary
counts users created, updated, unlocked, locked and deleted, and the ones
to retry.

## Examples

[Role mappings for provisioning](../examples/provisioning-mappings.md)
walks through three mappings and what each member gets. See also
[known limitations](../known-limitations.md).
