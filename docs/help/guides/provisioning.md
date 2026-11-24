---
title: Provision tangra users into Teleport
summary: Map tangra roles or groups to Teleport roles and logins, provision members with an invite through notifications, and de-provision them automatically when they leave.
kind: guide
order: 50
tags: [teleport, provisioning, mappings, invite, de-provisioning, lock, sync, members, search]
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

1. Choose what to map: a **module role** of the Teleport module
   (**administrator**, **operator**, **auditor** or **viewer**, picked from
   the list) or a tangra **group** (type its id). Members match a module
   role whether they hold it directly or through a group. Built-in platform
   roles (such as `owner` or `member`), custom roles and other modules'
   roles are not reported to provisioning, so they cannot be mapped.
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
member at once, choose **Provision user** and search for them: type part of
their name or sign-in e-mail. The list shows each member's display name
and e-mail; the first members appear as soon as the dialog opens. Pick the
member and choose **Provision**.

- The Teleport username is the member's **sign-in e-mail** in lower case,
  for example `dana.smith@example.com`. Any character other than letters,
  digits, `.`, `_`, `@` and `-` is replaced by `-`. If that name is already
  taken by a Teleport user tangra did not create, or by the cluster's
  management identity, the member is **not** provisioned: the conflict is
  counted and recorded in the audit trail.
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

Provisioning reads the tenant's members (sign-in e-mail, display name,
Teleport module roles and groups) from the auth service. When auth cannot
be reached, **Sync now**, **Provision user** and the member search answer
*dependency unavailable* (`detail.dependency` `auth`) and nothing is
changed; mappings can still be edited, and the next sync catches up.

The platform operator must allow the module to ask auth: auth's service
policy needs the rule `teleport-directory`, which admits
`spiffe://<trust domain>/svc/teleport` to `/auth.v1.Profiles/Lookup`,
`/auth.v1.Profiles/ListMembers` and `/auth.v1.Profiles/Members`. Without
it every provisioning call is *dependency unavailable*.

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
