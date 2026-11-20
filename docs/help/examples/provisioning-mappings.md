---
title: "Example: role mappings for provisioning"
summary: Map tangra operators, auditors and an on-call group to Teleport roles and logins, see what each member gets, and run a sync - with the current limitation that sync needs auth member listing.
kind: example
order: 60
tags: [teleport, example, provisioning, mappings, roles, logins]
requires: provisioning:manage
---
**Goal.** People who are tangra *operators* should get Teleport access to
servers as `ubuntu`. *Auditors* should get Teleport's read-only `auditor`
role. Members of the on-call group should also get `deploy` logins. When
someone leaves, their Teleport access should go.

**What you need.** `provisioning:manage` (administrators only). The
Teleport roles you map to must already exist on the cluster.

> **Current limitation.** Mappings can be created and edited today, but
> **Sync now** and **Provision user** answer *dependency unavailable*.
> They need the auth service to list the tenant's members with their roles
> and groups, and auth does not offer that yet. Nothing is changed on the
> cluster in the meantime. See [known limitations](../known-limitations.md).

## 1. Prepare the Teleport roles

On the cluster (or on the **Roles** tab), make sure these exist. A minimal
`server-access` role:

```yaml
kind: role
version: v7
metadata:
  name: server-access
spec:
  allow:
    logins: ['{{internal.logins}}']
    node_labels:
      env: [staging, production]
```

`{{internal.logins}}` takes the user's logins, which is where the mapped
logins go. Teleport's built-in `auditor` role already exists.

## 2. Add the mappings

Open the cluster, go to **Provisioning** and choose **Add mapping** three
times:

| Map | Tangra role slug or group id | Teleport roles | Logins |
|---|---|---|---|
| module role | `operator` | `server-access` | `ubuntu` |
| module role | `auditor` | `auditor` | |
| group | `<on-call-group-id>` | `server-access` | `deploy` |

The same through the API (helpers from the [HTTP API](../reference/api.md)):

```bash
tsend -X POST "$API/clusters/$CLUSTER/mappings" -d '{
  "subject_kind": "module_role", "subject_ref": "operator",
  "teleport_roles": ["server-access"], "logins": ["ubuntu"]}'

tsend -X POST "$API/clusters/$CLUSTER/mappings" -d '{
  "subject_kind": "module_role", "subject_ref": "auditor",
  "teleport_roles": ["auditor"]}'

tsend -X POST "$API/clusters/$CLUSTER/mappings" -d '{
  "subject_kind": "group", "subject_ref": "<on-call-group-id>",
  "teleport_roles": ["server-access"], "logins": ["deploy"]}'
```

| Answer | Cause |
|---|---|
| `422 validation_failed`, `detail.field` `teleport_roles` | A Teleport role does not exist on the cluster |
| `422 validation_failed`, `detail.field` `logins` | A login is not 1 to 32 characters of letters, digits, `.`, `_`, `-` starting with a letter or `_` |
| `409 conflict` | There is already a mapping for that role slug or group |

To change a mapping's roles or logins, use **Edit** or
`PUT /clusters/{id}/mappings/{mid}` with `{"teleport_roles": [...], "logins": [...]}`.
What it maps cannot be changed. Remove it and add a new one.

## 3. What each member gets

A member who matches several mappings gets all of their roles and logins
combined:

| tangra member | Matches | Teleport user | Roles | Logins |
|---|---|---|---|---|
| `Dana.Smith` (operator, on-call) | operator, on-call group | `dana.smith` | `server-access` | `ubuntu`, `deploy` |
| `erik` (auditor) | auditor | `erik` | `auditor` | none |
| `fay` (viewer only) | none | not provisioned | | |

The Teleport username is the tangra login in lower case. Any character
other than letters, digits, `.`, `_`, `@` and `-` becomes `-`. If that
name is taken by a Teleport user the platform did not create, the member
is skipped and the conflict is recorded in the module audit trail. Hand-made
users are never changed.

## 4. Sync and provision

Once auth offers member listing, this is how you use it:

```bash
# Reconcile the whole cluster now (the scheduler also runs it every 15 minutes).
tsend -X POST "$API/clusters/$CLUSTER/provisioning/sync"
# {"created": 2, "updated": 0, "locked": 0, "unlocked": 0, "deleted": 0, "errors": 0}

# Provision one member at once. The invite goes to them through notifications.
tsend -X POST "$API/clusters/$CLUSTER/managed-users" -d '{"tangra_user_id": "<tangra-user-uuid>"}'

# Who is managed, and in which state.
tget "$API/clusters/$CLUSTER/managed-users" | jq -r '.items[] | [.teleport_username, .state] | @tsv'
```

Today both changing calls answer:

```json
{"reason": "dependency_unavailable",
 "detail": {"dependency": "auth", "message": "the tenant's membership cannot be read from auth; nothing was changed"}}
```

## 5. When someone leaves

If `erik` leaves the tenant, or loses the auditor role, the next sync
**locks** his Teleport user with the message `tangra de-provisioned`.
Before locking, the platform asks auth again to confirm he really lost
access. His sessions end within seconds. After the grace period (7 days by
default) the user is deleted and the lock goes with it. If he gets the
role back before then, the next sync removes the lock.
