---
title: "Example: role mappings for provisioning"
summary: Map tangra operators, auditors and an on-call group to Teleport roles and logins, see what each member gets, find a member by name and run a sync.
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

> **Auth.** Sync and provisioning read the tenant's members from the auth
> service. While auth cannot be reached they answer *dependency
> unavailable* and nothing is changed on the cluster. See
> [provisioning](../guides/provisioning.md).

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
| `Dana.Smith@example.com` (operator, on-call) | operator, on-call group | `dana.smith@example.com` | `server-access` | `ubuntu`, `deploy` |
| `erik@example.com` (auditor) | auditor | `erik@example.com` | `auditor` | none |
| `fay@example.com` (viewer only) | none | not provisioned | | |

The Teleport username is the member's sign-in e-mail in lower case. Any character
other than letters, digits, `.`, `_`, `@` and `-` becomes `-`. If that
name is taken by a Teleport user the platform did not create, the member
is skipped and the conflict is recorded in the module audit trail. Hand-made
users are never changed.

## 4. Sync and provision

Through the API:

```bash
# Reconcile the whole cluster now (the scheduler also runs it every 15 minutes).
tsend -X POST "$API/clusters/$CLUSTER/provisioning/sync"
# {"created": 2, "updated": 0, "locked": 0, "unlocked": 0, "deleted": 0, "errors": 0}

# Find a member by part of their name or sign-in e-mail (at most 50, default 20).
tget "$API/clusters/$CLUSTER/provisioning/members?q=dana&limit=5"
# {"items": [{"user_id": "<tangra-user-uuid>", "display_name": "Dana Smith", "login": "dana.smith@example.com"}]}

# Provision one member at once. The invite goes to them through notifications.
tsend -X POST "$API/clusters/$CLUSTER/managed-users" -d '{"tangra_user_id": "<tangra-user-uuid>"}'

# Who is managed, and in which state.
tget "$API/clusters/$CLUSTER/managed-users" | jq -r '.items[] | [.teleport_username, .state] | @tsv'
```

While auth cannot be reached, these calls answer:

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
