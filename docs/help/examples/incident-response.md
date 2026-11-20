---
title: "Example: respond to an incident with locks"
summary: Cut off a compromised user, a risky role or one server within seconds, find out what happened in the audit log, and lift the locks again when the incident is closed.
kind: example
order: 30
tags: [teleport, example, incident, locks, audit, security]
requires: locks:manage
---
**Situation.** At 14:05 the security team reports that Alice's laptop was
stolen. Her Teleport user `alice` may be in use by someone else, and the
staging server she was working on might be affected.

**What you need.** `locks:manage` (operators and administrators) to lock
and unlock. `audit:read` (auditors, operators and administrators) to look
at the audit log.

## 1. Lock the user first

Open the cluster, go to **Locks** and choose **Create lock**:

| Field | Value |
|---|---|
| Target | **User** `alice` |
| Reason | `INC-1234: laptop stolen, access suspended` |
| Expires | leave empty: the lock stays until you remove it |

Teleport enforces the lock within seconds. Alice's open SSH, Kubernetes,
database and application sessions end, and new ones are refused. Teleport
shows the reason to whoever tries to use the account. The module audit
trail records it as `teleport.lock.create`.

The same through the API (helpers from the [HTTP API](../reference/api.md)):

```bash
tsend -X POST "$API/clusters/$CLUSTER/locks" \
  -d '{"target_kind": "user", "target": "alice", "reason": "INC-1234: laptop stolen, access suspended"}'
```

```json
{"name": "tangra-<uuid>", "target_kind": "user", "target": {"user": "alice"},
 "message": "INC-1234: laptop stolen, access suspended", "created_by": "<your tangra user id>"}
```

Keep the `name`: you need it to remove the lock.

## 2. Widen the lock if needed

| Situation | Target kind | `target` |
|---|---|---|
| A role was handed out too widely | `role` | the role name, for example `support`. Every holder is locked |
| One server is suspect | `server_id` | the server's host ID (a UUID, shown on the **Resources** tab and by `tctl nodes ls`) |
| A short block during the investigation | any | add `"expires_at": "2026-11-20T18:00:00Z"`. It must be in the future |

```bash
tsend -X POST "$API/clusters/$CLUSTER/locks" \
  -d '{"target_kind": "server_id", "target": "<host-id>", "reason": "INC-1234: forensic hold"}'
```

You cannot lock the platform's own management identity, or a role it
holds (`tangra-manager`). The answer is `403 forbidden` with
`detail.guard` set to `self_identity` or `management_role`. This keeps
the platform connected while you deal with the incident.

## 3. Find out what happened

On the **Events** tab, search from just before the theft until now. The
same searches through the API:

```bash
# Everything alice did since 13:00 UTC.
tget "$API/clusters/$CLUSTER/events?from=2026-11-20T13:00:00Z&to=2026-11-20T15:00:00Z&user=alice"

# Sessions and commands on the suspect server.
tget "$API/clusters/$CLUSTER/events?from=2026-11-20T13:00:00Z&to=2026-11-20T15:00:00Z&types=session.start&types=exec&resource=staging-web-01"

# Failed sign-ins as alice: someone trying her password?
tget "$API/clusters/$CLUSTER/events?from=2026-11-20T13:00:00Z&to=2026-11-20T15:00:00Z&types=user.login.failure&user=alice"
```

The **Sessions** tab lists the recorded sessions that ended in the range.
**Play in Teleport** opens a recording in the Teleport web UI, where you
sign in with your own Teleport account.

## 4. Clean up and lift the locks

When the incident is closed:

1. **Reset** `alice` on the **Users** tab. This invalidates her password
   and second factors and gives you a new one-time link to send her.
2. Remove the locks on the **Locks** tab (**Remove lock**), or:

   ```bash
   tget "$API/clusters/$CLUSTER/locks"                          # find the names
   tsend -X DELETE "$API/clusters/$CLUSTER/locks/tangra-<uuid>"
   ```

3. Review the module audit trail for the incident window:

   ```bash
   tget "$API/audit?cluster_id=$CLUSTER&action=teleport.lock.create&from=2026-11-20T13:00:00Z"
   ```

## Tip: get warned next time

An alert rule on `lock.created` tells the on-call team whenever anyone
locks anything, from the portal or from `tctl`. A failed-login burst rule
catches password guessing. Both are in the
[audit and alerts example](audit-and-alerts.md).
