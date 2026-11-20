---
title: "Example: audit searches and alert rules"
summary: Ready-made audit searches with filters and time windows, a failed-login burst rule, a resource-offline rule and a lock-watch rule, in the portal and through the API.
kind: example
order: 50
tags: [teleport, example, audit, events, alerts, failed-login, offline]
requires: audit:read
---
**What you need.** `audit:read` for searches (auditors, operators and
administrators). `alerts:manage` to create rules (administrators). The
examples use the helpers from the [HTTP API](../reference/api.md)
reference. All times are UTC, in RFC 3339 format.

## Audit searches

A search needs a start (`from`) and an end (`to`) at most **31 days**
apart. The portal's **Time range** offers the last hour, 24 hours, 7 days
and 31 days, or **From**/**To** for a custom range. Results come newest
first.

| Question | Filters |
|---|---|
| Who failed to sign in today? | **Event type** `user.login.failure`, last 24 hours |
| What did `bob` do last week? | **User** `bob`, last 7 days |
| Who opened sessions on database servers? | **Event type** `db.session.start`, **Resource** `postgres` |
| Who changed roles this month? | **Event type** `role.updated` (and `role.created`, `role.deleted` through the API) |
| Which locks were set during the incident? | **Event type** `lock.created`, custom range |

The same searches through the API. Repeat `types` to give several event
types:

```bash
# Failed sign-ins in the last 24 hours (GNU date).
FROM=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ); TO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
tget "$API/clusters/$CLUSTER/events?from=$FROM&to=$TO&types=user.login.failure"

# Everything bob did in a fixed week, 200 per page.
tget "$API/clusters/$CLUSTER/events?from=2026-11-09T00:00:00Z&to=2026-11-16T00:00:00Z&user=bob&limit=200"

# Every role change in November.
tget "$API/clusters/$CLUSTER/events?from=2026-11-01T00:00:00Z&to=2026-12-01T00:00:00Z&types=role.created&types=role.updated&types=role.deleted"

# The next page: send next back unchanged, with the same window and filters.
tget "$API/clusters/$CLUSTER/events?from=2026-11-01T00:00:00Z&to=2026-12-01T00:00:00Z&types=role.updated&next=<next>"

# Recorded sessions that ended yesterday, with playback links.
tget "$API/clusters/$CLUSTER/sessions?from=2026-11-19T00:00:00Z&to=2026-11-20T00:00:00Z" |
  jq -r '.items[] | [.started_at, .kind, .user, .target, .playback_url] | @tsv'
```

How the filters match:

- **user** is an exact name, case-insensitive;
- **resource** matches part of the server, app, database, Kubernetes
  cluster or desktop name;
- **types** must be from the
  [supported event types](../guides/audit-and-alerts.md#search-audit-events).
  Without it, all supported types are searched;
- a missing window, or one over 31 days, is `422 validation_failed`.

Each event has `time`, `type`, `code`, `user`, `resource`, `success`,
`summary` and `raw`, which is Teleport's own record and at most 16 KiB.

**The module's own audit trail** lists what the platform did, not what
users did in Teleport:

```bash
# Failed module actions on one cluster this week.
tget "$API/audit?cluster_id=$CLUSTER&outcome=failure&from=2026-11-16T00:00:00Z&order=desc"

# Every credential rotation.
tget "$API/audit?action=teleport.credential.rotate"
```

## Alert rules

Alerts go to the tangra users you list as recipients, through the
platform's notification module, as `teleport.alert` messages. They arrive
within about a minute. Open **Teleport → Alerts** to manage rules.
Recipient user ids are entered one per line.

### Rule 1: a failed-login burst

Alert when one user fails to sign in at least 3 times within 5 minutes,
on every cluster:

| Field | Value |
|---|---|
| Name | `Failed-login burst` |
| Cluster | **All clusters** |
| Alert when | **Teleport events**, **Event type** `user.login.failure` |
| Only on a burst by one user | on: **At least (events)** `3`, **Within (minutes)** `5` |
| Recipients | `<security-lead-user-id>` and `<on-call-user-id>` |

```bash
tsend -X POST "$API/alert-rules" -d '{
  "name": "Failed-login burst",
  "condition_kind": "teleport_event",
  "event_types": ["user.login.failure"],
  "threshold_count": 3,
  "window_minutes": 5,
  "recipients": {"user_ids": ["<security-lead-user-id>", "<on-call-user-id>"]}
}'
```

A burst alerts **once per user and window**. If someone keeps guessing
`alice`'s password for an hour, you get one alert per 5-minute window,
not one per attempt. `threshold_count` (1 to 1000) and `window_minutes` (1
to 1440) must be set together, or both left out.

### Rule 2: a resource went offline

Alert when an enrolled server, app, database or Kubernetes cluster on the
production cluster has been offline longer than the cluster's offline
threshold:

| Field | Value |
|---|---|
| Name | `Production resource offline` |
| Cluster | `Production` |
| Alert when | **Resource offline** |
| Recipients | `<ops-team-lead-user-id>` |

```bash
tsend -X POST "$API/alert-rules" -d '{
  "cluster_id": "018f3a2b-0000-7000-8000-000000000001",
  "name": "Production resource offline",
  "condition_kind": "resource_offline",
  "recipients": {"user_ids": ["<ops-team-lead-user-id>"]}
}'
```

The threshold is a cluster setting (15 minutes by default). To change it,
use **Resource offline after (minutes)** when editing the cluster, or:

```bash
tsend -X PATCH "$API/clusters/$CLUSTER" -d '{"settings": {"offline_threshold_minutes": 30}}'
```

Each resource alerts once when it is flagged. If it comes back, it turns
online again by itself. **Cluster unreachable** (`cluster_unreachable`)
and **Credential expiring** (`credential_expiring`) rules look the same:
no event types and no threshold.

### Rule 3: every lock

Tell the on-call team about every lock, whether it was set from the
portal or with `tctl`:

```bash
tsend -X POST "$API/alert-rules" -d '{
  "name": "Lock created",
  "condition_kind": "teleport_event",
  "event_types": ["lock.created"],
  "recipients": {"user_ids": ["<on-call-user-id>"]}
}'
```

Without a threshold, every matching event alerts.

### Changing and switching off rules

- `PUT /alert-rules/{id}` replaces every field. Send the whole rule.
  The cluster cannot be changed: delete the rule and create a new one.
- `"enabled": false` keeps the rule without alerting. A rule that is
  enabled again starts from now and does not replay old events.
- The cluster setting `alerts_enabled` switches all alerts for one cluster
  on or off.
- `422 validation_failed` names the field. For example
  `{"field": "threshold_count", "message": "must be 1 to 1000 with a window"}`,
  or `event_types` for a module condition that was given event types.

If no alert arrives, check the rule is enabled, the cluster's alerts are
on, and the recipients are tangra **user** ids. The management identity
must also be allowed to read `event` and `session` (see
[the tangra-manager role](../reference/tangra-manager-role.md)).
