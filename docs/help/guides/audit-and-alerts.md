---
title: Audit events, sessions and alerts
summary: Search a cluster's Teleport audit log and recorded sessions, get notified about failed-login bursts and other events, and review what the module itself changed.
kind: guide
order: 40
tags: [teleport, audit, events, sessions, playback, alerts, notifications, failed-login]
requires: alerts:read
---
The module reads Teleport's own audit log live: it does not copy events
into tangra. You need the **audit** permission (`audit:read`) for the event
and session views and the module audit trail. Auditors, operators and
administrators have it. The viewer role does not, so viewers see neither
tab.

## Search audit events

Open a cluster and choose the **Events** tab.

1. Pick a **time range**: the last hour, 24 hours, 7 days or 31 days, or a
   custom start and end. A search covers **at most 31 days**. Without a
   range, or with a longer one, the search is refused.
2. Optionally narrow it to one **event type**, a **user** (exact name) or a
   **resource** (part of a server, app, database, Kubernetes cluster or
   desktop name).
3. Choose **Search**. Events come back newest first, up to 100 at a time;
   **Load more** fetches the next page of the same search.

Every row shows the time, the event type, the user, the resource and a
short summary. A failed sign-in is its own type, `user.login.failure`, and
is marked **failed**. **Show the raw event** opens Teleport's full record
(at most 16 KiB; a larger event shows only its top-level fields and
`"truncated": true`).

Only these event types are searched and can be alerted on:

| Area | Event types |
|---|---|
| Sign-in | `user.login`, `user.login.failure` |
| Users | `user.create`, `user.update`, `user.delete`, `user.password_change`, `reset_password_token.create` |
| Sessions | `session.start`, `session.end`, `session.join`, `session.leave`, `exec`, `app.session.start`, `db.session.start`, `windows.desktop.session.start` |
| Roles and locks | `role.created`, `role.updated`, `role.deleted`, `lock.created`, `lock.deleted` |
| Access | `access_request.create`, `access_request.review`, `cert.create` |

Names and text in events come from Teleport. The module shows them as
plain text and never as formatted content.

## Recorded sessions

The **Sessions** tab lists the sessions that ended in the chosen range,
newest first: when they started, the type (server, Kubernetes, database,
application or desktop), the target, the participants and how long they
lasted. **Open in Teleport** opens the recording in the Teleport web UI in
a new tab; you sign in to Teleport there with your own Teleport account.
SSH sessions also have **Play**, which plays the recording inside the
portal for users with the `sessions:play` permission (administrators): see
[play recorded SSH sessions](session-playback.md).

## Alert rules

Open **Teleport → Alerts**. Everyone with `alerts:read` sees the rules;
only administrators (`alerts:manage`) can create, edit or delete them.

A rule has:

- a **name**;
- a **cluster**, or **All clusters**. You cannot change this after the rule
  is created;
- what it **alerts when**:
  - **Teleport events**: one or more event types from the list above.
    Without a burst setting, every matching event alerts. With **Only on a
    burst by one user**, the rule alerts when one user causes at least *N*
    matching events within *W* minutes (*N* from 1 to 1000, *W* from 1 to
    1440). Example: at least 3 `user.login.failure` within 5 minutes;
  - **Cluster unreachable**, **Credential expiring** or **Resource
    offline**: conditions the module detects itself;
- the **recipients**: the tangra user ids to notify, one per line;
- **Enabled**: turn it off to keep the rule without alerting.

Alerts go out through the platform's notification module, as the
`teleport.alert` message, with the cluster, user, resource and time. They
arrive within about a minute of the event, well inside the 5-minute target.

How alerts behave:

- **Once per window.** An any-match rule alerts once per event. A burst
  rule alerts once per user and window, so a long attack does not flood
  you.
- **Nothing is lost while notification is down.** The module holds its
  place in the audit log and retries every 30 seconds. A recipient can get
  the same alert twice after an outage. A message the notification module
  keeps refusing for an hour is dropped and logged.
- **No backlog for new rules.** A new rule starts with events from now on.
- The cluster setting **Alerts enabled** switches all alerts for that
  cluster on or off.

## The module audit trail

**Teleport → Audit** lists every change the module made or tried to make:
cluster registrations and credential rotations, users, roles, locks, join
tokens, links, alert rules and delivered alerts. Each record shows who
acted (a person, another module, or a background job), the cluster, the
action, the target and the outcome, with a reason for failures. Filter by
cluster, action, outcome or time.

The trail never contains identity files, join tokens, invite links or role
definitions. A role change is recorded with fingerprints of the old and new
definition only.

## Troubleshooting

| Message | What to do |
|---|---|
| *Validation failed* on a search | Choose a range of at most 31 days, with both a start and an end. |
| *Forbidden* on Events or Sessions | You need `audit:read`. Ask an administrator for the auditor role. |
| *The Teleport cluster did not answer* | The cluster is unreachable. Check its status on the overview tab. |
| No alert arrives | Check that the rule is enabled, the cluster's **Alerts enabled** setting is on, and the recipients are tangra user ids. The management identity must be allowed to read `event` and `session` (see [the tangra-manager role](../reference/tangra-manager-role.md)). |

## Examples

[Audit searches and alert rules](../examples/audit-and-alerts.md) has
ready-made searches and the failed-login burst, resource-offline and
lock rules, in the portal and through the API.
