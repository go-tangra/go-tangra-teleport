---
title: Play recorded SSH sessions
summary: Watch a recorded SSH session inside the portal - play, pause, speed, seek and skip idle - with the sessions:play permission; every playback is audited and nothing is copied out of Teleport.
kind: guide
order: 45
tags: [teleport, sessions, playback, recording, ssh, audit, sessions-play]
requires: audit:read
---
You can watch a recorded SSH session in the portal without signing in to
Teleport. The recording stays in Teleport: the module reads it live from
the cluster with its management identity while you watch, and keeps no
copy of it anywhere.

## Who can watch

Watching needs its own permission, **`sessions:play`**, because a
recording shows everything that was on the terminal, including any secret
that was printed. Listing sessions still needs only `audit:read`.

- Only the **administrator** module role holds `sessions:play` (and so the
  platform's owner and admin roles). Auditors, operators and viewers do not.
- Without it the **Sessions** tab shows the sessions but no **Play**
  button, and a direct request for a recording is refused as forbidden.
- Sessions of a cluster registered in another tenant are not found.

## Watch a session

1. Open a cluster and choose the **Sessions** tab.
2. Pick the session. **Play** appears on SSH sessions; every session,
   including SSH ones, keeps **Open in Teleport**.
3. The player opens and starts at once. While it plays, the rest of the
   recording loads in the background; *Loaded up to …* shows how far.

The controls:

| Control | What it does |
|---|---|
| Play / Pause | Stops output where it is and continues from the same point |
| Timeline | Shows elapsed and total time; click or drag to jump. The terminal shows exactly the screen at that moment |
| Speed | 0.5x, 1x, 2x, 4x or 8x, from the current point |
| Skip idle | Shortens pauses longer than 3 seconds; the timeline still shows real time |

Jumping past the part that has loaded shows **Loading…** and continues
once that part arrives. Window resizes in the original session resize the
player's terminal; a very wide or tall terminal is scaled down to fit.
Closing the player stops all loading.

Each session has its own link,
`/teleport/clusters/<cluster id>/sessions/<session id>/play`, which you can
put in a ticket or an audit finding. It also works for sessions outside the
list's time range.

## What is played

Only **SSH terminal sessions** play here. Desktop, Kubernetes, database
and application sessions keep **Open in Teleport**. The recording is shown
only as terminal output: nothing in it can run in, or change, the page.

## Audit

Each time someone starts a playback the module writes one entry to its
audit trail (**Teleport → Audit**): action `teleport.session.played`,
target kind `session`, the session id, the cluster, the user and the time.
Loading the rest of the same playback adds no further entries. A refused
start is recorded as a failure with its reason. The entry never contains
any of the recording. Teleport may also log that the management identity
read the recording.

## Limits

| Limit | Value |
|---|---|
| Recording size | 500 MiB of terminal output per playback (an operator can lower it with `recording.max_bytes`) |
| Concurrent reads | 2 per user and 8 per module instance (`recording.max_per_user`, `recording.max_concurrent`); beyond that the player waits and retries |
| One playback | expires after an hour without loading, or when the module restarts; the player then starts again (a new audit entry) |

## When it does not play

| Message | What to do |
|---|---|
| No recording of this session | The session was not recorded, is still in progress, or Teleport's retention deleted it. In-progress sessions become playable when Teleport has finished the recording |
| The management role cannot read session recordings | The cluster's `tangra-manager` role needs `session: [list, read]`. Re-run the bootstrap or apply the [documented role](../reference/tangra-manager-role.md) |
| Too large to play here | Open it in Teleport |
| Only SSH terminal sessions can be played here | Open it in Teleport |
| The rest could not be loaded | The cluster stopped answering or its credential expired. What loaded keeps playing; choose **Retry** |

## Related

- [Audit events, sessions and alerts](audit-and-alerts.md)
- [Teleport permissions](../reference/permissions.md)
- [HTTP API](../reference/api.md) — the recording route
