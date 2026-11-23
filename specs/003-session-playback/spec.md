# Feature Specification: Play Recorded SSH Sessions Inside the Teleport Module

**Feature Branch**: `003-session-playback`

**Created**: 2026-11-23

**Status**: Draft

**Extends**: `001-teleport-cluster-management` (US4, FR-022: recorded
sessions are listed with a link into the Teleport web UI; "No session replay
in v1"). This feature adds replay inside the portal for SSH terminal
sessions.

**Input**: User description: "In-module playback of recorded Teleport SSH
sessions in go-tangra-teleport: from the sessions list, an authorized user
watches a recorded SSH terminal session inside the tangra portal (play/pause,
speed, seek, timeline) instead of being sent to the Teleport web UI. Watching
requires a new permission sessions:play (granted to admins by default;
listing stays on audit:read). Every playback is audited (who, which session,
when). SSH terminal sessions only; desktop, Kubernetes and database sessions
keep the deep link into Teleport. Recordings stay in Teleport (no copy kept in
tangra); long recordings must load progressively. The module's Teleport
management role needs read access to session recordings."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Watch a recorded SSH session in the portal (Priority: P1)

An auditor investigating what happened on a host opens the cluster's recorded
sessions in the portal, picks an SSH session and watches it in a terminal
player on the same page: output appears with its original timing, and the
auditor can pause, resume, change speed, and jump to any point on a timeline.
They never leave the portal or sign in to Teleport separately.

**Why this priority**: This is the feature. Today auditors need a Teleport
account and a second sign-in to see what someone did; the portal is where they
already work.

**Independent Test**: Record an SSH session on an enrolled node (run a few
commands, resize the window, idle for a while), then, as a user with the
playback permission, open it from the sessions list and verify the terminal
shows the same output in order, with the original pauses, and that
pause/resume, speed and seek behave as described.

**Acceptance Scenarios**:

1. **Given** a recorded SSH session and a user with the playback permission,
   **When** they choose "Play" on it in the sessions list, **Then** a player
   opens in the portal and starts replaying the terminal output with its
   original timing and terminal size.
2. **Given** a playing session, **When** the user pauses, **Then** output
   stops at that point; **When** they resume, **Then** it continues from the
   same point.
3. **Given** a playing session, **When** the user picks a speed of 0.5x, 1x,
   2x, 4x or 8x, **Then** replay continues at that speed from the current
   point.
4. **Given** a session, **When** the user clicks or drags to a point on the
   timeline, **Then** the terminal shows exactly the screen as it was at that
   moment and replay continues from there.
5. **Given** a session with long idle gaps, **When** the user enables "skip
   idle", **Then** gaps longer than 3 seconds are shortened during replay
   while the timeline still shows real elapsed time.
6. **Given** the window was resized during the original session, **When** the
   replay reaches the resize, **Then** the player's terminal changes size
   accordingly.

---

### User Story 2 - Long recordings start quickly (Priority: P1)

A recording of a multi-hour session, or one with a lot of output, starts
playing within seconds; the rest loads while it plays, and seeking ahead to a
part that has not loaded yet waits for it with a visible indicator instead of
failing.

**Why this priority**: Recordings that matter (incidents, long maintenance)
are often the longest ones; a player that has to download everything first
is unusable for them.

**Independent Test**: Replay a recording with at least 50 MB of terminal
output and verify playback begins promptly, the loaded portion grows while
playing, and a seek beyond it completes once that part arrives.

**Acceptance Scenarios**:

1. **Given** a very long recording, **When** the user presses Play,
   **Then** playback begins before the whole recording has loaded.
2. **Given** a partly loaded recording, **When** the user seeks past the
   loaded part, **Then** the player shows that it is loading and continues
   from the chosen point once available.
3. **Given** the user closes the player, **Then** loading stops.

---

### User Story 3 - Only permitted users can watch, and every playback is audited (Priority: P1)

Recordings show everything that appeared on the terminal, including secrets
that were printed. Watching therefore needs its own permission, separate from
listing, and every playback is recorded: who watched which session of which
cluster, and when.

**Why this priority**: Without it the feature widens access to sensitive data;
it is a precondition for shipping, not an add-on.

**Independent Test**: With a user who can list sessions but lacks the playback
permission, verify the list shows no Play action and a direct playback request
is refused; with a permitted user, play a session and verify an audit entry
names the user, cluster, session and time.

**Acceptance Scenarios**:

1. **Given** a user with session listing but not playback permission,
   **When** they open the sessions list, **Then** they see the sessions (as
   today) but no Play action.
2. **Given** that user, **When** they request a recording directly, **Then**
   the request is refused as forbidden and nothing from the recording is
   returned.
3. **Given** a permitted user, **When** they start playback, **Then** one
   audit entry records the user, tenant, cluster, session id and time.
4. **Given** the built-in administrator role, **When** the module is
   installed or upgraded, **Then** that role can play sessions without
   further setup.
5. **Given** a user who can play sessions in one tenant, **When** they request
   a session of a cluster registered in another tenant, **Then** it is not
   found.

---

### User Story 4 - Other session kinds keep the Teleport link (Priority: P3)

Desktop, Kubernetes and database sessions, and any session the player cannot
replay, still show the existing "Open in Teleport" link; SSH sessions show
both Play and that link.

**Why this priority**: Keeps today's behavior for everything out of scope.

**Independent Test**: In a list containing an SSH session and a session of
another kind, verify Play appears only on the SSH session and the link on
both.

**Acceptance Scenarios**:

1. **Given** a non-SSH session, **When** the list shows it, **Then** it has
   the Teleport link and no Play action.
2. **Given** an SSH session, **When** the list shows it, **Then** it has
   both.

---

### Edge Cases

- **Recording not available**: the session was not recorded (recording
  disabled), is still in progress, or was deleted by retention: the player
  says so plainly and offers the Teleport link.
- **Cluster unreachable or credential expired mid-playback**: what has loaded
  keeps playing; the player shows that the rest could not be loaded and lets
  the user retry.
- **Management role lacks recording access** (cluster set up before this
  feature): playback is refused with an explanation that the management role
  must be updated, not a generic error.
- **Recording with an unusual terminal size** (very wide or tall): the player
  scales to fit the page instead of cropping.
- **Binary or malformed output** in the recording: replayed as the terminal
  would show it; nothing in the recording can run script or change the page
  outside the terminal view.
- **Several participants** (shared session): the output is the shared
  terminal, replayed once.
- **Very large recordings**: playback works up to 500 MB of terminal output;
  beyond the limit the player says the recording is too large to play here
  and offers the Teleport link.
- **Rapid seeking back and forth**: the screen always matches the chosen
  moment; no output from a previous position bleeds in.
- **Session outside the list's time window**: it can still be played from a
  direct link that names the cluster and session.

## Requirements *(mandatory)*

### Functional Requirements

**Playback**

- **FR-001**: The system MUST let a permitted user replay a recorded SSH
  terminal session of a registered cluster inside the portal, with the
  original output, timing and terminal size changes.
- **FR-002**: The player MUST offer play/pause, speeds 0.5x, 1x, 2x, 4x and
  8x, a timeline showing elapsed and total time, seeking to any point, and a
  "skip idle" option that shortens gaps longer than 3 seconds.
- **FR-003**: After a seek the terminal MUST show exactly the screen state at
  the chosen moment.
- **FR-004**: The player MUST begin playback before the whole recording has
  loaded and load the remainder progressively; seeking into a not yet loaded
  part MUST wait for it with a visible loading state.
- **FR-005**: Closing the player MUST stop any further loading.
- **FR-006**: The player MUST render recording content only as terminal
  output; nothing in a recording may execute in or alter the page outside the
  terminal view.
- **FR-007**: Playback MUST be offered only for SSH terminal sessions; other
  session kinds keep the existing link into the Teleport web UI, which SSH
  sessions also keep.
- **FR-008**: Each session MUST be playable from a link that names the
  cluster and session, so audit findings and tickets can point at it.

**Access and audit**

- **FR-009**: Playback MUST require a new permission, `sessions:play`,
  separate from the permission that lists sessions; users without it see no
  Play action and direct requests are refused as forbidden.
- **FR-010**: The built-in administrator role MUST receive `sessions:play`
  when the module is registered or upgraded; no other built-in role receives
  it.
- **FR-011**: Every playback start MUST produce one audit entry with the
  user, tenant, cluster, session id and time; loading further parts of the
  same playback MUST NOT produce additional entries.
- **FR-012**: Recordings MUST be visible only for clusters of the user's own
  tenant; any other cluster or session is reported as not found.

**Data handling**

- **FR-013**: Recordings MUST stay in Teleport: the module MUST NOT store any
  part of a recording (no database rows, files, caches or logs of its
  content); it relays content to the permitted user only while they play it.
- **FR-014**: Recording content MUST NOT appear in the module's logs,
  metrics, events or audit entries.
- **FR-015**: The module MUST bound the resources one playback can use (size
  of each loaded part, concurrent playbacks per user and per module instance)
  and refuse beyond those bounds with a clear "try again later" response.
- **FR-016**: Recordings larger than 500 MB of terminal output MUST be
  refused with an explanation and the Teleport link.

**Teleport access**

- **FR-017**: The management role the module documents and bootstraps MUST
  include read access to session recordings; the bootstrap MUST update an
  existing role idempotently.
- **FR-018**: When a cluster's management identity lacks recording access,
  playback MUST be refused with a message naming that cause and the fix.
- **FR-019**: When a session has no recording, or it was deleted, the player
  MUST say so and offer the Teleport link.

**Documentation**

- **FR-020**: The module's help MUST describe playback, the `sessions:play`
  permission, the audit entry, the management-role change and the limits.

### Key Entities

- **Session recording** (in Teleport, not stored by the module): the ordered
  terminal output of one SSH session with timing, terminal size and size
  changes; identified by cluster and session id.
- **Playback**: one user watching one recording; exists only as an audit
  entry (user, tenant, cluster, session, time) and transient loading state.
- **Permission `sessions:play`**: grants playback; distinct from session
  listing.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An auditor goes from the sessions list to watching a session in
  under 10 seconds, without signing in to Teleport.
- **SC-002**: Playback of any recording up to 500 MB starts within 5 seconds
  of pressing Play on a normal office connection.
- **SC-003**: After any seek, the screen matches the original session at that
  moment in 100% of tested positions (start, middle, end, just before and
  after a resize).
- **SC-004**: 100% of playbacks produce exactly one audit entry; 0 requests
  from users without the playback permission return recording content.
- **SC-005**: No recording content is found in the module's database, logs,
  metrics or audit after a playback (verified by test).
- **SC-006**: Replay timing stays within 100 ms of the original over a
  10-minute recording at 1x.

## Assumptions

- Teleport keeps the recordings (node or proxy recording mode, any storage
  backend); the module reads them through the cluster's API with its
  management identity, live, like other Teleport data (001 "Source of truth").
- Only terminal SSH sessions are in scope; desktop, Kubernetes exec,
  database and application sessions are out of scope and keep the link.
- Session listing (FR-022 of 001) stays as it is, with `audit:read`; this
  feature only adds the Play action and the player.
- Sessions still in progress are not playable here (no live viewing); they
  become playable once Teleport has finished the recording.
- The 500 MB limit and the per-user and per-instance concurrency bounds are
  defaults that an operator can lower; they protect the module and the
  cluster, not the user's browser.
- Existing clusters need their management role updated once (re-running the
  bootstrap or applying the documented role); until then playback is refused
  per FR-018.
- Playback is audited in the module's own audit trail; Teleport may also log
  that the management identity read the recording.
