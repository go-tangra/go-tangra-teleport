# Feature Specification: Teleport Access Through the Portal Sign-in

**Feature Branch**: `004-brokered-access`

**Created**: 2026-11-23

**Status**: Draft

**Builds on**: `001-teleport-cluster-management` (provisioning: portal groups
mapped to Teleport roles and Linux logins; managed Teleport users) and
`003-session-playback` (terminal rendering in the portal).

**Input**: User description: "Portal-brokered Teleport access for tangra
users (Teleport Community Edition, no SSO): tangra users never sign in to
Teleport; they sign in to the portal with their existing password and MFA,
and the teleport module obtains short-lived Teleport certificates for the
user's provisioned Teleport account via impersonation by the management
identity. Two ways to use them: (1) an SSH terminal inside the module to a
node the user may access, with the user's allowed Linux logins, sessions
recorded under the user's own Teleport identity; (2) a 'Download access for
tsh' short-lived identity file for the CLI. Access (roles, logins) comes from
existing provisioning mappings (portal group -> Teleport roles + logins). The
management identity may impersonate only tangra-managed users (labelled),
never local admins. Optional MFA re-check in the portal before issuing; short
certificate lifetime; every issuance and terminal session audited;
permissions for terminal and identity download."

## Context

The cluster runs Teleport Community Edition, which cannot use the portal as a
sign-in provider. Today a person who needs SSH through Teleport needs a
separate Teleport account with its own password and MFA. This feature lets
portal users reach the hosts they are entitled to using only their portal
sign-in: the portal vouches for them, and Teleport still enforces what each
person may do and records what they did under their own name.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Open an SSH terminal to a host from the portal (Priority: P1)

An engineer signed in to the portal opens the teleport module, sees the hosts
they are allowed to reach on a cluster, picks one and a Linux login they are
allowed to use, and gets a working terminal in the page. They never see a
Teleport sign-in page. Teleport records the session under the engineer's own
Teleport identity, so it appears in the session list (and can be played back)
with their name.

**Why this priority**: This is the everyday use; it removes the second
account for the common case.

**Independent Test**: Map a portal group to a role and the login `deploy`,
provision a member, sign in to the portal as that member, open a terminal to
an allowed node as `deploy`, run commands, close it; verify the session is
listed under the member's Teleport user and plays back.

**Acceptance Scenarios**:

1. **Given** a portal user whose group mapping grants access to a node and the
   login `deploy`, **When** they open the cluster's host list, **Then** they
   see that node with "Connect" and the logins `deploy` offered.
2. **Given** that user, **When** they connect as `deploy`, **Then** a terminal
   opens within a few seconds and behaves like a normal SSH session
   (typing, colours, resizing, copy and paste).
3. **Given** a node or login the user's mapping does not grant, **When** they
   try to connect, **Then** the connection is refused and no access is
   granted.
4. **Given** an open terminal, **When** the user closes the tab or the page,
   **Then** the SSH session ends.
5. **Given** the session ended, **When** an auditor opens the cluster's
   sessions, **Then** it is listed under the user's Teleport identity, not the
   module's.

---

### User Story 2 - Download short-lived access for the command line (Priority: P1)

An engineer who prefers their own terminal clicks "Download access for tsh",
receives a credential file valid for a few hours, and uses it with the
standard Teleport client to list and reach the same hosts, with the same
limits as in the portal. When it expires they download a new one.

**Why this priority**: Many operators work from their own terminal and
scripts; without this, they would still need a Teleport account.

**Independent Test**: Download the credential as a provisioned member, use it
with the Teleport client to list nodes and open a session as an allowed
login; verify it stops working after its lifetime.

**Acceptance Scenarios**:

1. **Given** a provisioned portal user with the download permission, **When**
   they choose "Download access for tsh", **Then** they receive a credential
   file and the exact command line to use it, with its expiry shown.
2. **Given** that credential, **When** it is used with the Teleport client,
   **Then** it grants exactly the user's mapped roles and logins, nothing
   more.
3. **Given** the credential's lifetime has passed, **When** it is used,
   **Then** Teleport refuses it.
4. **Given** a user without a provisioned Teleport account on that cluster,
   **When** they look for the download, **Then** it is not offered and a
   direct request is refused.

---

### User Story 3 - Strong sign-in before access is issued (Priority: P1)

Because the portal sign-in replaces Teleport's own, access is only issued to a
user whose portal session satisfies the portal's MFA, and an administrator can
require a fresh MFA confirmation in the portal before each terminal or
credential is issued.

**Why this priority**: Without it, a stolen portal session would become SSH
access; this keeps the bar where Teleport's own MFA kept it.

**Independent Test**: With "confirm MFA before access" on, open a terminal:
the portal asks for the user's MFA first; cancel it and no access is issued;
complete it and the terminal opens. With a portal account that has no MFA,
access is refused.

**Acceptance Scenarios**:

1. **Given** a portal user who has not completed MFA in their current portal
   session, **When** they request a terminal or credential, **Then** it is
   refused with a message to sign in with MFA.
2. **Given** the cluster setting "confirm MFA before access" is on, **When** a
   user requests access, **Then** the portal asks them to confirm MFA, and
   access is issued only after a successful confirmation within the last few
   minutes.
3. **Given** the confirmation is cancelled or fails, **Then** nothing is
   issued.

---

### User Story 4 - Administrators control and see brokered access (Priority: P2)

An administrator decides who may use the portal terminal and who may download
credentials (separate permissions), sets the credential lifetime within safe
bounds, and sees every issuance and every terminal session in the module's
audit: who, which cluster, which Teleport identity, which node and login (for
terminals), and when. Revoking a person's portal group or locking their
Teleport user stops new access immediately and ends their open terminals.

**Why this priority**: Required for operation and compliance, but builds on
US1–US3.

**Independent Test**: Grant only the terminal permission to a role; verify its
members can connect but not download. Change the lifetime to 1 hour and
verify downloaded credentials expire after 1 hour. Remove a member from the
mapped group, verify their open terminal ends and new access is refused.

**Acceptance Scenarios**:

1. **Given** the two permissions, **When** a role has only one, **Then** its
   members can use only that way of access.
2. **Given** an issuance or a terminal session, **Then** one audit entry
   records user, tenant, cluster, Teleport identity, kind (terminal or
   download), node and login (terminal), lifetime and outcome; credential
   contents never appear in it.
3. **Given** a user loses the mapping (removed from the group, or their
   Teleport user is locked or removed), **When** they request access,
   **Then** it is refused; **and** their open portal terminals end within one
   minute.
4. **Given** a lifetime setting outside the allowed range, **When** an
   administrator saves it, **Then** it is rejected.

---

### User Story 5 - The module can act only for the people it provisions (Priority: P1)

The module's own Teleport identity can obtain access only on behalf of the
Teleport users it provisioned for this tenant, never for local Teleport
accounts (such as the cluster administrator) or users of another tenant.
Setting this up is part of the documented management role and the cluster
bootstrap.

**Why this priority**: The ability to act as users is the most sensitive
power in this feature; bounding it is a precondition for shipping.

**Independent Test**: Attempt (through the module) to obtain access as a local
Teleport administrator and as another tenant's managed user; both are refused
by Teleport itself, not only by the module.

**Acceptance Scenarios**:

1. **Given** a Teleport user not created by the module's provisioning,
   **When** access for that user is requested through the module, **Then**
   Teleport refuses it.
2. **Given** the module requests access for a user, **Then** it is always the
   Teleport user provisioned for the requesting portal user in their tenant;
   the requester cannot choose another identity.
3. **Given** an existing cluster without the updated management role, **When**
   access is requested, **Then** it is refused with a message naming the role
   update needed.

---

### Edge Cases

- **User not provisioned on the cluster** (no mapping, or provisioning has not
  run yet): terminal and download are not offered; the page explains that
  access comes from group mappings and who can grant it.
- **User mapped on several clusters**: access is per cluster; each cluster
  uses that cluster's provisioned identity.
- **Node goes offline or is removed** during a terminal session: the terminal
  shows that the connection closed.
- **Login not present on the host**: the terminal shows the host's refusal.
- **Credential download on a shared computer**: the file is offered once per
  request, shows its expiry prominently, and is never stored by the portal.
- **Browser tab left open overnight**: terminal sessions end after a maximum
  duration (default 8 hours) or after the portal session ends, whichever is
  first.
- **Many terminals**: a user can have at most 5 open terminals at once;
  further attempts are refused with a clear message.
- **Teleport requires per-session MFA** on a role: brokered access cannot
  satisfy Teleport's own per-session MFA; such roles are reported as not
  usable through the portal rather than failing obscurely.
- **Cluster unreachable or management credential expired**: access is refused
  with the cluster's status shown.
- **Clock differences** between portal and cluster: lifetimes are applied by
  Teleport; the portal shows the expiry Teleport reports.

## Requirements *(mandatory)*

### Functional Requirements

**Access issuance**

- **FR-001**: The system MUST issue Teleport access only for the Teleport user
  that provisioning created for the requesting portal user in their tenant on
  that cluster; the requester MUST NOT be able to choose another identity.
- **FR-002**: Issued access MUST carry exactly the roles and logins Teleport
  holds for that provisioned user at issuance time.
- **FR-003**: Issued access MUST be short-lived: default 8 hours, adjustable
  per cluster by an administrator between 15 minutes and 12 hours.
- **FR-004**: The system MUST NOT store issued credentials; they exist only in
  the response that delivers them (download) or for the duration of a
  terminal session.

**Portal terminal**

- **FR-005**: The system MUST let a permitted user list the nodes of a cluster
  their provisioned identity may access, with the logins they may use, and
  open an interactive terminal to a chosen node and login inside the portal.
- **FR-006**: The terminal MUST support interactive use: input, output with
  colours, window resizing, copy and paste.
- **FR-007**: Terminal sessions MUST run under the user's provisioned Teleport
  identity, so Teleport applies its role rules and records the session under
  that identity.
- **FR-008**: A terminal session MUST end when the user closes it, when the
  page is closed, when the portal session ends, after a maximum duration
  (default 8 hours), or within one minute after the user's access is revoked.
- **FR-009**: A user MUST have at most 5 concurrent portal terminals.

**Command-line access**

- **FR-010**: The system MUST let a permitted user download a credential file
  for the Teleport command-line client, together with the command to use it
  and its expiry.
- **FR-011**: Downloaded credentials MUST grant no more than the user's
  provisioned identity and MUST expire per FR-003.

**Sign-in strength**

- **FR-012**: Access MUST only be issued to a portal user whose current
  portal session was established with MFA.
- **FR-013**: An administrator MUST be able to require, per cluster, a fresh
  MFA confirmation in the portal (within the last 5 minutes) before each
  terminal or download.
- **FR-014**: Roles that require Teleport's own per-session MFA MUST be
  reported as not usable through the portal.

**Permissions and audit**

- **FR-015**: Two new permissions MUST control access: one for the portal
  terminal and one for credential download. Administrators receive both by
  default; operators receive the terminal permission; auditors and viewers
  receive neither.
- **FR-016**: Every issuance and every terminal session MUST produce an audit
  entry with user, tenant, cluster, Teleport identity, kind, node and login
  (terminal), lifetime, start and end (terminal) and outcome; credential
  material and terminal content MUST NOT appear in audit, logs, metrics or
  events.
- **FR-017**: Refused requests (no permission, not provisioned, MFA missing,
  revoked) MUST be audited as failures.

**Teleport side**

- **FR-018**: The management role the module documents and bootstraps MUST
  allow acting only as Teleport users labelled as provisioned by this module
  (and for the same tenant), and the bootstrap MUST update existing clusters
  idempotently.
- **FR-019**: When the management identity lacks this ability, requests MUST
  be refused with a message naming the role update.

**Documentation**

- **FR-020**: The module's help MUST explain brokered access, the two
  permissions, the MFA settings, lifetimes, limits, the management-role
  change, and the difference from signing in to Teleport directly.

### Key Entities

- **Provisioned identity**: the Teleport user that provisioning created for a
  portal user on a cluster (existing; labelled as managed, with tenant and
  portal user).
- **Issued access**: a short-lived credential for a provisioned identity;
  not stored; recorded only as an audit entry.
- **Portal terminal session**: one interactive connection from a user's
  browser to a node and login through the portal; ends per FR-008; audited.
- **Cluster access settings**: per-cluster lifetime and "confirm MFA before
  access".

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A provisioned portal user goes from the host list to a working
  terminal in under 15 seconds without any Teleport sign-in.
- **SC-002**: A user downloads command-line access and runs their first
  command against an allowed host in under 2 minutes.
- **SC-003**: 0 successful issuances for identities other than the requester's
  provisioned user, verified by tests that try other users, local
  administrators and other tenants.
- **SC-004**: 100% of terminal sessions appear in the cluster's session list
  under the user's own Teleport identity.
- **SC-005**: After revocation, new access is refused immediately and open
  terminals end within 60 seconds in 100% of tests.
- **SC-006**: 100% of issuances and terminal sessions produce an audit entry;
  no credential material or terminal content is found in audit, logs or
  stored data.

## Assumptions

- The cluster runs Teleport Community Edition; single sign-on to Teleport
  itself is out of scope (it would need Teleport Enterprise).
- Provisioning (001) is how people get Teleport identities; this feature does
  not create users outside it. Local Teleport accounts keep working as today.
- The Teleport web UI still requires a Teleport sign-in; everyday SSH happens
  in the portal or with downloaded credentials instead.
- Portal MFA is already available and enforced by the portal's sign-in; this
  feature reads whether the current session used it and can ask for a fresh
  confirmation.
- Only SSH node access is in scope; databases, Kubernetes, applications and
  desktops are out of scope for both the terminal and the downloaded
  credential's intended use (the credential grants what the roles allow, but
  only SSH use is documented and tested).
- Defaults (8-hour lifetime, 5 terminals, 8-hour terminal maximum, 5-minute
  MFA freshness) are adjustable within the stated bounds.
