# Feature Specification: Access Identity for Brokered Access

**Feature Branch**: `005-access-identity`

**Created**: 2026-11-23

**Status**: Draft

**Builds on**: `004-brokered-access` (portal terminals and identity
downloads issued by impersonating managed Teleport users).

**Input**: User description: "Teleport refuses impersonation from a
`tctl auth sign` identity, which is what the module's long-lived management
identity is. Keep the management identity for everything it does today and
add an optional per-cluster access identity — a `tsh login` identity of a
dedicated Teleport user `tangra-access` — used only by brokered access.
Least privilege on the Teleport side (the impersonate rule moves from the
management role to a new `tangra-access` role), validation on upload,
status/upload/remove API, expiry alerts and audit, and a cluster-page panel."

## Context

Brokered access (004) asks Teleport for certificates as a managed user. Teleport
allows that only from a certificate obtained by signing in; every
`tctl auth sign` identity carries an impersonator and is refused. The
management identity is a `tctl auth sign` identity on purpose: it is long-lived
and needs no person to sign in. A sign-in identity, on the other hand, needs a
password and second factor once per lifetime. Splitting the two keeps the
management credential long-lived and bounds what the sign-in identity can do to
"become a managed user".

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Configure the access identity (Priority: P1)

An administrator bootstraps the `tangra-access` user and role on the cluster,
signs in once with `tsh login --out`, and uploads the identity file on the
cluster page. The module checks it before storing it and shows its user,
expiry and state.

**Independent Test**: Upload a sign-in identity of `tangra-access`: it is
stored and the panel shows `ok` and the expiry. Upload a `tctl auth sign`
identity: refused with a reason that says so; nothing stored.

**Acceptance Scenarios**:

1. **Given** a cluster without an access identity, **When** an administrator
   uploads a valid sign-in identity of the same cluster, **Then** it is stored
   encrypted, the status shows `configured`, the Teleport user and the expiry.
2. **Given** an identity made with `tctl auth sign`, **When** it is uploaded,
   **Then** it is refused (422 `access_identity_not_sign_in`) and nothing changes.
3. **Given** an identity of another Teleport cluster, **When** uploaded,
   **Then** it is refused as a validation failure.
4. **Given** an identity that Teleport does not let impersonate a managed user,
   **When** uploaded and a managed user exists, **Then** it is refused
   (422 `access_identity_cannot_impersonate`).
5. **Given** a configured identity, **When** an administrator replaces or
   removes it, **Then** the old one is deleted from the secret store and the
   action is audited.

### User Story 2 - Portal access uses the access identity (Priority: P1)

Portal terminals, node listing and identity downloads obtain certificates with
the access identity. Everything else keeps using the management identity.

**Acceptance Scenarios**:

1. **Given** a configured, valid access identity, **When** a provisioned user
   opens a terminal, **Then** the certificates are issued with it.
2. **Given** no access identity, **When** issuance is attempted, **Then** the
   management identity is tried (works only if it is itself a sign-in identity
   whose role may impersonate); if Teleport refuses, the answer is 422
   `access_identity_missing`.
3. **Given** an expired access identity, **Then** the answer is 422
   `access_identity_expired`; one Teleport rejects is 422
   `access_identity_invalid`.
4. Terminals already open keep running until their own certificates expire.

### User Story 3 - Warned before it expires (Priority: P2)

Administrators are notified before the access identity expires with the same
thresholds as the management credential (7 days or 25% of the lifetime, then
one day, then expired), once per stage.

### Edge Cases

- The cluster is removed: the access identity is deleted with it.
- The secret store is unavailable: upload answers `dependency_unavailable`.
- An identity larger than 64 KiB or empty: validation failure.
- No managed user exists yet at upload: the impersonation dry check is skipped
  (reported in the response as `impersonation_checked: false`).

## Requirements *(mandatory)*

- **FR-001** Keep the management identity unchanged for all existing features.
- **FR-002** Store at most one access identity per cluster, encrypted in the
  same secret store as the management credential, never returned or logged.
- **FR-003** On upload verify: parses and unexpired; signs in (ping); has no
  impersonator (a sign-in identity); same Teleport cluster as the
  registration; may impersonate a managed user (1-minute dry issuance when a
  managed user exists). Record the Teleport user, issue and expiry times.
- **FR-004** API: status (read), upload/replace and remove (`clusters:manage`).
- **FR-005** Brokered access issues certificates with the access identity, through
  a connection pool separate from the management one; refusals
  `access_identity_missing`, `access_identity_expired`, `access_identity_invalid`
  replace `management_identity_unsuitable` and `management_role_outdated`.
- **FR-006** Fallback: no access identity → the management identity is used.
- **FR-007** Expiry stages are announced (event + notification) like the
  management credential's; upload, replace and remove are audited.
- **FR-008** Teleport side: the management role no longer impersonates; a new
  `tangra-access` role holds only the impersonate rule (managed users only)
  and a long `max_session_ttl`; documented bootstrap.
- **FR-009** UI: cluster-page panel (status, expiry, upload/replace/remove, the
  `tsh login` command); My access and the terminal page explain the
  missing/expired states.

## Success Criteria *(mandatory)*

- **SC-001** On a Teleport 18 cluster, the management identity can no longer
  impersonate after the role change; a `tangra-access` sign-in identity can.
- **SC-002** A `tctl auth sign` identity is refused on upload, with nothing stored.
- **SC-003** A terminal opened through the module with the access identity runs a
  command on a node and the session is recorded under the managed user.

## Assumptions

- The `tangra-access` user signs in with a password and a second factor
  (local users); its lifetime is bounded by the role's `max_session_ttl`.
- Renewal is manual (sign in again and upload); alerts make it visible.
