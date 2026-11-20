# Feature Specification: Teleport Cluster Management Module (go-tangra-teleport)

**Feature Branch**: `001-teleport-cluster-management`

**Created**: 2026-11-19

**Status**: Draft

**Input**: User description: "go-tangra-teleport: a tangra module that is a management tool for self-hosted Teleport Community Edition (https://goteleport.com/docs/get-started/deploy-community/), with the ability to integrate with the rest of the tangra system."

## Overview

Tangra tenants that run self-hosted Teleport Community Edition clusters for infrastructure access today manage them through command-line tools on the cluster host. That work happens outside tangra: there is no shared view, changes leave no tangra audit trail, and Teleport identities are disconnected from tangra users, inventory and alerting.

This module brings Teleport cluster administration into the tangra portal. Tenant administrators can:

- connect one or more Teleport clusters;
- manage Teleport users, roles, locks and join tokens;
- see and enroll protected resources (servers, applications, databases, Kubernetes clusters, desktops);
- review Teleport audit events and sessions;
- get alerts through the tangra notification channels.

The module also plans and guides the deployment of new Community Edition clusters.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Connect a Teleport cluster and see its health (Priority: P1)

A tenant administrator registers an existing self-hosted Teleport Community Edition cluster with tangra. They give the cluster's public proxy address and a management credential that was issued for a dedicated, least-privilege Teleport identity. Tangra verifies the connection. It then shows a cluster overview: cluster name, Teleport version, connection status, credential expiry, and counts of users, roles and enrolled resources.

**Why this priority**: Every other capability depends on a working, verified connection. On its own it already gives administrators a single place to see whether their access infrastructure is healthy.

**Independent Test**: Register a test cluster with a valid credential. Confirm the overview shows correct metadata and counts. Then invalidate the credential and confirm the status changes to "Credential invalid" with a clear reason.

**Acceptance Scenarios**:

1. **Given** a tenant administrator with a reachable Teleport cluster and a valid management credential, **When** they register the cluster, **Then** tangra verifies connectivity before saving, stores the credential only as a protected secret reference, and shows the cluster as "Connected" with its name and version.
2. **Given** a registered cluster, **When** the management credential is within the configured expiry threshold, **Then** the overview shows a warning and the tenant's administrators get a notification.
3. **Given** a registered cluster, **When** it becomes unreachable, **Then** its status changes to "Unreachable" within 5 minutes, the last successful contact time is shown, and an alert is sent.
4. **Given** a tenant with several clusters, **When** a user opens the module, **Then** they see only their own tenant's clusters, each with its health status.
5. **Given** a registered cluster, **When** an administrator removes it, **Then** tangra deletes its stored connection data and credential reference and leaves the Teleport cluster itself unchanged.

---

### User Story 2 - Manage Teleport users, roles and locks (Priority: P1)

A tenant administrator manages who can access infrastructure through Teleport without opening a shell on the cluster host. They can do the following:

- list users;
- create a user with roles and allowed logins, and get a time-limited invite link;
- update a user's roles and logins;
- reset a user;
- delete a user;
- view, create and edit roles;
- lock a user, role or server, with a reason and an optional expiry, to cut off access during an incident.

**Why this priority**: User and role administration is the most frequent day-to-day Teleport task. Locks are the main incident-response control.

**Independent Test**: On a connected cluster:

1. Create a user with the `access` role.
2. Confirm the invite link is shown once.
3. Change the user's roles and confirm the change appears in Teleport.
4. Lock the user and confirm Teleport rejects their sessions.
5. Unlock the user and delete them.

**Acceptance Scenarios**:

1. **Given** a connected cluster, **When** an administrator creates a user with roles and logins, **Then** the user exists in Teleport and the invite link is shown once with its expiry time.
2. **Given** an existing role, **When** an administrator edits its definition, **Then** tangra validates the definition before applying it, shows what will change, and applies it only after confirmation.
3. **Given** a definition that is invalid or that Teleport rejects, **When** it is submitted, **Then** nothing is changed and Teleport's error is shown in a readable form.
4. **Given** an active session for a user, **When** an administrator creates a lock on that user, **Then** the lock appears in the active-locks list with its reason, author and expiry, and Teleport enforces it.
5. **Given** a built-in Teleport role (e.g. `editor`, `access`, `auditor`), **When** an administrator tries to delete it, **Then** the action is blocked with an explanation.
6. **Given** a user who holds only the tangra viewer role for this module, **When** they open users or roles, **Then** they can view but not change anything.

---

### User Story 3 - Enroll and inventory protected resources (Priority: P2)

An operator wants to add a server (or an application, database, Kubernetes cluster or desktop) to Teleport. They:

1. Pick the resource type.
2. Generate a join token with a short validity period.
3. Get a ready-to-run install and join command.

Once the agent joins, the resource appears in the module's resource list with its labels and online/offline status. Where a matching host already exists in tangra inventory or asset management, the resource is linked to that record.

**Why this priority**: Enrollment is the second most common task. Linking with inventory and assets gives value that standalone Teleport cannot provide.

**Independent Test**: Generate a server join token. Run the given command on a test host. Confirm the host appears as online in the resource list within the refresh interval. Confirm the token can no longer be used after its validity period ends.

**Acceptance Scenarios**:

1. **Given** a connected cluster, **When** an operator generates a join token for a resource type with a validity period (default 30 minutes, maximum 24 hours), **Then** tangra shows the token once along with an install/join command for that cluster, and records who created it and when it expires.
2. **Given** joined resources, **When** a user opens the resource list, **Then** they can filter by type, label, name and status. Each entry shows last-seen time and Teleport agent version.
3. **Given** a joined server whose hostname or address matches exactly one tangra inventory or asset record, **When** the resource list refreshes, **Then** the resource shows a link to that record, and the record shows that the host is reachable through Teleport.
4. **Given** an active join token, **When** an operator revokes it, **Then** Teleport rejects any later join attempt with that token.
5. **Given** a resource that has been offline for longer than the configured threshold, **When** the threshold passes, **Then** the resource is flagged and an alert is sent if alerts are enabled for that cluster.

---

### User Story 4 - Review audit events and sessions, with alerting (Priority: P2)

An auditor reviews Teleport activity from tangra. They:

- search and filter Teleport audit events (logins, failed logins, session starts and ends, role changes, lock events) by time range, user, resource and event type;
- list recorded sessions with participants, duration and target;
- subscribe tenant users or channels to alerts for chosen event types (for example failed-login bursts, new admin-role assignments, locks created).

**Why this priority**: Visibility and alerting are central to security operations. They depend on the connection from Story 1 but not on Stories 2 or 3.

**Independent Test**: Perform a login, a failed login and a session on a connected cluster. Confirm all three appear in the module's event view with correct filters. Configure an alert for failed logins and confirm it arrives through the tangra notification channel.

**Acceptance Scenarios**:

1. **Given** a connected cluster with audit activity, **When** an auditor searches events for the last 24 hours filtered by user, **Then** only matching events are returned, newest first, and the auditor can page through them.
2. **Given** an alert rule for an event type, **When** a matching event occurs, **Then** the subscribed recipients are notified within 5 minutes. The notification includes cluster, user, resource and time.
3. **Given** recorded sessions, **When** an auditor opens the session list, **Then** they see session id, participants, target resource, start time and duration, plus a link that opens playback in the Teleport web UI.
4. **Given** any change made through this module (user, role, lock, token, cluster), **When** it completes or fails, **Then** a tangra audit record is written with actor, tenant, cluster, action, target and outcome.

---

### User Story 5 - Provision tangra users into Teleport (Priority: P3)

A tenant administrator maps tangra module roles or groups to Teleport roles, for example "tangra operators → Teleport `access` with logins `ubuntu`". Matching tangra users can then be provisioned into a cluster with one action. They are de-provisioned (locked, then removed) when they leave the tenant or lose the mapped role.

**Why this priority**: Consistent identity lifecycle removes orphaned accounts. It builds on Story 2 and is not needed for the core management workflows.

**Independent Test**: Define a mapping. Provision a tangra user and confirm a Teleport user with the mapped roles exists and is linked to the tangra user. Remove the user's tangra role and confirm the Teleport user is locked within the sync interval.

**Acceptance Scenarios**:

1. **Given** a role mapping, **When** an administrator provisions a tangra user, **Then** a Teleport user is created with the mapped roles and logins, and the user gets an invite link through the tangra notification channel.
2. **Given** a provisioned user, **When** that user is removed from the tenant or loses every mapped role, **Then** the Teleport user is locked at the next sync, and deleted after a configurable grace period (default 7 days).
3. **Given** a Teleport user that was not created by tangra, **When** a sync runs, **Then** that user is never changed automatically. It is listed as "unmanaged".

---

### User Story 6 - Guided deployment of a new Community Edition cluster (Priority: P3)

An administrator who has no cluster yet uses a guided wizard. They:

1. Enter the cluster domain, ACME contact email (or choose to bring their own certificate), and target Teleport version.
2. Get a deployment checklist: DNS records for the domain and wildcard, open port 443, minimum host size.
3. Get a generated configuration and install script.
4. Create the first administrator account.
5. Register the new cluster with tangra (Story 1) using a least-privilege management identity that the wizard helps create.

**Why this priority**: This makes onboarding easier, but administrators can already deploy by following Teleport's own guide and then registering the cluster.

**Independent Test**: Run the wizard for a test domain. Apply the generated artifacts on a clean Linux host. Confirm the cluster starts with a valid certificate and can be registered with the generated management identity in fewer than 10 manual steps.

**Acceptance Scenarios**:

1. **Given** the wizard inputs, **When** the administrator completes the wizard, **Then** they get a downloadable configuration, an install script pinned to the chosen version, a DNS/network checklist, and the commands to create the first administrator and the management identity.
2. **Given** a draft deployment, **When** the administrator asks to check prerequisites, **Then** the wizard checks that the domain and wildcard resolve and that port 443 answers with a valid certificate, and shows each check's result.
3. **Given** a deployed cluster, **When** the administrator finishes the wizard, **Then** they are taken straight to cluster registration with the address already filled in.

---

### Edge Cases

- **Teleport version outside the supported range**: registration warns. Unsupported operations are disabled and labelled, never failed silently.
- **Lost connectivity mid-operation**: the operation is reported as failed or unknown, never as succeeded, and the next refresh reconciles the real state.
- **Change made outside tangra** (for example `tctl` on the host): the module shows Teleport's current state on the next refresh and never overwrites it silently. Edits use the version that was read, so a concurrent change is detected and the user is asked to reload.
- **Enterprise-only features** (for example Access Request approval workflows, or SSO connectors that Community Edition does not include): they are not offered for Community Edition clusters, and the UI says the feature needs Enterprise.
- **Management credential expiry**: if the credential is not renewed in time, the cluster goes to "Credential expired" and every write action is blocked until a new credential is provided.
- **Self-lockout**: tangra refuses to lock or delete its own management identity.
- **Very large audit volumes**: event search must stay usable through paging and required time ranges, and must never try to load unbounded result sets.
- **Removing a tenant**: all of its cluster registrations and stored references are removed. The Teleport clusters themselves are not touched.
- **One-time secrets**: join tokens and invite links shown once are not shown again in tangra, and they never appear in logs, events or audit records.
- **Ambiguous inventory match** (several records match one resource): no link is created automatically. The candidates are shown for manual confirmation.

## Requirements *(mandatory)*

### Functional Requirements

**Cluster connection**

- **FR-001**: The system MUST let authorized tenant administrators register, edit and remove Teleport Community Edition clusters. Each cluster has a display name, proxy address and management credential.
- **FR-002**: The system MUST verify connectivity and credential validity before saving a cluster registration, and re-verify at least every 5 minutes.
- **FR-003**: The system MUST store management credentials only in the tangra secrets store, and refer to them by reference. Credentials MUST never be returned to browsers or written to logs, events or audit records.
- **FR-004**: The system MUST track management credential expiry, renew the credential automatically where the credential type allows it, and alert administrators before expiry. The default threshold is 7 days for long-lived credentials and 25% of remaining lifetime for short-lived ones.
- **FR-005**: The system MUST show per-cluster health: status, Teleport version, cluster name, last successful contact, credential expiry, and resource and user counts.
- **FR-006**: The system MUST support more than one cluster per tenant, and MUST isolate every cluster, its data and its actions to the owning tenant.

**Users, roles and locks**

- **FR-007**: The system MUST let authorized users list, create, update, reset and delete Teleport users, including their roles and allowed logins.
- **FR-008**: The system MUST show invite and reset links exactly once, with their expiry.
- **FR-009**: The system MUST let authorized users list, view, create, edit and delete Teleport roles.
- **FR-010**: The system MUST validate role definitions and show a preview of changes before applying them.
- **FR-011**: The system MUST block deletion of Teleport built-in roles.
- **FR-012**: The system MUST let authorized users create and remove locks on users, roles and servers. Each lock has a mandatory reason and an optional expiry.
- **FR-013**: The system MUST refuse any action that would lock out or delete its own management identity.
- **FR-014**: The system MUST detect concurrent changes to a Teleport resource between read and write, and reject a stale write with a clear message.

**Resources and enrollment**

- **FR-015**: The system MUST list enrolled resources (servers, applications, databases, Kubernetes clusters, desktops) with labels, status, last-seen time and agent version, and support filtering and search.
- **FR-016**: The system MUST let authorized users create join tokens for a chosen resource type. The default validity is 30 minutes and the maximum is 24 hours.
- **FR-017**: For each join token, the system MUST show the token and a matching install/join command once.
- **FR-018**: The system MUST list active join tokens without showing their secret values, and allow revoking them.
- **FR-019**: The system MUST link enrolled servers to tangra inventory and asset records that match exactly one record by hostname or address, offer ambiguous matches for manual confirmation, and show the link in both directions.
- **FR-020**: The system MUST flag resources that stay offline longer than a configurable threshold (default 15 minutes), and optionally alert on them.

**Audit, sessions and alerting**

- **FR-021**: The system MUST let authorized users search Teleport audit events by time range (required, maximum 31 days per query), event type, user and resource, with paging.
- **FR-022**: The system MUST let authorized users list recorded sessions with participants, target, start time and duration, with a link to playback in the Teleport web UI.
- **FR-023**: The system MUST let tenant administrators define alert rules on Teleport event types and on module conditions (cluster unreachable, credential expiring, resource offline), and deliver them through the tangra notification channels.
- **FR-024**: The system MUST write a tangra audit record for every change it makes or attempts. Each record holds actor, tenant, cluster, action, target and outcome.
- **FR-025**: The system MUST publish platform events, which other tangra modules can consume, when clusters, users, locks, tokens and resources change. These events MUST carry identifiers only and no secrets.

**Identity provisioning**

- **FR-026**: The system MUST let tenant administrators define mappings from tangra roles/groups to Teleport roles and logins, per cluster.
- **FR-027**: The system MUST provision Teleport users for tangra users who match a mapping, and send them the invite through tangra notifications.
- **FR-028**: The system MUST de-provision managed users, by locking them and then deleting them after a configurable grace period (default 7 days), when they leave the tenant or lose every mapped role. Synchronization MUST run at least every 15 minutes and when tangra membership changes.
- **FR-029**: The system MUST never change Teleport users it did not create (unmanaged users) during automatic synchronization.

**Guided deployment**

- **FR-030**: The system MUST provide a deployment wizard. From domain, certificate choice (ACME email or own certificate) and Teleport version, it generates a configuration file, a version-pinned install script, a DNS/network checklist, and first-administrator and management-identity setup steps.
- **FR-031**: The system MUST be able to check deployment prerequisites: domain and wildcard DNS resolution, and port 443 reachability with a valid certificate.

**Platform integration**

- **FR-032**: The system MUST appear in the tangra portal as a module, with navigation, help documentation, and catalogue metadata for installation.
- **FR-033**: The system MUST define module permissions with at least an administrator role (full management) and a viewer role (read-only, including audit). It MUST check those permissions on every action.
- **FR-034**: The system MUST degrade gracefully when an optional tangra dependency (notification, inventory, asset, scheduler) is unavailable. Core cluster management keeps working, and the affected features show as temporarily unavailable.
- **FR-035**: The system MUST include its own configuration (cluster registrations, mappings, alert rules, deployment drafts) in tangra's backup and restore. Secrets are carried as references only.

### Security Requirements *(mandatory — Constitution: Development Workflow)*

- **Trust boundaries crossed**:
  - the browser API through the gateway;
  - the outbound connection to each tenant's Teleport cluster (an external, tenant-controlled system);
  - the platform secret store (management credentials);
  - the platform event bus (tangra membership events in, Teleport events out);
  - service-to-service mesh calls (auth, notification, scheduler, inventory, asset, secrets);
  - outbound prerequisite probes (DNS lookups and TLS dials) to administrator-supplied domains.
- **Data classification**:
  - Management credentials, join tokens and invite/reset links are **secrets**.
  - Teleport audit events and session metadata are **tenant-confidential** and contain user and host identifiers (PII).
  - Role definitions and lock reasons are **tenant-confidential**.
  - Module audit records are **tamper-evident**.
- **Authentication/Authorization**:
  - Browser callers use the gateway platform token with a permission on every route.
  - Module callers use SPIFFE mTLS with a deny-by-default policy.
  - Row-level security isolates tenants.
  - The module acts on Teleport only through each cluster's dedicated least-privilege management identity, never with platform-wide credentials.
- **Threat scenarios**:
  - one tenant reading or acting on another tenant's cluster;
  - the module being used as a server-side request forgery (SSRF) pivot through cluster addresses or deployment probes into internal networks;
  - a malicious or compromised Teleport cluster returning oversized or crafted responses;
  - leakage of management credentials, tokens or invite links through responses, logs, events or audit;
  - a non-administrator raising Teleport privileges through role edits or mappings;
  - forged membership events triggering provisioning or de-provisioning;
  - the module locking itself out, or deleting built-in roles.
- **SR-001**: All local data MUST be isolated per tenant by row-level security. Every Teleport operation MUST first verify that the cluster belongs to the caller's tenant.
- **SR-002**: Management credentials, join tokens and invite links MUST come from, or go only to, the secret store or a single one-time response. They MUST never appear in other responses, logs, events or audit records.
- **SR-003**: Cluster addresses and deployment probe targets MUST be validated, and outbound connections to loopback, link-local, metadata-service and (unless explicitly allowed per deployment) private address ranges MUST be refused, with the check applied to the resolved addresses.
- **SR-004**: Responses from Teleport clusters MUST be bounded in size and time and decoded into typed structures. Teleport-supplied text shown in the UI MUST be encoded.
- **SR-005**: Changes to roles, role mappings and locks MUST require the module administrator permission. Operators MAY create join tokens and locks, but MUST NOT change roles or mappings.
- **SR-006**: Membership events MUST be re-verified with the auth service before any provisioning or de-provisioning action.
- **SR-007**: Every change MUST be audited append-only with actor, tenant, cluster, action, target and outcome.

### Key Entities

- **Teleport Cluster Registration**: a tenant's connection to one Teleport cluster.
  - Holds display name, proxy address, cluster name, detected version, edition, management credential reference and expiry, health status, and last contact time.
- **Managed Teleport User (link)**: the link between a Teleport user and a tangra user.
  - Holds whether tangra manages the user, the source mapping, and the provisioning state (active, locked-pending-deletion).
  - The Teleport user itself remains owned by Teleport.
- **Role Mapping**: per cluster, maps a tangra role or group to Teleport roles and allowed logins.
- **Join Token Record**: metadata for a join token created through tangra (resource type, creator, expiry, revoked state).
  - Never holds the secret value after it has been shown.
- **Resource Link**: links a Teleport-enrolled resource to a tangra inventory or asset record, with how the match was made (automatic or confirmed).
- **Alert Rule**: a condition (Teleport event type or module condition), its scope (cluster), and its recipients/channels.
- **Deployment Draft**: wizard inputs, generated artifacts, and prerequisite check results for a planned cluster.
- **Teleport resources read live**: users, roles, locks, nodes and other resources, audit events and sessions.
  - Shown from the cluster. Tangra does not keep them as the source of truth.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An administrator can register an existing cluster and see its health overview in under 5 minutes, given a prepared management credential.
- **SC-002**: Creating a Teleport user with roles and getting the invite link takes under 1 minute and needs no shell access to the cluster host.
- **SC-003**: A new server can be enrolled from token generation to "online in tangra" in under 10 minutes by an operator following only the module's instructions.
- **SC-004**: A lock created in tangra takes effect in Teleport within 30 seconds of confirmation.
- **SC-005**: Cluster outages and expiring credentials are detected and alerted within 5 minutes. No credential expires without at least one prior warning.
- **SC-006**: Audit event searches over a 24-hour window return their first page in under 3 seconds for clusters with up to 100,000 events per day.
- **SC-007**: 100% of changes made through the module produce a tangra audit record. 0 secrets (credentials, tokens, invite links) appear in logs, events or audit records, as verified by automated scanning.
- **SC-008**: Users who lose access in tangra are locked in every mapped Teleport cluster within one sync interval (default 15 minutes).
- **SC-009**: A new Community Edition cluster can be deployed and registered by following the wizard in fewer than 10 manual steps.

## Assumptions

- **Target edition**: the target is self-hosted Teleport Community Edition, the current major version and the one before it. Enterprise and Teleport Cloud are out of scope, though a compatible Enterprise cluster may still connect with Enterprise-only features hidden.
- **Management identity**: the module authenticates to each cluster as a dedicated Teleport identity with a least-privilege role, following Teleport's API guidance. The administrator supplies the credential, or creates it with wizard guidance; it can be an exported identity or a machine identity that renews automatically.
- **Network reach**: the module reaches each cluster over the cluster's public proxy address (port 443). No direct network access to the cluster's internal services is needed.
- **Tenancy**: clusters belong to exactly one tangra tenant, and cross-tenant cluster sharing is out of scope for v1.
- **Source of truth**: Teleport stays the source of truth for its own users, roles, resources, audit events and session recordings. Tangra stores only registrations, links, mappings, rules, drafts and token metadata.
- **No session replay in v1**: session recordings are listed, but playback happens in the Teleport web UI, reached by deep link.
- **Deployment is guided, not executed**: the wizard produces artifacts and checks, and the administrator runs the install on the host. Running it remotely through other tangra modules may come later.
- **Existing platform services**: tangra's existing authentication, permissions, secrets, notification, scheduler, inventory, asset, audit, backup and portal services are reused, not duplicated.
- **Out of scope for v1**: SSO connector management, Access Requests, trusted clusters, Teleport plugin configuration, and Machine ID bot management beyond the module's own management identity.
