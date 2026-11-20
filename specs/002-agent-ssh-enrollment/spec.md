# Feature Specification: Enroll Inventory Hosts as Teleport SSH Nodes Through the Inventory Agent

**Feature Branch**: `002-agent-ssh-enrollment`

**Created**: 2026-11-20

**Status**: Draft

**Spans**: go-tangra-teleport (primary: enrollment service, join-material
source, UI), go-tangra-inventory-v4 (agent installer, delivery item and
command, mesh client, SDK contract), go-tangra-docker (policies, user-applied)

**Input**: User description: "I'd like to be able to enroll resources via
the tangra inventory client."

**Binding user decisions** (2026-11-20):

1. **The agent installs Teleport itself.** No local hook is required; the
   agent downloads, verifies and installs the Teleport version the cluster
   runs, writes the configuration and starts the service.
2. **SSH only.** The enrolled host runs the Teleport SSH service only (no
   app, database, Kubernetes or desktop service).
3. **Inventory facts become Teleport labels** on the node.

Builds on 001 US3 (join tokens, resource links, `teleport.v1.Access`) and on
inventory 033/037 (reference-only commands, material pulled at fetch time,
the enrolled agent trusted as the host).

## Context

Today an operator enrolls a server by creating a join token in the module
(001 US3), copying the install command to the host and running it as root.
Most tenant hosts already run an enrolled inventory agent that the platform
trusts to identify the host and that keeps an authenticated command stream
to inventory. The module can enroll those hosts directly: pick hosts, choose
a cluster, click **Enroll**. The node then appears in the cluster with
labels taken from the host's inventory record and is linked to that host.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Enroll an inventory host as an SSH node (Priority: P1) 🎯 MVP

On a cluster's **Resources** tab an operator chooses **Enroll inventory
hosts**, searches the tenant's inventory hosts, and selects one or more
whose agent is online, runs Linux with systemd and supports Teleport
enrollment. The dialog shows, per host, the labels the node will get. The
operator clicks **Enroll**. The agent installs Teleport (the cluster's
version), joins the cluster as an SSH node and reports back. The dialog shows
progress live: queued, delivered, installing, joined (or failed with a
reason). The node appears in the Resources tab, linked to its inventory host.

**Why this priority**: it removes the copy-paste-as-root step for the
common case and is the whole value of the feature.

**Independent Test**: with a Teleport CE container and a test agent
connected, enroll one host. The node joins, carries the expected labels,
is linked to the inventory host, and no join token appears in the module or
inventory database, logs, audit, events or command payloads.

**Acceptance Scenarios**:

1. **Given** an online Linux agent and a healthy cluster, **When** the
   operator enrolls the host, **Then** within 5 minutes the node is listed by
   the cluster with labels from FR-010 and the resource link to the host.
2. **Given** a host whose agent is offline, **When** the operator enrolls
   it, **Then** the item stays queued and runs when the agent reconnects,
   until it expires (default 24 h).
3. **Given** a Windows host, an agent too old, or enrollment disabled on the
   agent, **Then** the host is shown as not eligible and cannot be selected
   (or the agent reports `unsupported` / `disabled_locally`).
4. **Given** a host already running Teleport (`/etc/teleport.yaml` exists or
   the `teleport` unit is active), **Then** the agent refuses with
   `already_installed` and changes nothing.
5. **Given** a viewer or a user without `resources:enroll` on the cluster,
   **Then** the action is not offered and the API answers forbidden.

---

### User Story 2 - Follow and retry enrollments (Priority: P2)

The operator sees each host's enrollment state on the cluster (and on the
host in inventory): `queued`, `delivered`, `installing`, `joined`, `failed`
(with a reason from a closed set), `expired`, `cancelled`. A failed or
expired item can be retried (a new item; the old one stays in history). A
queued item can be cancelled.

**Independent Test**: force a download failure, see `failed:
download_failed`, retry after fixing it, see `joined`.

---

### User Story 3 - Keep labels in line with inventory (Priority: P3)

When a host's inventory facts change (OS upgrade, new tag), the node's
labels follow. The module re-renders the labels and inventory sends the
agent a label update; the agent rewrites the `labels` block of
`/etc/teleport.yaml` and restarts the Teleport service. Labels set by hand
outside the `tangra.io/` prefix are never touched.

**Independent Test**: tag the host `env=prod` in inventory; within the
next sync the node carries `tangra.io/tag.env=prod`.

---

### User Story 4 - Host owner control (Priority: P2)

The host owner can turn Teleport enrollment off in the agent's local
configuration (`teleport.enabled: false`, default **true** on Linux). The
server never chooses a path, a command, a download location or a service
user on the host; those come from the agent's built-in installer and local
configuration.

### Edge Cases

- **Cluster unreachable or read-only** (`unsupported_version`, credential
  expired) when the agent fetches: the fetch fails with
  `cluster_unavailable`; the item is retried until its fetch budget (5) is
  spent, then `failed`.
- **Token expiry**: the join token is minted at fetch time with a 30-minute
  lifetime; an install that takes longer fails with `join_failed` and is
  retried as a new item.
- **Download integrity**: a package whose SHA-256 does not match the
  checksum published for that version is refused (`checksum_mismatch`);
  nothing is installed.
- **Unsupported distribution or architecture** (no Teleport build): the
  agent reports `unsupported_platform` before downloading.
- **Two agents claim the same host**: the item is `unsupported` (inventory
  SR-001 of 037).
- **Node already in the cluster under the same host UUID**: the cluster
  answers with the existing node; the module links it and the item is
  `joined`.
- **Host deleted or retired in inventory** while queued: the item is
  cancelled.
- **Cluster deleted**: queued items for it are cancelled; joined nodes are
  left alone (the operator removes Teleport on the host).
- **Proxy address private**: the address the agent dials is the cluster's
  registered proxy address; the agent applies no SSRF policy of its own
  beyond refusing loopback and link-local (the host's network decides).

## Requirements *(mandatory)*

### Functional Requirements

#### Teleport module

- **FR-001**: The module MUST offer
  `GET /clusters/{id}/enrollment-targets` (`resources:enroll`) listing the
  tenant's inventory hosts (through `inventory.v1`, as the caller) with
  hostname, OS, architecture, agent online, eligibility (and why not), the
  labels the node would get, and any active enrollment item.
- **FR-002**: The module MUST offer `POST /clusters/{id}/enrollments`
  (`resources:enroll`, CSRF) with `host_ids` (1–50) and an optional
  `ttl_hours` (1–72, default 24). For each host it creates an enrollment
  record (no token) and asks inventory to create a Teleport delivery item.
  It returns the enrollment ids. A newer request for the same (host,
  cluster) supersedes the older active one.
- **FR-003**: The module MUST offer `GET /clusters/{id}/enrollments`
  (`resources:read`) and `POST /clusters/{id}/enrollments/{eid}/cancel`
  and `/retry` (`resources:enroll`). The list refreshes unfinished
  enrollments from inventory (`stale: true` when it cannot be reached).
- **FR-004**: The module MUST serve `inventory.v1.TeleportJoinSource/RenderTeleportJoin`
  (defined in the inventory SDK, implemented here) on the mesh, accepted
  only from svc/inventory (policy plus a handler check).
  Given an enrollment id, tenant and host id that match an active
  enrollment with fewer than 5 renders, it MUST mint a single-use Teleport
  provision token (role `Node`, join method `token`, 30-minute TTL), and
  return: the token, the proxy address, the cluster's CA pin(s), the
  Teleport version the cluster runs, and the labels (FR-010). Nothing of it
  is stored.
- **FR-005**: The module MUST follow each enrollment's progress (state,
  reason, node host UUID) by reading it from inventory
  (`TeleportJoinDeliveryService/GetTeleportJoins`) when the list is read
  and in a leased sweep (every minute), never moving an unfinished state
  backwards, and on `joined` confirm the resource link between the node
  and the inventory host (001 US3) once the node's snapshot exists,
  creating no duplicate. An unfinished enrollment inventory no longer knows
  after its expiry becomes `expired`.
- **FR-006**: Every step MUST be audited without secrets
  (`teleport.enrollment.create|render|report|cancel|retry`, target the
  enrollment, details: host id, cluster, state, reason).
- **FR-007**: The module MUST publish `teleport.enrollment.changed` events.

#### Inventory service

- **FR-008**: Inventory MUST store a Teleport delivery item per (host,
  cluster) without token material and push a `COMMAND_TYPE_TELEPORT_JOIN`
  command carrying only the item id and attempt. It MUST replay active
  items when the agent reconnects, and accept item creation only from
  svc/teleport (policy plus a handler check).
- **FR-009**: When the agent calls `FetchTeleportJoin(item_id)`, inventory
  MUST call `JoinSource/RenderJoin` on svc/teleport, relay the answer to the
  agent and keep nothing (buffer zeroed). It records the agent's
  `ReportTeleportJoin` on the item, where the module reads it (FR-005). The fetch is refused on a
  plaintext ingest edge unless `allow_plaintext_ingest` is set (033).

#### Labels

- **FR-010**: The node's static labels MUST be derived from the host's
  inventory record, all under the `tangra.io/` prefix:
  - `tangra.io/inventory-host` = inventory host id
  - `tangra.io/hostname`, `tangra.io/os` (os_name), `tangra.io/os-version`,
    `tangra.io/arch`, `tangra.io/manufacturer`, `tangra.io/model`
  - `tangra.io/tag.<key>` = value for each inventory tag
  Keys and values are sanitized to Teleport's label syntax (keys
  `[A-Za-z0-9._/-]`, values printable, at most 63 / 255 characters), empty
  facts are omitted, at most 64 labels. The module computes labels; the
  agent only writes them.
- **FR-011** (US3): When a linked host's facts change, the module MUST
  re-render the labels and, if they differ, ask inventory to push a label
  update (`COMMAND_TYPE_TELEPORT_LABELS`, item id only; the agent fetches
  the labels). The agent rewrites only the `tangra.io/` labels in
  `/etc/teleport.yaml` and restarts the service.

#### Agent

- **FR-012**: The agent MUST install Teleport itself on Linux with systemd:
  download the release tarball for the reported version and its
  architecture from `cdn.teleport.dev`, verify the SHA-256 against the
  published `.sha256`, install the binaries to `/usr/local/bin`, write
  `/etc/teleport.yaml` (mode 0600) with `ssh_service` enabled and
  `auth_service` / `proxy_service` disabled, the proxy address, the
  token (join method `token`), the CA pin(s) and the labels, write a
  `teleport.service` unit, and `systemctl enable --now teleport`.
- **FR-013**: The agent MUST report `installing`, then `joined` (with the
  node's host UUID read from `/var/lib/teleport/host_uuid` after the service
  is active and the node certificate exists), or `failed` with a reason
  from the closed set: `unsupported_platform`, `already_installed`,
  `disabled_locally`, `download_failed`, `checksum_mismatch`,
  `install_failed`, `join_failed`, `cluster_unavailable`, `timeout`.
- **FR-014**: The agent MUST handle one Teleport item at a time, give up
  after 15 minutes (`timeout`) and leave a failed install's files in place
  for diagnosis except the token, which it removes from
  `/etc/teleport.yaml` on failure.

### Security Requirements

- **SR-001**: The enrolled agent is trusted as the host (037 SR-001):
  inventory hands an item only to the agent bound to that item's host.
- **SR-002**: The join token exists only in memory along the fetch path
  (module → inventory → agent) and in `/etc/teleport.yaml` (0600, root) on
  the host. It never appears in commands, database rows, audit, events,
  logs or API responses. It is single-use and expires in 30 minutes.
- **SR-003**: Only the configured source may render: the module accepts
  `JoinSource/*` only from svc/inventory; inventory accepts Teleport item
  creation only from svc/teleport.
- **SR-004**: The host decides: the agent's local `teleport.enabled`
  switch, built-in paths and the fixed download origin are never
  configurable by the server. The server-supplied values (version, proxy
  address, CA pins, labels) are validated by the agent: version `x.y.z`,
  proxy `host:port`, CA pin `sha256:<64 hex>`, labels per FR-010; anything
  else is refused (`install_failed: invalid_material`).
- **SR-005**: Enrollment is SSH only: the rendered configuration never
  enables another Teleport service, and the token role is `Node` only.
- **SR-006**: The redaction scan (001 SC-007) covers the new paths with a
  sentinel token.

### Key Entities

- **Enrollment** (teleport module): id, tenant, cluster, inventory host id,
  state, reason, attempt, render count, node host UUID, expires_at,
  created_by, timestamps. No token.
- **Teleport delivery item** (inventory): id, tenant, host, enrollment id,
  cluster id, state, attempt, timestamps. No token.

## Success Criteria *(mandatory)*

- **SC-001**: An operator enrolls an eligible host in under one minute of
  interaction, and the node joins within 5 minutes of the agent receiving
  the command.
- **SC-002**: 50 hosts enrolled in one request all reach a final state;
  each joined node carries exactly the FR-010 labels and one resource link.
- **SC-003**: The sentinel join token appears zero times in any captured
  output (database, logs, audit, events, commands, API responses).
- **SC-004**: A tampered package (checksum mismatch) is never installed.

## Assumptions

- Targets are Linux hosts with systemd on amd64 or arm64; Windows and
  macOS are out of scope (shown as not eligible).
- Hosts can reach the cluster's proxy address and `cdn.teleport.dev`.
- The token join method is used (no IAM/Azure/GCP join).
- Removing Teleport from a host (un-enrollment) is out of scope; locking or
  deleting the node in the module (001) still works.
- Inventory host facts are those of the latest snapshot as reflected on the
  Host record; no new facts are collected for this feature.

## Out of Scope

- App, database, Kubernetes and desktop services (decision 2).
- Upgrading Teleport on enrolled nodes (Teleport's own agent updates).
- Running a local hook instead of the built-in installer (decision 1).
