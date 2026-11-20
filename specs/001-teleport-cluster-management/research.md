# Research: Teleport Cluster Management Module

**Feature**: [spec.md](./spec.md) | **Plan**: [plan.md](./plan.md) | **Date**: 2026-11-19

Each decision below records what was chosen, why, and the alternatives that were rejected. Items marked **Verify** are confirmed by a spike task in the Setup phase of `tasks.md` before dependent work starts.

## D1 — Talking to Teleport: the official `api` Go module

- **Decision**: Use `github.com/gravitational/teleport/api`, only its `client`, `types`, `client/proto` and `types/events` packages.
  - Connect through the cluster's public proxy address (`<proxy>:443`) using TLS routing.
  - Authenticate with identity-file credentials loaded from memory (`client.LoadIdentityFileFromString`).
  - Pin the major version so that the supported cluster versions are N and N-1.
- **Rationale**:
  - It is the supported, typed gRPC surface for users, roles, locks, tokens, resources, audit search and watchers.
  - Its license (Apache-2.0) is separate from the main Teleport repository (AGPL-3.0).
  - Using the proxy address keeps the spec's single-port assumption.
- **Alternatives rejected**:
  - Shelling out to `tctl` would need binaries in the image, parse unstructured output and widen the attack surface.
  - Importing `github.com/gravitational/teleport/lib/...` would pull in AGPL code and a very large dependency tree.
  - The Teleport Terraform provider or Kubernetes operator are not interactive, and are designed for another kind of tool.
- **Verify**:
  - The dependency footprint of the `api` module (module graph size, `govulncheck`, license scan) is recorded under Principle VI.
  - Proxy-address dialling (ALPN/TLS routing) works on a Community Edition test cluster.
- **Spike outcome (T008, 2026-11-19)** — status: *compile-verified*; the live dial is *not runtime-confirmed*.
  - **Version**: `github.com/gravitational/teleport/api v0.0.0-20260825163510-1283425b60ec`. The `api` module publishes no semver tags; this pseudo-version is the `api/` tree at Teleport 19.0.0-prealpha.2, which supports clusters on 19 (N) and 18 (N-1). It requires `go 1.26.7`, so go.mod declares `go 1.26.7` (plan.md says Go 1.26). Re-pin it to the commit of the 19.0.0 GA release when that is tagged.
  - **Module graph**: `go list -m all` lists 205 modules, including the tangra SDKs and freya. `scripts/license-check.sh` passes: there is no AGPL module.
  - **No `lib/`**: `go list -deps ./...` imports no `github.com/gravitational/teleport/lib` package. Only `api/client`, `api/client/proto`, `api/identityfile`, `api/types` and `api/gen/proto/go/teleport/users/v1` are used.
  - **govulncheck (v1, 2026-11-19)**:
    - The first run found 18 reachable vulnerabilities:
      - 12 in the Go standard library (`net/http`, `crypto/x509`, `crypto/tls`, `net/textproto`, `os`, `html/template`) in the local toolchain, go1.26.8; they are fixed in go1.26.9 to go1.26.11;
      - in `golang.org/x/net` v0.58.0;
      - in `golang.org/x/crypto` v0.55.0 (ssh DoS, reached through `api/client`);
      - in `go.opentelemetry.io/otel/exporters/otlp/otlptrace` v1.44.0.
    - The modules were bumped to x/net v0.60.0, x/crypto v0.57.0 and otlptrace v1.45.0. The remaining findings are standard-library ones and are fixed by building with go ≥ 1.26.11. The Dockerfile base image `golang:1.26` picks up the patched toolchain. `scripts/vulncheck.sh` runs this in CI.
  - **Dial path**: `internal/teleportapi.Dial` loads the identity from memory with `client.LoadIdentityFileFromString`. It resolves the proxy address once through netguard and dials the pinned IP, using TLS routing with the cluster name as the ALPN SNI. gRPC message size, call timeout and concurrency are bounded.
  - **Tests**: unit tests cover the adapter types, the bounds (gRPC interop server over bufconn) and the pool and cache. The live check is `internal/teleportapi/spike_test.go` (build tag `spike`): `TestSpikeD1DialThroughProxy` needs `TELEPORT_SPIKE_PROXY` and `TELEPORT_SPIKE_IDENTITY`. It was not run because no Teleport cluster or Docker is available in this environment. Run it before T034 relies on ALPN routing.

## D2 — Management credential and renewal

- **Decision**: v1 supports two credential types, both stored as a `warden:` reference, never in the module database.
  1. **Identity file** exported with `tctl auth sign --user=tangra-mgmt --format=file --ttl=<≤ 2160h>`.
     - Expiry is read from the certificate.
     - Alerts fire at 7 days, 1 day and on expiry.
     - Replacement is an explicit "rotate credential" action.
  2. **Bot identity** for a Teleport Machine ID bot with the same role.
     - The module renews it itself before 2/3 of its TTL has passed.
     - It re-issues certificates through the API client and writes the new identity back to warden as a new version.
     - If renewal fails it falls back to the alert path.
- **Rationale**: identity files are the documented way to give API clients credentials. Bot certificates are renewable and short-lived, which matches Principle II. Embedding `tbot` would pull in AGPL `lib/` code.
- **Alternatives rejected**:
  - Running a `tbot` sidecar per cluster is too much operational overhead for each tenant cluster.
  - Storing a static admin password is not supported for the API and is insecure.
- **Verify**: certificate re-issue for a bot identity with the `api` module only. If it is not feasible without `lib/`, v1 ships identity-file mode only and bot mode moves to a later iteration. No P1 story depends on bot mode.
- **Spike outcome (T009, 2026-11-19)** — **bot mode is deferred**; v1 ships identity-file mode only.
  - `api/client.(*Client).GenerateUserCerts` exists and compiles against the pinned module. `TestSpikeD2ReissueCerts` (build tag `spike`) calls it with fresh SSH and TLS public keys for the identity's own user. It was not run here: no live cluster.
  - A Machine ID bot cannot be renewed this way. Bot certificates carry a generation counter, and renewal goes through the bot join/renew flow. That flow is implemented in `tbot` and `lib/auth` (AGPL), not in `api/`. Re-implementing it is out of scope and risks lock-out on a generation mismatch.
  - warden exposes no write RPC (see D11), so a renewed identity could not be written back as a new version anyway.
  - Done: `bot` was removed from `credential_kind` in data-model.md and contracts/http-api.md. T050 evaluates expiry only. Bot mode becomes a later iteration once warden can write and either a renewal path without `lib/` exists or a tbot sidecar is accepted.

## D3 — Least-privilege management role

- **Decision**: Ship a reference Teleport role `tangra-manager` in help docs and in the deployment wizard output, with these permissions:
  - `user`, `role`, `lock`, `token`: read, list, create, update, delete;
  - `node`, `app_server`, `db_server`, `kube_server`, `windows_desktop`: read, list;
  - `event`, `session`: read, list;
  - `cluster_auth_preference`: read.
  
  The module reports which permissions are missing at registration by probing read access. Write probes are not run.
- **Rationale**: this follows Teleport's API guidance (a dedicated user with a scoped role) and lets health checks state what is allowed.
- **Alternative rejected**: requiring the built-in `editor` role grants far more than the module needs.

## D4 — Source of truth and caching

- **Decision**: Teleport stays the source of truth. The module stores only registrations, links, mappings, alert rules, drafts, token metadata, resource snapshots (for offline detection and inventory links), and alert cursors.
  - Lists are read live from Teleport with server-side paging (`ListResources`, user, role and lock listing).
  - The read path has a short Valkey cache (TTL 15 s, keyed by tenant and cluster) to protect clusters from UI bursts.
- **Rationale**: this avoids drift and two-way sync problems (spec edge case "change made outside tangra").
- **Alternative rejected**: a full local mirror would need complex reconciliation and would make tangra a second, stale source of truth.

## D5 — Concurrency control on writes

- **Decision**: Use Teleport resource revisions (`Metadata.Revision`) with conditional updates.
  - The browser sends back the revision it read.
  - A mismatch maps to `409 conflict` (FR-014).
- **Alternative rejected**: last-write-wins silently overwrites changes made with `tctl`.

## D6 — Role definition editing

- **Decision**: The UI edits roles as YAML (`kind: role`, `version: v7`/`v8`).
  - The server parses YAML → JSON → typed role and runs the type's own `CheckAndSetDefaults()`.
  - It rejects other kinds and anything over 64 KiB.
  - It returns a normalized-YAML diff against the current revision for the preview.
  - Preset roles are detected by the `teleport.internal/resource-type: preset` label and cannot be deleted (FR-011).
- **Rationale**: YAML is the format Teleport administrators already use. Reusing the type's own validation avoids re-implementing role semantics.
- **Alternative rejected**: a fully structured role form cannot cover the role schema in v1 (a simplified form may come later).

## D7 — Change notification and offline detection

- **Decision**: One cluster watcher per connected cluster, running inside the module.
  - It uses `client.NewWatcher` on kinds `node`, `app_server`, `db_server`, `kube_server`, `windows_desktop`, `lock`, `user` and `role`.
  - It updates resource snapshots, publishes platform events, and invalidates the cache.
  - A server-kind delete (heartbeat expiry) marks the resource offline with a timestamp.
  - A sweep flags resources offline longer than the threshold (default 15 minutes) and raises alerts.
  - With several replicas, each watcher is owned through a Valkey lease (`teleport:watch:<cluster_id>`, 30 s TTL, renewed every 10 s).
- **Rationale**: this meets SC-004 and FR-020 without polling every resource list, and keeps working when the scheduler is unavailable (FR-034).
- **Alternative rejected**: polling `ListResources` every minute is expensive on large clusters and slower to react.

## D8 — Audit events, sessions and alert rules

- **Decision**:
  - **Search** is served live through Teleport event search and session-event search, with a required time range (≤ 31 days), page size ≤ 200 and opaque `next` keys passed back to the browser (FR-021/022).
  - **Alert rules** are evaluated by an alert poller per cluster, under the same lease as D7.
    - Every 30 s it searches from a stored cursor (last event time and id), restricted to the event types used by enabled rules.
    - Rules support "any match" and "≥ N matches within W minutes per user" (for failed-login bursts).
    - Deliveries are de-duplicated per rule, cluster and window.
  - **Session playback** is a deep link to `https://<proxy>/web/cluster/<cluster>/session/<sid>`.
- **Rationale**: this meets the 5-minute alert target (SC-005, US4-AS2) without copying audit data into tangra.
- **Alternative rejected**: streaming the whole audit log into TimescaleDB duplicates Teleport's storage and makes a second PII store.

## D9 — Join tokens and install commands

- **Decision**:
  - Tokens use the `token` join method.
  - Roles map from the resource type: `Node`, `App`, `Db`, `Kube`, `WindowsDesktop`.
  - TTL defaults to 30 minutes, with a maximum of 24 hours (FR-016).
  - The token value goes back once in the create response, with the install command:
    - for servers, `curl -fsSL https://<proxy>/scripts/<token>/install-node.sh | sudo bash`;
    - for other types, a generated `teleport.yaml` snippet plus `teleport <type> start` arguments.
  - Only the token name hash, type, creator, expiry and revoked state are stored.
  - Revocation deletes the token in Teleport.
  - Delegated join methods (iam, github, kubernetes, bound_keypair …) are out of v1 scope.
- **Rationale**: this is the documented secure method, and it is short-lived (Principle II).

## D10 — Tangra identity provisioning

- **Decision**:
  - **Role mappings** are stored per cluster: a tangra module role or group maps to Teleport roles and logins.
  - **Managed users** get labels `tangra.io/managed: "true"`, `tangra.io/tenant: <id>` and `tangra.io/user: <id>`. The Teleport username is the tangra login (sanitized, collisions rejected).
  - **Reconciliation** runs in two ways:
    - **event-driven**: on auth membership and role-change events from the platform stream (each re-verified with `go-tangra-auth` over mTLS, SR-006);
    - **periodic**: the scheduler task `teleport:sync-provisioning` every 15 minutes.
  - **De-provisioning** creates a lock (`tangra de-provisioned`), then deletes the user after the grace period through `teleport:purge-deprovisioned`.
  - Users without the managed label are never changed (FR-029).
  - Invites go out through notification to the user's tangra e-mail. The link is never stored.
- **Verify**: the exact auth event type names and payloads in `go-tangra-auth` v4. If no suitable event exists, the periodic sync alone meets SC-008.
- **Spike outcome (T010, 2026-11-19)** — read from ../go-tangra-auth (v4 SDK).
  - auth publishes no membership or role-change events on the platform stream. Its event types are notification templates (`auth.invite`, `auth.account_reset`, `auth.recovery`, …), not membership changes.
  - The periodic `teleport:sync-provisioning` task alone meets SC-008, as allowed above. T103 is reduced to that sync.
  - Session revocations can optionally be watched through `authv1.Sessions` (the verifier already consumes them) to speed up de-provisioning.
  - Membership and role reads go through the auth SDK over mTLS (SR-006).

## D11 — Platform integration surface (tangra v4 pattern)

- **Framework and platform plumbing**:
  - **Framework**: freya (`github.com/go-tangra/go-tangra/v4`) on Kratos v3.
  - **Gateway**: registration through `gatewayclient` with `pkg/teleportmanifest`.
  - **Catalogue**: `tangra-module.yaml` and `deploy/bundle/`.
  - **Help docs**: `docs/help` loaded with `helpdocs.Load`.
- **Secrets (warden SDK)**: the module writes the uploaded credential to a module folder and keeps only the `warden:` reference. It resolves credentials at use time (`internal/secrets`, the pattern from dns-v4).
- **Notification**: alert delivery and invites.
- **Scheduler (`schedulerclient.Registrar` + `sdktask.NewServer`, the pattern from signing-v4)**:
  - `teleport:health-check` (1 min, backstop for watchers);
  - `teleport:sync-provisioning` (15 min);
  - `teleport:purge-deprovisioned` (hourly);
  - `teleport:credential-expiry` (hourly);
  - `teleport:token-gc` (hourly; prunes expired token metadata).
  
  Watchers and pollers (D7/D8) do not depend on the scheduler.
- **Inventory and asset SDKs (read-only lookup by hostname or IP)**:
  - Links are made for unique matches and offered for confirmation when ambiguous.
  - Other modules can query `teleport.v1.Access/LookupHost` over gRPC ([contracts/grpc.md](./contracts/grpc.md)) to show a "reachable via Teleport" badge.
- **Events**:
  - Out: `teleport.*` on `platform:events:<tenant>`, carrying ids only.
  - In: auth membership events.
- **Audit and backup**:
  - Audit uses the framework `audit` package and an `internal/audit` vocabulary.
  - Backup exports registrations, mappings, rules and drafts (secrets as references, FR-035).
- **Verify**: the inventory-v4 and asset-v4 SDKs expose host lookup by hostname or IP. If they do not, add a small read RPC in those modules (a cross-repo task) or fall back to manual linking.
- **Spike outcome (T010, 2026-11-19)** — read from ../go-tangra-inventory-v4, ../go-tangra-asset-v4, the warden SDK and freya v4.10.0.
  - **Inventory and asset**: neither offers a host lookup by hostname or IP. Their gRPC surfaces are CRUD and list (`ListAssets`, `GetAsset`, …) with no hostname/IP filter. T079 is marked NEEDS CROSS-REPO: add a small `LookupHost`-style read RPC in each module. Until then, linking is manual (confirmed links only).
  - **warden**: the SDK offers reads only (`GetPassword`); there is no create or update RPC. `internal/secrets.Warden` returns `ErrWriteUnsupported` for `Put` and `Delete`. Development stores credentials through `FileStore` (`secrets.allow_file`, refused in production). Registering a cluster in production needs a warden write RPC (cross-repo gap).
  - **Audit**: the framework `audit` package has a closed action vocabulary that cannot carry `teleport.*` actions. The module keeps its own batched writer in `internal/audit`, with a closed vocabulary, redaction and an append-only `audit_events` table.
  - **Status**: compile-verified against the real SDKs; there is no runtime confirmation against running peers.

## D12 — SSRF guard for cluster addresses and deployment probes

- **Decision**: One `netguard` package resolves the hostname and checks every resolved IP before dialling. It refuses:
  - loopback, link-local, `169.254.169.254`/`fd00:ec2::254`;
  - multicast and unspecified addresses;
  - RFC 1918 / ULA, unless the deployment config lists them in `teleport.allowed_private_networks`.
  
  - The dialler is pinned to the checked IP, which prevents DNS rebinding.
  - Ports are limited to an allow-list (default `[443, 3080]`).
  - Probe timeouts are 5 s.
- **Rationale**: SR-003. On-prem clusters on private networks are common, so private ranges are an explicit, logged opt-out (Principle I).

## D13 — Edition and version detection

- **Decision**: Ping the cluster at registration and on each health check to read the server version and features.
  - Store the edition (`community` | `enterprise`).
  - Hide Enterprise-only UI paths (Access Requests, SSO beyond Community Edition) and label them for Community Edition clusters.
  - Versions outside the supported range show a warning, and write actions are disabled for versions older than N-1.

## D14 — Deployment wizard output

- **Decision**: Render from typed templates using `text/template` with escaping helpers. Inputs are validated: domain against an RFC 1123 pattern, e-mail, and a version pattern `^\d+\.\d+\.\d+$`. The outputs are:
  - `teleport.yaml`, equivalent to `teleport configure --acme --acme-email --cluster-name`, or the bring-your-own-certificate variant;
  - `install.sh`, which runs `curl https://cdn.teleport.dev/install.sh | bash -s <version>`, then `teleport configure`, then `systemctl enable --now teleport`;
  - the `tangra-manager` role YAML and its `tctl` commands (create the role, `tctl users add tangra-mgmt --roles=tangra-manager`, `tctl auth sign …`);
  - the first-admin command `tctl users add <admin> --roles=editor,access,auditor --logins=…`;
  - a DNS/port/host-size checklist (2 vCPU / 1 GB minimum, A records for the domain and its wildcard, port 443 open to all sources).
  
  Prerequisite checks use the netguard dialler (D12). Nothing is executed remotely (spec assumption).

## Supply chain (Principle VI)

| Dependency | Purpose | Alternatives rejected | Status |
|---|---|---|---|
| `github.com/gravitational/teleport/api` | Typed Teleport gRPC client and types | tctl shell-out; hand-written gRPC from protos (version drift, larger maintenance) | Apache-2.0, actively maintained, tagged per Teleport release |
| YAML→JSON conversion | Role editing | Custom converter | Use `gopkg.in/yaml.v3` + `encoding/json` (already in the v4 stack). Add `sigs.k8s.io/yaml` only if the round-trip loses fidelity |

All other needs are met by modules already in the v4 stack (freya, pgx/v5, valkey-go, grpc, goose, testcontainers, kin-openapi, and the tangra SDKs for auth, portal, lcm, warden, notification, scheduler, inventory and asset).

## STRIDE threat model

| Threat | Scenario | Mitigation |
|---|---|---|
| **S**poofing | A caller forges a module identity to call `teleport.v1.Access` | SPIFFE mTLS with a deny-by-default `deploy/policy.yaml`; callers allow-listed by SVID |
| **S**poofing | A forged membership event triggers provisioning or de-provisioning | Events are only hints: re-verify with auth over mTLS before acting (SR-006) |
| **T**ampering | A role edit raises privileges | Administrator permission only (SR-005), diff preview, revision check, audit of before/after hashes |
| **T**ampering | A malicious cluster returns crafted data | Bounded responses (max gRPC message 4 MiB, 10 s timeouts), typed decoding, UI output encoding (SR-004) |
| **R**epudiation | An administrator denies changing roles or locks | Append-only audit with actor, tenant, cluster, target, outcome and correlation id (SR-007) |
| **I**nformation disclosure | Credential, token or invite leaks | warden references only; one-time response fields use a redacting secret type that never reaches logs; redaction scan in CI (SC-007) |
| **I**nformation disclosure | Cross-tenant read | RLS on every table plus a cluster-ownership check before any Teleport call (SR-001); negative tests |
| **I**nformation disclosure | SSRF through the proxy address or probes | netguard (D12) |
| **D**enial of service | Large audit searches, UI bursts hammering a cluster | Required time range, page caps, 15 s read cache, gateway rate limits, a per-cluster concurrency semaphore (4) |
| **E**levation of privilege | An operator changes roles or mappings | Separate permissions for roles and mappings (SR-005) |
| **E**levation of privilege | The module locks itself out or deletes preset roles | Self-identity guard (FR-013), preset protection (FR-011) |
