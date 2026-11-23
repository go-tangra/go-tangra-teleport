# Implementation Plan: Teleport access through the portal sign-in

**Branch**: `004-brokered-access` | **Date**: 2026-11-23 | **Spec**: [spec.md](spec.md)

## Summary

A provisioned portal user gets Teleport SSH access without a Teleport login.
The module's management identity asks Teleport for short-lived certificates
**as the user's provisioned Teleport user** (Teleport impersonation,
`GenerateUserCerts` with `Username` = the managed user). Teleport allows that
only for users labelled `tangra.io/managed=true` (impersonate rule with a
`where` clause in the management role). The certificates are used two ways:

1. **Portal terminal**: the module dials the node through the cluster proxy
   with the user's certificates and runs an interactive SSH session; the
   browser receives output over SSE and sends input/resize over POST. Teleport
   records the session under the user's own name.
2. **Download**: an identity file (`tsh -i`) with the same certificates.

Access is issued only when the portal session used MFA (`amr` contains `otp`
or `hwk`). Nothing issued is stored.

## Technical context

- Go 1.26, existing layering: `teleportapi` (client wrapper + Fake),
  `clusters.Service.Client` (tenant check + pooled client), `httpapi`
  (OpenAPI-declared routes with `x-freya-permission`), `audit.Recorder`,
  `provisioning` (managed users, `owned()` label check), `users.Label*`.
- Caller identity: `authclient.Identity` already carries `AMR` and
  `ExpiresAt` (auth SDK v4.1.0); the module reads it in `httpapi/middleware.go`.
- Teleport API (pinned): `Client.GenerateUserCerts(ctx, proto.UserCertsRequest{
  PublicKey/SSHPublicKey+TLSPublicKey, Username, Expires, RouteToCluster,
  Format})`; `client/proxy.NewClient` + `DialHost(ctx, "node:0", cluster,
  keyring)`; `golang.org/x/crypto/ssh` for the session (already an indirect
  dependency); `api/identityfile.Encode` for the download; host CA from
  `GetCertAuthorities(types.HostCA)` for host-key checking and identity CAs.
- Gateway: WebSocket upgrades are refused (`501 not_implemented`); SSE works
  (`/api/teleport/v1/stream`); maximum route timeout 300 s.
- UI: Vue 3 + `@go-tangra/ui` (fixed `ICONS` set, enforced by
  `ui/tests/unit/icons.spec.ts`); `@xterm/xterm` 5.5.0 already pinned.
- Storage: one migration adding per-cluster access settings.
- Deployment: one module process (production runs one). Terminals live in
  process memory; with several replicas the gateway would need sticky routing
  (documented limitation).

## Constitution check

| Principle | How this plan complies |
| --- | --- |
| I. Secure by default | Two new permissions; download for administrators only; MFA session required; short lifetimes |
| II. Zero trust | Teleport itself bounds impersonation to managed users; the module additionally checks tenant and user labels (`owned`) before every issuance; host keys verified against the cluster host CA |
| III. Boundary validation | node, login, cols/rows, TTL, input size all validated; terminal ids random 128-bit and bound to tenant+user |
| IV. Test-first | Unit tests (issuer, terminal hub, watchdog, settings), contract tests (403/404/409/422/429), Fake-backed service tests, Teleport 18 integration test (impersonation refused for local admin, terminal echo, identity file works) |
| V. Observability & audit | Audit rows for every issuance, terminal start and end, and refusal; never key material or terminal content |
| VI. Supply chain | No new dependency (`x/crypto/ssh` promoted from indirect) |
| VII. Simplicity | No gateway change (SSE + POST); in-memory terminals; no credential storage |

Result: pass, with the deviations listed below.

## Decisions (research)

- **R1 Impersonation** — `GenerateUserCerts` as the management identity with
  `Username` = managed user. Management role gains
  `allow.impersonate: {users: ['*'], roles: ['*'], where:
  'equals(impersonate_user.metadata.labels["tangra.io/managed"], "true")'}`.
  Local users (admin) and anything not provisioned are refused by Teleport.
  Tenant + `tangra.io/user` labels are checked by the module (Teleport's role
  is per cluster and does not know the tenant). *Alternative*: a Machine ID
  bot per user — rejected (heavy, no Community UI).
- **R2 Which user** — the caller's managed user on that cluster is looked up
  from the provisioning repo (tenant, tangra user id); the request never names
  a Teleport user. Not provisioned → 409 `not_provisioned`.
- **R3 MFA** — issue only if `amr` contains `otp` or `hwk`; otherwise 403
  `mfa_required`. **FR-013 (fresh confirmation) is deferred**: the auth
  service has no step-up proof the module can verify (its step-up is internal
  to key removal). Needs an auth change (e.g. a short-lived step-up token with
  `auth_time`); the cluster setting is not added until then.
- **R4 Lifetime** — per-cluster `access_ttl_minutes` (default 480, 15–720) in
  a new `cluster_access_settings` table; Teleport may cap further (role
  `max_session_ttl`, impersonator certificate expiry) — the expiry shown is
  what the certificate says.
- **R5 Terminal transport** — `POST /terminals` creates; `GET
  /terminals/{tid}/output` is SSE with event id = byte offset; the module
  keeps the last 256 KiB of output for resume and closes each stream at 290 s
  (client reconnects with `Last-Event-ID`/`?from=`). `POST .../input`
  (≤ 64 KiB, base64), `POST .../resize`, `POST .../keepalive`, `DELETE`.
- **R6 Terminal end** — closed by user (DELETE), no output reader for 30 s
  (page closed), no authenticated keepalive for 3 min (portal session ended),
  8 h maximum, certificate expiry, SSH exit, or watchdog revocation.
- **R7 Revocation** — watchdog every 30 s per terminal: managed user still
  exists and is owned, no lock targets it; else end. Teleport locks also end
  sessions natively.
- **R8 Limits** — 5 terminals per user, 64 per process (429 `too_many`).
- **R9 Per-session MFA roles** — if any of the user's roles has
  `require_session_mfa` (or cluster auth preference requires it), refuse with
  422 `session_mfa_required` (FR-014).
- **R10 Node list** — nodes are listed with a short-lived (5 min, cached per
  user+cluster for 4 min) impersonated client, so Teleport's own RBAC decides
  what the user sees; logins come from the user's Teleport traits/roles.
- **R11 Download** — `POST /access/identity` returns `text/plain` identity
  file (`Content-Disposition: attachment`, `Cache-Control: no-store`) plus
  headers `X-Teleport-Expires`, and the UI shows
  `tsh -i <file> --proxy=<proxy_addr> ssh <login>@<node>`.
- **R12 Audit kinds** — `teleport.access.issued` (download),
  `teleport.terminal.started`, `teleport.terminal.ended` (with reason and
  duration), failures as the same kind with outcome failure. Deviation from
  FR-016 wording: a terminal session produces a start and an end row (the
  audit trail is append-only).
- **R13 Permissions** — `access:terminal` (administrator + operator),
  `access:download` (administrator). Not granted to worker/module subjects.

### Deviations from the spec

- FR-013 deferred (R3). FR-018 tenant bound is enforced by the module, not by
  Teleport (R1). FR-016 is two rows per terminal (R12).

### Deviations found during implementation (Teleport 18.11 behaviour)

- **D1 Management identity must come from a sign-in.** Every `tctl auth
  sign` identity is itself an impersonated certificate, and Teleport refuses
  impersonation from one ("impersonated user can not impersonate anyone
  else"); renewing it for itself keeps the impersonator. Brokered access
  therefore needs a management identity obtained by signing in as
  `tangra-mgmt` (`tsh login --user=tangra-mgmt --out=tangra-mgmt.identity
  --format=file`, password and second factor once; its lifetime is bounded
  by the role's `max_session_ttl`). The other features keep working with a
  `tctl auth sign` identity. A refusal for this reason answers 422
  `management_identity_unsuitable` (distinct from
  `management_role_outdated`); the integration test signs in through the
  proxy's web login (password + TOTP) to get one.
- **D2 Host CA.** The CAs `GenerateUserCerts` returns are the user CA, not
  the host CA. The host CA is read with `GetClusterCACert` (TLS) and
  `GetCertAuthorities(HostCA, false)` (SSH; allowed by Teleport's implicit
  rules, no role change) on every issuance; the proxy TLS and the node host
  certificates are verified against it.
- **D3 Lifetime.** The impersonated certificate is not capped by the
  impersonator's expiry (an 8 h request from a 2 h management identity got
  8 h); Teleport still applies the user's roles' `max_session_ttl`. The
  expiry shown is the certificate's (unchanged plan behaviour).
- **D4 Impersonate rule.** `users: ['*'], roles: ['*']` with the `where`
  clause on `impersonate_user.metadata.labels` is accepted as planned; a
  local user (the cluster administrator) is refused by Teleport.
- **D5 Node listing cache.** Instead of caching an impersonated client for
  4 min, each listing issues 5-minute certificates (never leaving the
  module, not audited as an issuance) and the result — not the
  certificates — is cached per tenant, user and cluster for 60 s. Listing
  requires an MFA session (it issues certificates).
- **D6 Extra refusals.** `user_locked` (409), `terminal_ended` (409),
  `too_many` (429) and `management_identity_unsuitable` (422, D1) join the
  reasons; a login the certificates do not carry is 422 `validation_failed`
  (field `login`) before any SSH connection.
- **D7 GET access** issues nothing and does not require MFA; it returns an
  `mfa` flag so the UI can explain. Settings are shown there (no separate
  GET settings route); an administrator who is not provisioned sees the
  lifetime field without its current value.
- **D8 Audit.** `teleport.access.issued` (download), `teleport.terminal.started`
  and `teleport.terminal.ended` (`end_reason`, `duration_s`) target the
  managed user; refusals are the same action with outcome failure (the
  finer `label_mismatch` reason is audit-only, the API says
  `not_provisioned`). Route-permission refusals happen in the HTTP
  middleware before the handler; a hook (`Server.OnDenied`) audits them for
  the two issuing routes (identity download, terminal create) as
  `forbidden` failures. Permission refusals of the read routes (my access,
  nodes, terminal input/output) are answered 403 and not audited.
- **D9 Keys.** User keys are ECDSA P-256 (generated in memory per issuance);
  clusters restricted to the legacy RSA-only signature suite would refuse
  them.
- **D10 Watchdog.** It re-runs the full resolution (permission, cluster,
  managed-user row, labels, lock) every 30 s and ends a terminal only on a
  definitive refusal (forbidden, not found, not provisioned, locked); a
  transient failure (cluster unreachable) keeps it. A permission removed in
  the platform ends terminals within 30 s.
- **D11 Self renewal.** The management user asking for its own
  certificates is a renewal, not an impersonation; the module never asks
  for it (it is not a managed user).

## Data model

- `cluster_access_settings(cluster_id PK → clusters, tenant_id,
  access_ttl_minutes int not null default 480 check 15..720, updated_at,
  updated_by)`.
- In memory: `Terminal{id, tenant, user, cluster, teleportUser, node, login,
  started, lastKeepalive, ring(256 KiB), offset, ssh session}`.
- Nothing else; certificates and keys live only in memory for the request or
  the terminal.

## Contract

All under `/api/teleport/v1/clusters/{id}`:

| Route | Permission | Notes |
| --- | --- | --- |
| `GET /access` | `access:terminal` | my identity: `{teleport_user, logins, roles, expires_max, can_download, settings}`; 409 not provisioned |
| `GET /access/nodes` | `access:terminal` | nodes the user may reach (Teleport RBAC) |
| `POST /access/identity` | `access:download` | body `{ttl_minutes?}` → identity file |
| `PUT /access/settings` | `clusters:manage` | `{access_ttl_minutes}` 422 out of range |
| `POST /terminals` | `access:terminal` | `{node, login, cols, rows}` → `{terminal_id, expires_at}` |
| `GET /terminals/{tid}/output` | `access:terminal` | SSE, timeout 300 |
| `POST /terminals/{tid}/input` | `access:terminal` | `{data}` base64 ≤ 64 KiB |
| `POST /terminals/{tid}/resize` | `access:terminal` | `{cols, rows}` 1..1000 |
| `POST /terminals/{tid}/keepalive` | `access:terminal` | 204 |
| `DELETE /terminals/{tid}` | `access:terminal` | 204 |

Errors: 403 `forbidden`/`mfa_required`, 404 unknown cluster/terminal (other
user's terminal is 404), 409 `not_provisioned`, 422 validation /
`session_mfa_required` / `management_role_outdated` (impersonation denied),
429 `too_many`, 502 cluster unreachable. (Path segments contain no `:` —
gateway schema, `TestRoutePathsMatchGatewaySchema`.)

## Project structure

```
internal/access/            issuer.go (R1–R4, R9), nodes.go (R10), identity.go (R11),
                            settings.go, errors.go, *_test.go
internal/terminal/          hub.go (limits, lookup), terminal.go (ssh, ring, SSE),
                            watchdog.go, *_test.go
internal/teleportapi/       access.go (GenerateUserCerts, host CA, DialHost) + Fake
internal/httpapi/access.go, terminal.go
internal/store/migrations/  NNN_cluster_access_settings.sql
internal/authz/authz.go     AccessTerminal, AccessDownload
pkg/teleportmanifest/       permissions + operator grant
internal/deploy/templates/tangra-manager-role.yaml.tmpl  impersonate rule
api/openapi/teleport.yaml   routes above
ui/src/pages/clusters/      MyAccessCard.vue, TerminalPage.vue; Resources tab "Terminal" action
ui/src/stores/access.ts
tests/contract/access_test.go, tests/integration/access_test.go
docs/help/guides/portal-access.md
```

## Quickstart (validation)

1. Update the management role (re-run the bootstrap) so it can impersonate
   managed users.
2. Map a portal group to a role with login `root`, run provisioning; sign in
   to the portal **with MFA** as a member holding `access:terminal`.
3. Cluster → Resources → node → **Terminal** → `root`: a shell opens; run
   `id`; close the tab; Sessions shows the session under the member's
   Teleport user and it plays back.
4. **Download access for tsh**, run `tsh -i <file> --proxy=<addr> ls` and
   `ssh root@<node>`.
5. Negative: sign in without MFA → refused; remove the member from the group
   → open terminal ends within a minute; attempt as a user without a mapping
   → not offered.
