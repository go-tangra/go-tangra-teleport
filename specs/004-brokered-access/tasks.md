# Tasks: Teleport access through the portal sign-in

**Input**: [spec.md](spec.md), [plan.md](plan.md) (decisions R1–R13, contract table).
Tests are required (constitution IV): write each test before its code.

## Phase 1: Setup

- [X] T001 Promote `golang.org/x/crypto` to a direct dependency in go.mod (no version change) for `x/crypto/ssh` (already direct: go.mod lists `golang.org/x/crypto v0.57.0` in the main require block; no change)

## Phase 2: Foundational

- [X] T002 Add `AccessTerminal = "access:terminal"` and `AccessDownload = "access:download"` to internal/authz/authz.go (not in workerAllowed/moduleAllowed)
- [X] T003 Declare both permissions in pkg/teleportmanifest/manifest.go; operator grant gets `access:terminal`; administrator gets both via PermissionRefs; update manifest tests
- [X] T004 Declare the contract-table routes in api/openapi/teleport.yaml (`x-freya-permission`, output route `x-freya-timeout-seconds: 300`, schemas `MyAccess`, `AccessNode`, `AccessSettings`, `TerminalCreate`, `Terminal`); paths without `:`
- [X] T005 Migration internal/store/migrations/NNN_cluster_access_settings.sql (R4) and repo methods Get/Put in internal/repo (default 480 when absent)
- [ ] T006 Add to teleportapi.Client (internal/teleportapi/access.go + Fake in fake*.go): `IssueUserCerts(ctx, user string, ttl time.Duration) (UserCerts, error)` (generates an Ed25519/ECDSA key in memory, `GenerateUserCerts` with SSH+TLS public keys, returns key, SSH cert, TLS cert, expiry), `HostCAs(ctx)`, `UserCAs(ctx)` (TLS CA for the identity file), `DialNode(ctx, certs, node, login)` returning an `*ssh.Client` via `client/proxy` DialHost with host-key check against the host CA; map AccessDenied on impersonation to reason `management_role_outdated`
- [ ] T007 Management role: add the impersonate rule (R1) to internal/deploy/templates/tangra-manager-role.yaml.tmpl and its golden/test; document the same change for go-tangra-docker `configs/teleport/tangra-manager-role.yaml`

## Phase 3: US5 + US3 – issuance bounded to the caller's managed user, MFA required (P1)

- [ ] T008 [P] [US5] Tests internal/access/issuer_test.go: caller resolves only to their own managed user (tenant + tangra user labels, R2); not provisioned → ErrNotProvisioned; label mismatch → refused; impersonation denied → ErrRoleOutdated; amr without otp/hwk → ErrMFARequired; roles with require_session_mfa → ErrSessionMFARequired (R9); TTL clamp to settings
- [ ] T009 [US5] Implement internal/access/issuer.go, errors.go, settings.go; caller identity (tenant, user, amr) passed from httpapi (extend the subject built in internal/httpapi/middleware.go to carry AMR)
- [ ] T010 [US5] Audit rows (R12) for every issuance and refusal via audit.Recorder; test that no key/cert bytes reach audit or logs

## Phase 4: US2 – download access for tsh (P1)

- [ ] T011 [P] [US2] Tests internal/access/identity_test.go: identity file parses with `identityfile.Decode`, contains key, SSH cert, TLS cert, host and TLS CAs; expiry header matches the cert
- [ ] T012 [US2] Implement internal/access/identity.go and `POST /access/identity`, `GET /access`, `PUT /access/settings` in internal/httpapi/access.go (`Cache-Control: no-store`, attachment)
- [ ] T013 [US2] Contract tests tests/contract/access_test.go: 403 without permission, 403 mfa_required, 409 not_provisioned, 422 ttl out of range, 404 other tenant's cluster

## Phase 5: US1 – portal terminal (P1)

- [ ] T014 [P] [US1] Tests internal/terminal/hub_test.go: limits 5/user, 64/process (429); lookup of another user's terminal is not found; ring buffer resume from offset; stream closes at the max duration; reader-gone 30 s and keepalive 3 min and 8 h timeouts end the terminal (fake clock)
- [ ] T015 [US1] Implement internal/terminal/{hub,terminal}.go: SSH session with PTY (`xterm-256color`, cols/rows), output pump into ring + subscribers, input/resize, end reasons (R6); certificates dropped from memory on end
- [ ] T016 [US1] Implement internal/terminal/watchdog.go (R7): every 30 s check the managed user still exists, is owned, and is not locked; end otherwise; tests with Fake
- [ ] T017 [US1] Node listing internal/access/nodes.go (R10): impersonated short-lived client per user+cluster (cached 4 min), returns nodes + allowed logins
- [ ] T018 [US1] HTTP internal/httpapi/terminal.go: create, SSE output (event id = offset, `?from=`/Last-Event-ID, closes at 290 s), input (≤64 KiB base64), resize (1..1000), keepalive, delete; audit start/end
- [ ] T019 [US1] Contract tests in tests/contract/terminal_test.go: 403/404/422/429 and SSE resume
- [ ] T020 [US1] Wire services in cmd/ / server deps; graceful shutdown ends all terminals with reason `shutdown`

## Phase 6: US1/US2/US4 UI

- [ ] T021 [P] [US1] ui/src/stores/access.ts (API calls) and ui/src/pages/clusters/TerminalPage.vue: interactive xterm (reuse cspStyles from the player), SSE reconnect with offset, input/resize POSTs, keepalive every 60 s, DELETE on unmount; route `/teleport/clusters/:id/terminal` with `node` and `login` query
- [ ] T022 [P] [US2] ui/src/pages/clusters/MyAccessCard.vue on the cluster overview: my Teleport user, logins, "Download access for tsh" (permission-gated) with the command line and expiry; explains not-provisioned and MFA-required states
- [ ] T023 [US1] Resources tab: "Terminal" action with login picker on nodes the user can reach (permission-gated); administrators see access settings (TTL) on the cluster settings
- [ ] T024 [US1] UI unit tests (ui/tests/unit/terminal-page.spec.ts, my-access.spec.ts); icons only from ICONS (icons.spec.ts must pass)

## Phase 7: Integration and polish

- [ ] T025 Integration test tests/integration/access_test.go against Teleport 18: impersonation for a managed user works, for local admin is refused by Teleport; terminal runs `echo` and the session appears under the managed user; identity file works with the Teleport client library
- [ ] T026 docs/help/guides/portal-access.md (FR-020) incl. management-role change, MFA requirement, deferred fresh-MFA, single-replica limitation
- [ ] T027 `make test` / `go test ./...`, `go vet`, UI `npm run test` and `npm run build` green

## Dependencies

T001–T007 before all stories; Phase 3 before 4 and 5; T015 before T016/T018; UI after the HTTP routes; T025 after T018.
