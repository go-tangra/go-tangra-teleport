# Quickstart validation (T125)

**Status: NOT VALIDATED LIVE.** The live run of `quickstart.md` against the
dev stack and a Teleport CE container has not been done: this workstation
has no usable Docker (the daemon socket refuses the user) and no
`@go-tangra` npm token. This file maps each scenario to the evidence that
exists today, so the live run only has to fill in the last column.

Legend for **Evidence**:

- **Automated (runs here)**: a test in the normal gate (`go test -race ./...`)
  that exercises the scenario with fakes; passing as of 2026-11-20.
- **Integration only**: an `integration`-tagged test against a real Teleport
  CE container or TimescaleDB (`make test-integration`); written, compiles
  (`go vet -tags integration`), skipped here without Docker. NOT RUN.
- **Not verifiable here**: needs the running stack, a second node, the
  browser or a cross-repo dependency.

| # | Scenario | Automated (runs here) | Integration only (NOT RUN) | Not verifiable here | Live result |
|---|---|---|---|---|---|
| 1 | Register; overview; `warden:` ref; credential never returned | `internal/clusters` TestRegisterVerifiesThenSaves, TestStatusTransitions; `tests/contract` TestClusterResponsesMatchSchemas, TestNoResponseCarriesCredentialMaterial; `tests/security` TestNoCredentialMaterialInAnyOutput; `make redaction-scan` | `tests/integration` TestClusterLifecycle | `credential_ref` starting with `warden:` in production: warden has no write RPC yet (registration answers `dependency_unavailable`; contract TestRegistrationWithoutWritableSecretStore) | pending |
| 1b | Stop Teleport → `unreachable`, event, notification within 5 min | `internal/clusters` TestMonitorChecksEveryTenant, TestStatusTransitions; `internal/tasks` TestHealthCheckTenantScopedIdempotent | TestClusterLifecycle (container stop, injected clock) | the real 5-minute wall-clock budget | pending |
| 1c | `169.254.169.254:443` → `422 blocked_target`, nothing stored | `tests/security` TestBlockedTargets; `internal/clusters` TestRegisterSavesNothingOnFailure; `internal/netguard` tests | — | — | pending |
| 2 | Create `alice`; invite once; roles in Teleport | `internal/users` TestCreateReturnsTheInviteOnce; `tests/contract` TestOneTimeFieldsOnlyInCreatingResponses | `tests/integration` TestIdentityLifecycle | `tctl get users/alice` by hand | pending |
| 2b | Stale revision → `409` | `internal/users` TestUpdateChecksTheRevision; `tests/contract` TestIdentityResponsesMatchSchemas | TestIdentityLifecycle | — | pending |
| 2c | Lock `alice` → `tsh login` fails within 30 s; listed and audited | `internal/locks` TestCreateLock | TestIdentityLifecycle (alice's own identity refused) | `tsh login` by a person | pending |
| 2d | Delete `editor`; lock `tangra-mgmt` → `403` | `internal/roles` TestDeleteGuards; `internal/locks` TestManagementIdentityCannotBeLocked | TestIdentityLifecycle | — | pending |
| 2e | Viewer → `403` on writes; reads work | `tests/security` TestViewerCannotChangeIdentity, TestViewerCannotWrite, TestOperatorCannotManageRoles | — | — | pending |
| 3 | Node token (TTL 5 min); node joins `online`; list without value | `internal/tokens` TestTokenReturnedOnceHashStored; `internal/resources` TestWatcherTracksServers; `tests/security` TestNoJoinTokenInAnyOutput | `tests/integration` TestEnrollLifecycle | running `install_command` on a host (the integration test joins with the config snippet) | pending |
| 3b | Revoke → second join rejected | `internal/tokens` TestRevokeDeletesInTeleport | TestEnrollLifecycle (token no longer listed by Teleport) | an actual second join attempt | pending |
| 3c | Inventory host → `auto` link; `LookupHost` from inventory SVID | `internal/resources` TestLinking; `tests/contract` TestAccessLookupAndLinks; `deploy` TestAccessOnlyFromInventoryAssetPortal | — | NEEDS CROSS-REPO: inventory/asset expose no host lookup, so automatic linking answers `dependency_unavailable` in production | pending |
| 4 | 5 failed logins, burst ≥ 3 / 5 min → one notification; filters | `internal/alerts` TestBurstRule, TestRulesScopeAndDeduplication; `internal/auditlog` TestSearchEvents | `tests/integration` TestFailedLoginBurstAlert | delivery through the real notification service | pending |
| 4b | Events without range or 60-day range → `422` | `internal/auditlog` TestSearchValidatesTheQuery; `tests/contract` TestAuditResponsesMatchSchemas | — | — | pending |
| 5 | Mapping → provision → role removed → lock → grace → delete; unmanaged untouched | `internal/provisioning` TestLeavingTheTenantLocks, TestGracePeriodDeletes, TestUnmanagedUsersAreNeverTouched, TestRoleChangeUpdatesRolesAndLogins; `internal/tasks` TestSyncProvisioningTenantScopedIdempotent, TestPurgeDeprovisioned | — | NEEDS CROSS-REPO: auth has no member listing with module roles; production provisioning answers `dependency_unavailable`; the scheduler is not in the core dev stack | pending |
| 6 | Draft for `tp.example.test`; artifacts; checks; private probes refused | `internal/deploy` TestDraftLifecycle, TestRenderGolden, TestRenderedArtifacts, TestChecksPass, TestChecksFail, TestPrivateTargetsRefused; `tests/contract` TestDeploymentResponsesMatchSchemas | — | `teleport configure`/start with the generated files on a real host | pending |
| 7 | Remove cluster → rows and secret gone; Teleport unchanged | `internal/clusters` TestRemoveDeletesSecretAndLeavesTeleport, TestRemoveKeepsRegistrationWhenSecretStoreIsDown | TestClusterLifecycle (removal step) | warden-side deletion (warden has no write/delete RPC for modules yet) | pending |
| 8 | Notification and scheduler stopped → management works; alerts/provisioning `dependency_unavailable`; watchers keep status | `internal/app` TestDegradedModeWithFakes | `tests/integration` TestDegradedMode | stopping the real services in the stack | pending |
| 9 | Tenant B → `GET /clusters/{A}/users` → `404` | `tests/security` TestCrossTenantClusterIsNotFound, TestCrossTenantIdentityIsNotFound; `internal/httpapi` TestPermissionEnforcement | `tests/integration` TestRowLevelSecurity (T018) | — | pending |

## Browser path

The UI flow register → users → lock → enroll → events is
`ui/e2e/teleport.spec.ts` (T122, Playwright). NOT RUN: it needs `make
ui-build` (npm token), the stack (`make compose-up PROFILES=teleport-ce`)
and `E2E_OPERATOR_PASSWORD`, `E2E_TELEPORT_PROXY`, `E2E_TELEPORT_IDENTITY`;
without them it skips.

## To complete T125

1. `make image && make compose-up PROFILES=teleport-ce` (deploy/README.md),
   accept the operator invite, create the `tangra-mgmt` identity in
   `teleport-ce`.
2. `make test-integration` (Docker) and record the result per row.
3. Walk each scenario above through the portal and the API; fill **Live
   result** with pass/fail, the date and the image digests.
4. Scenarios marked NEEDS CROSS-REPO stay `dependency_unavailable` until
   warden, auth and inventory/asset ship the missing RPCs.
