# Tasks: Access identity for brokered access

**Input**: [spec.md](spec.md), [plan.md](plan.md) (decisions R1–R9, contract table).
Tests are required (constitution IV): write each test before its code.

## Phase 1: Research

- [X] T001 Measure on Teleport 18 in the integration container: impersonator markers of a `tctl auth sign` vs a sign-in identity; what a `tangra-access` role with only the impersonate rule can do; the `tsh login --ttl` ceiling and the exact `tsh login` flags (plan R1, R2, D1)

## Phase 2: Foundational

- [X] T002 [P] Test + implement `Impersonator` in internal/teleportapi/identity.go (TLS subject `1.3.9999.2.7`, SSH extension `impersonator`); identitytest `Options.Impersonator`
- [X] T003 [P] Conformance test (internal/repotest) + migration `0006_cluster_access_identity.sql`, repo.AccessIdentityStore, memstore and repodb
- [X] T004 Audit actions `teleport.access_identity.{upload,replace,delete}`; event `teleport.credential.expiring` gains `kind`
- [X] T005 Fake: `AccessIssuer()` (same cluster through the access identity, `AccessImpersonationDenied`); clusterstest `AccessPool`, `AccessIdentity()`

## Phase 3: US1 – configure the access identity (P1)

- [X] T006 [US1] Tests internal/clusters/accessidentity_test.go: verify-then-store, replace, remove, refusals (not sign-in, other cluster, expired, empty, cannot impersonate, secret store down), no managed user, cluster removal and tenant purge
- [X] T007 [US1] Implement internal/clusters/accessidentity.go (status, put, delete, AccessClient) and the separate pool in internal/app
- [ ] T008 [US1] OpenAPI routes `GET/PUT/DELETE /clusters/{id}/access-identity` (no `:`), handlers in internal/httpapi/accessidentity.go, contract tests

## Phase 4: US2 – brokered access uses it (P1)

- [ ] T009 [US2] Tests internal/access: issuance through the access identity; fallback to the management identity; `access_identity_missing`, `access_identity_expired`, `access_identity_invalid`; open terminals unaffected
- [ ] T010 [US2] Implement in internal/access/issuer.go and errors.go; retire `management_role_outdated` / `management_identity_unsuitable`; `access_identity` in GET access; httpapi messages; OpenAPI reasons

## Phase 5: US3 – expiry alerts (P2)

- [X] T011 [US3] Announce access identity expiry stages from CheckCredential and CheckCluster (test in accessidentity_test.go)

## Phase 6: Teleport side

- [ ] T012 Remove the impersonate rule from internal/deploy/templates/tangra-manager-role.yaml.tmpl, goldens and docs/help/reference/tangra-manager-role.md; add `tangra-access-role.yaml` artifact (role, `max_session_ttl`), setup-commands step and docs/help/reference/tangra-access-role.md; render tests

## Phase 7: UI

- [ ] T013 `AccessIdentityCard.vue` on the cluster page (status, expiry, upload/replace/remove, the `tsh login` command); store calls; unit test
- [ ] T014 MyAccessCard and TerminalPage explain `access_identity_missing` / `access_identity_expired`; reasons in ui/src/api/client.ts; icons from ICONS only

## Phase 8: Integration and polish

- [ ] T015 tests/integration/access_identity_test.go (Teleport 18): management identity can no longer impersonate; a `tsh login` identity of tangra-access can; upload refuses a `tctl auth sign` identity; terminal end-to-end with the access identity
- [ ] T016 Docs: guides/portal-access.md (bootstrap for an existing cluster), api.md, known-limitations; plan Deviations
- [ ] T017 CI gates: gofmt, vet, staticcheck, gosec, `go test -race`, coverage, integration, UI lint/test/build
