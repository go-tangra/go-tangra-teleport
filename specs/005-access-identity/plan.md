# Implementation Plan: Access identity for brokered access

**Branch**: `005-access-identity` | **Date**: 2026-11-23 | **Spec**: [spec.md](spec.md)

## Summary

Brokered access (004) gets its own optional per-cluster credential: a
`tsh login` identity file of the Teleport user `tangra-access`, whose role
holds only the impersonate rule. The management identity (`tctl auth sign`,
`tangra-manager`) keeps doing everything else and loses the impersonate rule.

## Technical context

- Existing: `clusters.Service` (identity parsing, verification dial, secret
  store, pool, expiry evaluation and announcements), `access.Service`
  (Resolve → Issue), `teleportapi.Pool` keyed by cluster + credential ref.
- New storage: `cluster_access_identity` (one row per cluster: secret ref,
  Teleport user, issued/expires, updated_at/by), RLS like every table; the row
  cascades with the cluster, the secret is deleted by Remove/PurgeTenant.
- Secret name `teleport-access-<cluster id>` in the same `secrets.Store`.

## Decisions (research)

- **R1 Which calls use the access identity** — only `IssueUserCerts`
  (`GenerateUserCerts` with `Username`, plus the host CA reads it does). The
  user/lock/role reads, the auth-preference read, node listing and the SSH
  dial (both authenticate with the issued user certificates) stay on the
  management client. Measured on Teleport 18.11: a `tangra-access` sign-in
  identity whose role has only the impersonate rule issues certificates for a
  managed user and reads the host CA (implicit rules); it cannot read users
  or locks. So the role carries **no** read rules.
- **R2 Sign-in detection** — a `tctl auth sign` (or any impersonated)
  certificate carries the impersonator in the TLS subject (ASN.1
  `1.3.9999.2.7`) and the SSH extension `impersonator`; a sign-in one has
  neither (verified in the container). `teleportapi.ParseIdentity` reports
  `Impersonator`; upload refuses non-empty (422 `access_identity_not_sign_in`).
- **R3 Dry check** — when the cluster has an active managed user, issue
  1-minute certificates for it with the uploaded identity and drop them;
  Teleport refusing → 422 `access_identity_cannot_impersonate`. No managed
  user → skipped, the response says `impersonation_checked: false`.
- **R4 Separate pool** — `clusters.Service.AccessPool`, a second
  `teleportapi.Pool` with the same dial function (the key's credential ref is
  the access secret), invalidated on replace/remove/cluster removal.
- **R5 Fallback** — no row: issue with the management client; any Teleport
  refusal of the impersonation then answers `access_identity_missing`.
  Expired row (by its recorded expiry): `access_identity_expired`, no dial. A
  configured identity Teleport rejects (credential invalid or impersonation
  denied): `access_identity_invalid`. `management_role_outdated` and
  `management_identity_unsuitable` are retired.
- **R6 Alerts** — `CheckCredential` (task) and `CheckCluster` (monitor) also
  evaluate the access identity with `EvaluateExpiry` and the same thresholds;
  each stage is announced once (event `teleport.credential.expiring` with
  `credential: access_identity`, notification template
  `teleport.credential_expiring` with `credential` and `status_reason`
  variables) to the `credential_expiring` alert-rule recipients. The cluster
  status is not changed (it describes the management credential).
- **R7 Audit** — `teleport.access_identity.upload`, `.replace`, `.delete`
  (target `credential`), success and failure, never the identity.
- **R8 Lifetime** — measured on Teleport 18.11.10 (see Deviations D1).
- **R9 Permissions** — GET status `clusters:read` (like the management
  credential's identity/expiry on GET cluster); PUT/DELETE `clusters:manage`
  (like rotation).

## Contract

Under `/api/teleport/v1/clusters/{id}`:

| Route | Permission | Notes |
| --- | --- | --- |
| `GET /access-identity` | `clusters:read` | `{configured, teleport_user, issued_at, expires_at, state, updated_at, updated_by}`; state `ok`/`expiring`/`expired` (`missing` when not configured) |
| `PUT /access-identity` | `clusters:manage` | `{credential}` → status + `impersonation_checked`; 422 `credential_invalid`, `validation_failed`, `access_identity_not_sign_in`, `access_identity_cannot_impersonate`; 502; 503 secret store |
| `DELETE /access-identity` | `clusters:manage` | 204; 404 when none |

`GET /access` (my access) gains `access_identity` (`ok`/`expiring`/`expired`/`missing`).

## Project structure

```
internal/store/migrations/0006_cluster_access_identity.sql
internal/repo (AccessIdentity, AccessIdentityStore), memstore, repodb/access.go
internal/teleportapi/identity.go          Impersonator
internal/clusters/accessidentity.go       status, put, delete, AccessClient, expiry
internal/access/issuer.go, errors.go      issuance through the access identity
internal/httpapi/accessidentity.go, access.go
internal/audit/audit.go                   three actions
internal/deploy/templates/                manager role without impersonate; tangra-access.yaml
api/openapi/teleport.yaml
ui/src/pages/clusters/AccessIdentityCard.vue, MyAccessCard.vue, TerminalPage.vue
docs/help/reference/tangra-manager-role.md, tangra-access-role.md, guides/portal-access.md
tests/integration/access_identity_test.go
```

## Deviations

(filled in during implementation)
