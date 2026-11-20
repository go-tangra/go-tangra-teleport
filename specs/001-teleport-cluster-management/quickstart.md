# Quickstart & Validation: Teleport Cluster Management Module

This guide proves the feature end to end. Endpoints and payloads are described in [contracts/http-api.md](./contracts/http-api.md), and tables in [data-model.md](./data-model.md).

## Prerequisites

- A tangra v4 development stack (gateway, auth, lcm, warden, notification, scheduler, Valkey, TimescaleDB), brought up as for other v4 modules: `make compose-up` in this repo, which adds the `teleport` service to the core stack.
- A **Teleport Community Edition test cluster**:
  - **Automated tests**: `tests/integration` starts the official Teleport container image (pinned by digest) with testcontainers in single-node mode, reachable on `localhost` through the dev-only `allowed_private_networks: [127.0.0.0/8]` opt-out.
  - **Manual runs**: use the deployment wizard (scenario 6) on a disposable VM.
- On the cluster, create the management identity:

  ```bash
  tctl create -f tangra-manager-role.yaml        # from the wizard or docs/help/reference
  tctl users add tangra-mgmt --roles=tangra-manager
  tctl auth sign --user=tangra-mgmt --format=file --ttl=720h --out=tangra-mgmt.identity
  ```

## Build and test gates

```bash
make generate          # buf + openapi types
make lint vuln         # vet, staticcheck, gosec, govulncheck
make test              # unit + contract (race), fakes for Teleport/warden/notification
make test-integration  # testcontainers: Postgres, Valkey, Teleport CE
make cover             # ≥ 80% overall, 100% for authz/, netguard/, secrets/
make redaction-scan    # SC-007: no credentials/tokens/invite URLs in logs, events, audit
make ui-build e2e      # Playwright against the federated UI
```

## Scenarios

| # | Story | Steps | Expected |
|---|---|---|---|
| 1 | US1 | Register the cluster: `POST /clusters` with `proxy_addr` and the identity file contents. Open the overview | `connected`; cluster name, version, `edition=community`, counts; `credential_ref` starts with `warden:` in the database, and the credential is absent from every response |
| 1b | US1 | Stop the Teleport container; wait | Within 5 minutes: `unreachable`, a `teleport.cluster.status_changed` event, a notification |
| 1c | US1 | Register with `proxy_addr=169.254.169.254:443` | `422 blocked_target`; nothing stored |
| 2 | US2 | Create user `alice` (`access`, `ubuntu`) | `invite_url` returned once; `tctl get users/alice` shows the roles |
| 2b | US2 | Edit role `access` with a stale revision | `409 conflict` |
| 2c | US2 | Lock `alice` with a reason | Within 30 seconds `tsh login` as alice fails; the lock is listed and audited |
| 2d | US2 | Delete role `editor`; lock `tangra-mgmt` | Both refused (`403`) |
| 2e | US2 | Repeat 2 as a viewer-role user | `403` on every write; reads work |
| 3 | US3 | Create a node token (TTL 5 min); run `install_command` in a test container | The node appears `online` with its labels; the token list shows metadata without the value |
| 3b | US3 | Revoke the token, then try to join a second node | The join is rejected |
| 3c | US3 | Add an inventory host with the same hostname | The resource shows an `auto` link; `teleport.v1.Access/LookupHost` from the inventory SVID returns the host |
| 4 | US4 | Make a failed login 5 times, with a burst rule of ≥ 3 in 5 minutes | One notification within 5 minutes; the events view filters by user and type |
| 4b | US4 | `GET /clusters/{id}/events` without `from`/`to`, or with a 60-day range | `422 validation_failed` |
| 5 | US5 | Map tangra `operator` → Teleport `access`; provision a tangra user; remove the user's tangra role | Teleport user created with `tangra.io/managed`; after a sync (≤ 15 minutes) a lock exists; after the grace period (set to 1 minute in tests) the user is deleted. An unmanaged Teleport user is untouched |
| 6 | US6 | Create a deployment draft for `tp.example.test`; download the artifacts; run checks | Valid `teleport.yaml`, version-pinned `install.sh`, role YAML; checks report per-item results; probes to private addresses are refused unless allowed |
| 7 | Platform | Remove the cluster; check the database and warden | Registration, links and mappings gone; the warden secret deleted; Teleport still running and unchanged |
| 8 | Platform | Stop the notification and scheduler services | Cluster management keeps working; alerts and provisioning report `dependency_unavailable`; the watchers keep updating status |
| 9 | Security | Tenant B calls `GET /clusters/{tenantA-id}/users` | `404 not_found` (RLS plus ownership check) |
