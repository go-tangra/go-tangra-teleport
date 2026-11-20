# teleport — deployment notes

The **teleport** service manages self-hosted Teleport Community Edition
clusters for tangra tenants. Module id `teleport`; browser API under
`/api/teleport/v1` (gateway-proxied, platform token); mesh gRPC
`teleport.v1.Access` (inventory, asset and portal, read-only) and
`scheduler.v1.TaskExecutor` (the scheduler only) on the SPIFFE mTLS mesh.

## Server operations

| Item | Value |
|---|---|
| Binary | `teleportsvc -config deploy/container.yaml` (applies migrations, then serves); `teleportsvc bootstrap -config …` migrates and exits |
| Listeners | gRPC `server.grpc_addr` (:9925), HTTP `server.http_addr` (:9926) — mesh, mTLS; admin `admin.addr` (:9870, `/healthz`, `/readyz`, metrics) |
| Store | TimescaleDB, database `teleport`, app role `teleport_app` (NOBYPASSRLS); `db.migrate_dsn` for the migration role |
| Event bus | Valkey user `teleport`: streams `platform:events:<tenant>` (publishes `teleport.*`), leases `teleport:lease:*`, read cache `teleport:cache:*` |
| Credentials | warden references (`secrets.warden_service`); development `file:` references under `secrets.file_dir` |
| Mesh identity | enrols with lcm through the gateway edge (`mesh_enroll`), stores its SVID in `/state` |
| Gateway | registers its manifest (routes, permissions, abilities, nav, help digest) on a lease; registers the module roles and built-in grants with auth |
| Scheduler | `task_scheduler.enabled` registers the five `teleport:*` task types (see docs/help/operations.md) |
| Outbound | each managed cluster's proxy address (443 or 3080), through the netguard SSRF guard |

Policy (`deploy/policy.yaml`): the gateway forwards HTTP operations only;
inventory, asset and portal may call `teleport.v1.Access/{LookupHost,GetLinks}`
and the gRPC health check; the scheduler alone may call
`scheduler.v1.TaskExecutor/ExecuteTask` (the executor re-checks the verified
peer as well). The module itself needs auth's generic `svc/*` rules,
warden's secret reads, notification's send RPC and the scheduler's
registration RPC for `svc/teleport`.

## Development stack (`make compose-up`)

`deploy/compose.dev.yaml` is an overlay on the core stack in
`go-tangra/deploy/stack` (checked out next to this repository; override with
`CORE_STACK=<path>`). It is applied with the core compose file and project
name `freya-stack`, so the core stack's own files stay unchanged:

```sh
make image                         # go-tangra-teleport:dev from this checkout
make compose-up                    # the module (and what it needs) in freya-stack
make compose-up PROFILES=teleport-ce   # plus a Teleport CE test cluster
make compose-down                  # removes only the module's containers and volumes
```

### What the overlay adds to the core stack

| Core-stack change | How the overlay makes it | Permanent equivalent in go-tangra/deploy/stack |
|---|---|---|
| Database `teleport`, role `teleport_app` (NOBYPASSRLS) | one-shot `teleport-db-init` (idempotent) | a `teleport` block in `init-db.sql` |
| Valkey user `teleport` | one-shot `teleport-valkey-user` (`ACL SETUSER`, lost when valkey restarts) | `--user teleport on >dev ~* &* +@all` in the valkey command |
| Gateway allow-list `spiffe://example.org/svc/teleport=/api/teleport;teleport` | one-shot `teleport-gateway-allow` (gateway bootstrap, idempotent) | one more `-allow` in `gateway-bootstrap` |
| Join token `/tokens/teleport.token` | one-shot `teleport-token` (auth `mint-enrollment-token`) | a `teleport-token` service |
| Service `teleport` | image `${TELEPORT_IMAGE:-go-tangra-teleport:dev}`, `deploy/container.yaml` and `deploy/policy.yaml` from this checkout | a `teleport` service and `configs/teleport.yaml` |

The core stack has no scheduler service yet: the module still serves its
task executor and runs its leased health monitor, watchers, alert poller
and offline sweep itself, and the scheduler registrar retries in the
background. Notification, warden and auth are the core stack's.

### A Teleport CE test cluster

`PROFILES=teleport-ce` starts `teleport-ce` (single node, config
`deploy/teleport-ce.yaml`, proxy on `127.0.0.1:3080` for `tsh` and the
browser). Save the YAML block of `docs/help/reference/tangra-manager-role.md`
as `tangra-manager-role.yaml`, then create the management identity:

```sh
docker compose -p freya-stack cp tangra-manager-role.yaml teleport-ce:/var/lib/teleport/
docker compose -p freya-stack exec teleport-ce tctl create -f /var/lib/teleport/tangra-manager-role.yaml
docker compose -p freya-stack exec teleport-ce tctl users add tangra-mgmt --roles=tangra-manager
docker compose -p freya-stack exec teleport-ce tctl auth sign --user=tangra-mgmt --format=file --ttl=720h --out=/var/lib/teleport/tangra-mgmt.identity
docker compose -p freya-stack cp teleport-ce:/var/lib/teleport/tangra-mgmt.identity .
```

The module reaches the cluster at `teleport-ce:3080` on the stack network,
which is a private address: add the stack network's subnet to
`teleport.allowed_private_networks` in `deploy/container.yaml` for this
test (for example `["172.16.0.0/12"]`), then register the cluster with
proxy address `teleport-ce:3080` and the identity file.

## Join bundle (catalogue)

`tangra-module.yaml` and `deploy/bundle/` are the catalogue entry and join
bundle (spec 035): the gateway's add-module wizard renders `config.yaml` and
`policy.yaml` for its core and the operator runs `docker compose up -d`.
`cmd/teleportsvc/catalogue_test.go` proves the rendered files validate and
the policy admits exactly the expected peers. The bundle runs with
`env: dev` only because production refuses `file:` credential references
and warden has no write RPC for modules yet; every other production guard
(verified TLS to the database and Valkey, verified enrolment, no private
networks) is met.
