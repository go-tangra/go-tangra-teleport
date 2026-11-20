---
title: HTTP API
summary: Call the Teleport module from scripts with curl - authentication, the CSRF header, every route under /api/teleport/v1 with its permission, request examples, error reasons and limits.
kind: reference
order: 75
tags: [teleport, api, curl, csrf, errors, reference]
requires: clusters:read
---
The portal itself uses this API, and you can call it from scripts. The
routes are under `/api/teleport/v1` on your portal address and go through
the gateway, which checks who you are before passing the request on. The
OpenAPI document is `api/openapi/teleport.yaml` in the module repository.

The examples use `https://portal.example.com` as the portal and
`018f3a2b-0000-7000-8000-000000000001` as a cluster id. Change both to your
own.

## Authentication and the CSRF header

The gateway accepts one of two credentials:

- **A bearer token**: `Authorization: Bearer <token>`. A request that has a
  bearer token and **no cookies at all** does not need the CSRF check.
- **Your browser session**: the `__Host-session` cookie. Every request that
  changes something (`POST`, `PUT`, `PATCH`, `DELETE`) must also send:
  - the `__Host-csrf` cookie and the same value in the `X-CSRF-Token` header;
  - an `Origin` header with the portal address.

  If any of these is missing or wrong, the gateway answers
  `403 {"reason":"csrf"}`.

A shell setup for the session variant, with the two cookie values copied
from the browser's developer tools:

```bash
PORTAL=https://portal.example.com
API=$PORTAL/api/teleport/v1
CLUSTER=018f3a2b-0000-7000-8000-000000000001
SESSION='<session-cookie>'
CSRF='<csrf-cookie>'

# Reads only need the session cookie.
tget() { curl -fsS -b "__Host-session=$SESSION" "$@"; }

# Changes need both cookies, the matching header and the Origin.
tsend() {
  curl -sS -b "__Host-session=$SESSION; __Host-csrf=$CSRF" \
    -H "X-CSRF-Token: $CSRF" -H "Origin: $PORTAL" \
    -H 'Content-Type: application/json' "$@"
}
```

With a bearer token, use `-H "Authorization: Bearer <token>"` in both
functions and leave out the cookies, the CSRF header and the Origin.

Every route needs the permission listed below. If you lack it, the answer
is `403 forbidden`. A cluster that belongs to another tenant answers
`404 not_found`.

## Request rules

- Request bodies are JSON. Unknown fields, invalid JSON and trailing data
  are refused with `400 malformed_body`. A body over 1 MiB is refused with
  `413 body_too_large`.
- Teleport names (users, roles, lock targets) are 1 to 128 characters. The
  first is a letter or digit, and the rest are letters, digits or
  `. _ @ + : -`.
- **Lists read from Teleport** (users, roles, resources, events, sessions)
  page with an opaque cursor. Each page carries a `next` value; send it back
  unchanged, with the same filters, to get the following page.
- **Lists the module keeps** (clusters, the module audit trail) follow the
  platform list contract: `page`, `page_size` (1 to 200), `sort` and
  `order` (`asc` or `desc`). The answer carries
  `{items, total, page, page_size, sort, order}`.
- **One-time values** appear only in the response that creates them: invite
  and reset links, join tokens, install commands and configuration snippets.
  They cannot be read again.
- No response ever contains an identity file, a private key or a Teleport
  stack trace.

## Routes

| Route | Permission |
|---|---|
| `GET /health` | none |
| `GET /stream` (server-sent events, `?last_id=`) | `clusters:read` |
| `GET /clusters`, `GET /clusters/{id}`, `POST /clusters/{id}/check` | `clusters:read` |
| `POST /clusters`, `PATCH /clusters/{id}`, `DELETE /clusters/{id}`, `POST /clusters/{id}/credential` | `clusters:manage` |
| `GET /clusters/{id}/users` (`?q=&next=&page_size=`) | `users:read` |
| `POST /clusters/{id}/users`, `PUT` and `DELETE /clusters/{id}/users/{name}`, `POST /clusters/{id}/users/{name}/reset` | `users:manage` |
| `GET /clusters/{id}/roles`, `GET /clusters/{id}/roles/{name}` | `roles:read` |
| `POST /clusters/{id}/roles:preview`, `PUT` and `DELETE /clusters/{id}/roles/{name}` | `roles:manage` |
| `GET /clusters/{id}/locks` | `locks:read` |
| `POST /clusters/{id}/locks`, `DELETE /clusters/{id}/locks/{name}` | `locks:manage` |
| `GET` and `POST /clusters/{id}/tokens`, `DELETE /clusters/{id}/tokens/{tid}` | `tokens:manage` |
| `GET /clusters/{id}/resources` (`?kind=&label=key=value&q=&status=&next=`) | `resources:read` |
| `POST /clusters/{id}/resources/{rid}/links`, `DELETE /clusters/{id}/resources/{rid}/links/{lid}` | `resources:link` |
| `GET /clusters/{id}/events`, `GET /clusters/{id}/sessions`, `GET /audit` | `audit:read` |
| `GET /alert-rules` | `alerts:read` |
| `POST /alert-rules`, `PUT` and `DELETE /alert-rules/{id}` | `alerts:manage` |
| `GET /clusters/{id}/mappings`, `GET /clusters/{id}/managed-users` | `users:read` |
| `POST /clusters/{id}/mappings`, `PUT` and `DELETE /clusters/{id}/mappings/{mid}`, `POST /clusters/{id}/managed-users`, `POST /clusters/{id}/provisioning:sync` | `provisioning:manage` |
| `GET` and `POST /deployments`, `GET`, `PUT` and `DELETE /deployments/{id}`, `GET /deployments/{id}/artifacts/{name}`, `POST /deployments/{id}/checks` | `deployments:manage` |

## Examples

### Clusters

```bash
# List clusters, worst status first.
tget "$API/clusters?sort=status&order=desc&page_size=50"

# Register a cluster. The identity file goes in as a JSON string.
jq -n --rawfile id tangra-mgmt.identity \
  '{display_name: "Production", proxy_addr: "teleport.example.com:443", credential: $id}' |
  tsend -X POST "$API/clusters" --data-binary @-

# Rotate the credential.
jq -n --rawfile id tangra-mgmt.identity '{credential: $id}' |
  tsend -X POST "$API/clusters/$CLUSTER/credential" --data-binary @-

# Check the cluster now, then change its settings.
tsend -X POST "$API/clusters/$CLUSTER/check"
tsend -X PATCH "$API/clusters/$CLUSTER" \
  -d '{"settings": {"offline_threshold_minutes": 30, "alerts_enabled": true}}'
```

`offline_threshold_minutes` is 5 to 1440. A `PATCH` needs at least one
field.

### Users, roles and locks

```bash
# Create a user. The answer holds the one-time invite_url.
tsend -X POST "$API/clusters/$CLUSTER/users" \
  -d '{"name": "alice", "roles": ["access"], "logins": ["ubuntu"]}'

# Change roles. Send the revision from the last read.
tsend -X PUT "$API/clusters/$CLUSTER/users/alice" \
  -d '{"roles": ["access", "auditor"], "logins": ["ubuntu"], "revision": "<revision>"}'

# Preview a role change, then apply it with the same revision.
jq -n --rawfile y support.yaml '{yaml: $y, revision: "<revision>"}' |
  tsend -X POST "$API/clusters/$CLUSTER/roles:preview" --data-binary @-
jq -n --rawfile y support.yaml '{yaml: $y, revision: "<revision>"}' |
  tsend -X PUT "$API/clusters/$CLUSTER/roles/support" --data-binary @-

# Lock a user for two hours.
tsend -X POST "$API/clusters/$CLUSTER/locks" -d '{
  "target_kind": "user", "target": "alice",
  "reason": "INC-1234: suspected credential leak",
  "expires_at": "2026-11-20T16:00:00Z"}'
```

The worked examples have more:
[users and roles](../examples/users-and-roles.md),
[locks](../examples/incident-response.md).

### Tokens, resources and links

```bash
# A join token for a server, valid for 60 minutes (1 to 1440, default 30).
tsend -X POST "$API/clusters/$CLUSTER/tokens" -d '{"resource_type": "node", "ttl_minutes": 60}'

# Offline databases labelled env=production.
tget "$API/clusters/$CLUSTER/resources?kind=db&status=offline&label=env=production"

# Link a resource to an inventory record by hand.
tsend -X POST "$API/clusters/$CLUSTER/resources/<rid>/links" \
  -d '{"target_module": "inventory", "target_id": "<inventory-host-id>"}'
```

`resource_type` and `kind` are `node`, `app`, `db`, `kube` or `desktop`.

### Audit, alerts, provisioning and deployments

The [audit and alerts example](../examples/audit-and-alerts.md),
the [provisioning example](../examples/provisioning-mappings.md) and the
[deployment example](../examples/deploy-wizard.md) show these routes with
complete bodies.

## Errors

Every refusal is JSON with a stable `reason`, sometimes a `message` and a
`detail` object. The `detail` never contains a secret.

```json
{"reason": "validation_failed", "detail": {"field": "proxy_addr", "message": "..."}}
```

| Status | `reason` | Typical cause |
|---|---|---|
| 400 | `malformed_body` | Invalid JSON, an unknown field or trailing data |
| 400 | `bad_request` | A request the route cannot read |
| 401 | `unauthenticated` | No valid session or token |
| 403 | `csrf` | Sent by the gateway: a change without a matching `X-CSRF-Token` and `__Host-csrf` cookie, or without an allowed `Origin` |
| 403 | `forbidden` | The permission is missing, or a safety guard refused the change; `detail.guard` is `self_identity`, `management_role` or `preset_role` |
| 404 | `not_found` | No such cluster, user, role, lock, token, link, rule or draft in your tenant |
| 409 | `conflict` | A duplicate name, or the user, role or mapping changed since you read it (a stale `revision`) |
| 413 | `body_too_large` | A body over its limit |
| 422 | `validation_failed` | Invalid input; `detail.field` or `detail.param` names it, `detail.message` explains |
| 422 | `blocked_target` | The proxy address resolves to a loopback, link-local, metadata or private address that is not allowed |
| 422 | `credential_invalid` | The identity file is malformed, expired, rejected, or belongs to another cluster |
| 422 | `unsupported_version` | The cluster runs a Teleport version that is too old, so changes are blocked |
| 422 | `enterprise_only` | The feature needs Teleport Enterprise |
| 422 | `teleport_rejected` | Teleport refused the change; for roles `detail.message` is Teleport's first line |
| 429 | `rate_limited` | Deployment checks were run again within 10 seconds |
| 501 | `not_implemented` | The route is not available in this build |
| 502 | `cluster_unreachable` | The Teleport cluster did not answer |
| 503 | `dependency_unavailable` | A platform service the request needs is missing; `detail.dependency` is `secret_store`, `auth` or `notification` |
| 503 | `temporarily_unavailable` | Any other server-side failure; retry later |

For example, while production cannot store credentials, registering a
cluster answers:

```json
{"reason": "dependency_unavailable",
 "detail": {"dependency": "secret_store",
            "message": "the secret store cannot store Teleport credentials yet (warden write support is pending)"}}
```

See [known limitations](../known-limitations.md).

## Limits

| Limit | Value |
|---|---|
| Request body | 1 MiB |
| Identity file, role YAML | 64 KiB each |
| `page_size` | 1 to 200 |
| Event and session search window | at most 31 days; `limit` 1 to 200 |
| Raw audit event | 16 KiB (larger events are truncated) |
| Join token validity | 1 to 1440 minutes (default 30) |
| Roles and logins per user | 32 each |
| Alert rule | 1 to 32 event types, 1 to 50 recipient users |
| Role mapping | 1 to 16 Teleport roles, up to 32 logins |
| Deployment checks | once every 10 seconds per draft |
