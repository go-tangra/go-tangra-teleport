---
title: "Example: register an existing cluster"
summary: From tctl on the cluster to a connected cluster in the portal - the tangra-manager role, the management user, the identity file, the Register cluster dialog and the same through the API.
kind: example
order: 10
tags: [teleport, example, clusters, tctl, identity, credential]
requires: clusters:manage
---
**Goal.** You run a Teleport cluster at `teleport.example.com` and want to
manage it from the portal.

**What you need.** A shell on a machine with `tctl` and administrator
rights on the cluster, and the `clusters:manage` permission in the portal.
Administrators, `owner` and `admin` have it.

## 1. Create the role on the cluster

Copy the YAML from [The tangra-manager role](../reference/tangra-manager-role.md)
into `tangra-manager-role.yaml`. Then create the role and check it:

```bash
tctl create -f tangra-manager-role.yaml
tctl get role/tangra-manager
```

`-f` (force) replaces a `tangra-manager` role that already exists, so the
same command also updates the role later.

## 2. Create the management user

```bash
tctl users add tangra-mgmt --roles=tangra-manager
```

`tctl` prints a sign-up link. You can ignore it: the platform signs in with
a certificate, not a password.

## 3. Export the identity file

```bash
tctl auth sign --user=tangra-mgmt --format=file --ttl=720h --out=tangra-mgmt.identity
```

- `--format=file` is the only credential format the platform accepts.
- `--ttl=720h` makes the identity valid for 30 days. Teleport may cap it
  at its own maximum. The portal warns 7 days before it expires, or at a
  quarter of its lifetime for short-lived identities, and again one day
  before.
- The file must be at most 64 KiB. A normal identity file is a few KiB.

Treat the file like a password. Do not mail it or commit it.

## 4. Register it in the portal

Open **Teleport → Clusters → Register cluster** and fill in:

| Field | Example | Notes |
|---|---|---|
| Name | `Production` | 1 to 64 characters, unique in your tenant |
| Proxy address | `teleport.example.com` | `host` or `host:port`; the port is 443 when you leave it out. Only the ports your operator allows can be used (443 and 3080 by default) |
| Identity file | `tangra-mgmt.identity` | uploaded, never shown again |

Choose **Register**. Before it saves anything, the platform checks that:

1. the address is allowed (it is not a loopback, link-local or metadata
   address, and not a private address unless your operator allowed that
   range);
2. the identity file can be read and has not expired;
3. the cluster answers with that identity;
4. the identity holds the read grants it needs. Missing grants do not stop
   the registration; they are listed on the cluster page.

If a check fails, nothing is stored and the dialog shows why:

| Message | Fix |
|---|---|
| Blocked target | Use the public proxy address, or ask your operator to allow the private range (`teleport.allowed_private_networks`) |
| Cluster unreachable | Check DNS, the firewall and that the proxy answers on that port |
| Credential invalid | Export the identity file again (step 3) and check the `--user` |
| Conflict | Another cluster in your tenant already has that name |
| Dependency unavailable | The secret store cannot store the identity yet. See [known limitations](../known-limitations.md) |

Then delete the local file:

```bash
shred -u tangra-mgmt.identity   # or: rm tangra-mgmt.identity
```

## 5. Check the result

The cluster page should show **Connected**, the Teleport version and
edition, the credential's expiry, and the number of users, roles and
resources. If **Missing permissions** lists entries such as `token:read`,
compare the role on the cluster with the reference and update it with
`tctl create -f tangra-manager-role.yaml`. The next check (within a
minute, or **Check now**) picks it up.

## The same through the API

With the `tget` and `tsend` helpers from the [HTTP API](../reference/api.md)
reference:

```bash
jq -n --rawfile id tangra-mgmt.identity \
  '{display_name: "Production", proxy_addr: "teleport.example.com", credential: $id}' |
  tsend -X POST "$API/clusters" --data-binary @-
```

A successful answer is `201` with the cluster. The credential is not in it:

```json
{
  "id": "018f3a2b-0000-7000-8000-000000000001",
  "display_name": "Production",
  "proxy_addr": "teleport.example.com:443",
  "cluster_name": "teleport.example.com",
  "edition": "community",
  "server_version": "19.1.2",
  "credential_kind": "identity_file",
  "credential_identity": "tangra-mgmt",
  "credential_expires_at": "2026-12-20T10:00:00Z",
  "status": "connected",
  "missing_permissions": [],
  "writes_blocked": false
}
```

The answer has more fields (counts, settings, timestamps); the excerpt
shows the ones to check. A failed check answers with its reason, for
example `422 {"reason":"blocked_target"}` or
`502 {"reason":"cluster_unreachable"}`.

## Rotate before it expires

Repeat step 3 on the cluster and upload the new file with **Rotate
credential** on the cluster page, or:

```bash
jq -n --rawfile id tangra-mgmt.identity '{credential: $id}' |
  tsend -X POST "$API/clusters/$CLUSTER/credential" --data-binary @-
```

The new identity must belong to the same Teleport cluster. If its check
fails, the old credential stays in place.
