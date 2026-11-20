---
title: Get started
summary: Create the tangra-manager role and user on your cluster, export an identity file, register the cluster and read its health.
kind: guide
order: 10
tags: [teleport, getting-started, clusters, credential, identity]
requires: clusters:manage
---
This walk-through connects one Teleport cluster. For the same steps with
sample values and the API calls, see
[the registration example](examples/register-cluster.md). You need `clusters:manage`;
the *Teleport administrator* role and the built-in `owner` and `admin` roles
have it. On the cluster you need `tctl` with administrator rights.

## 1. Create the management identity

1. Save the role from [The tangra-manager role](reference/tangra-manager-role.md)
   as `tangra-manager-role.yaml` and create it:

   ```bash
   tctl create -f tangra-manager-role.yaml
   ```

2. Create the user the platform signs in as:

   ```bash
   tctl users add tangra-mgmt --roles=tangra-manager
   ```

   You do not need to finish the sign-up link: the platform uses a
   certificate, not a password.

3. Export its identity file. The TTL is how long the credential lasts; the
   platform warns 7 days before it expires (or at a quarter of the lifetime
   for short-lived files):

   ```bash
   tctl auth sign --user=tangra-mgmt --format=file --ttl=720h --out=tangra-mgmt.identity
   ```

## 2. Register the cluster

Open **Teleport → Clusters**, choose **Register cluster** and fill in:

- **Name** — how the cluster is shown in the platform (unique in your tenant).
- **Proxy address** — the cluster's public proxy address, `host` or
  `host:port` (port 443 when omitted). Addresses that resolve to loopback,
  link-local, cloud metadata or (unless your operator allowed them) private
  networks are refused with *blocked target*.
- **Identity file** — upload `tangra-mgmt.identity` (at most 64 KiB).

The platform connects first and saves nothing if that fails:

| Message | Meaning |
|---|---|
| *Blocked target* | The address is not allowed (see above). |
| *Cluster unreachable* | Nothing answered at that address. |
| *Credential invalid* | The identity file is malformed, expired or rejected by the cluster. |
| *Dependency unavailable* | The secret store cannot store credentials. In production the credential store (warden) does not accept new credentials yet, so registration is refused rather than keeping the identity anywhere else (see [known limitations](known-limitations.md)). |

The identity is kept in the platform's secret store and is never shown
again. Delete the local file once the cluster is registered.

## 3. Read the overview

The cluster page shows the cluster name, Teleport version and edition, the
connection status, the credential's expiry, the last successful contact,
counts of users, roles and enrolled resources, and any
[missing permissions](reference/tangra-manager-role.md). The platform checks
every cluster each minute:

| Status | Meaning | What to do |
|---|---|---|
| Connected | The last check succeeded. | Nothing. |
| Unreachable | Three checks in a row failed. | Check the cluster and the network path to its proxy. |
| Credential expiring | The identity expires soon. | Rotate the credential. |
| Credential invalid | The identity expired or was rejected. | Rotate the credential. |
| Unsupported version | Teleport is older than the two supported major versions. | Upgrade the cluster; until then changes are blocked. |

To be notified when a cluster becomes unreachable or its credential nears
expiry, add an alert rule for that condition with its recipients.

## Rotate or remove

- **Rotate credential** — export a new identity file (step 1.3) and upload
  it on the cluster page. It is checked against the same cluster before it
  replaces the old one.
- **Remove** — deletes the registration, its links and mappings and the
  stored credential. The Teleport cluster itself is not changed; delete the
  `tangra-mgmt` user there if you no longer need it.
