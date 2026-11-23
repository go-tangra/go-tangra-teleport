---
title: Known limitations
summary: What the Teleport module cannot do yet - production cluster registration, provisioning, automatic inventory and asset linking, credential kinds and non-SSH session playback - and what to do meanwhile.
kind: faq
order: 95
tags: [teleport, limitations, faq, warden, provisioning, links, playback]
requires: clusters:read
---
These limits apply to this release. Most depend on other platform services
that do not have the needed function yet. They are not settings you can
change.

## Known limitations

### Production cluster registration needs warden secret write

Cluster identities are kept in the platform's secret store, warden. warden
cannot yet store secrets written by other modules. Until it can, in
production:

- **Register cluster** and **Rotate credential** answer *dependency
  unavailable* (`503`, `detail.dependency` `secret_store`);
- nothing is stored, and the identity file is never kept anywhere else
  as a fallback.

Development stacks and the join bundle set `secrets.allow_file: true`.
That stores identities as files, which is refused in production. Clusters
registered there work fully. See [Operate Teleport](operations.md).

### Provisioning needs auth member listing

Mappings from tangra roles and groups to Teleport roles can be created,
edited and removed. **Sync now**, **Provision user** and the scheduled sync
need the auth service to list the tenant's members with their module
roles, groups and login. Auth cannot do that yet, so these calls answer
*dependency unavailable* (`detail.dependency` `auth`) and change nothing.
Meanwhile, create users by hand on the **Users** tab. See
[provisioning](guides/provisioning.md).

### Automatic inventory and asset linking needs a lookup RPC

To link a Teleport resource to its inventory host or asset record
automatically, the module must look up records by hostname or IP address.
The inventory and asset modules do not offer that lookup yet. So:

- the resource list reports `link_status: dependency_unavailable` and
  shows *automatic matching unavailable*;
- you can still **Link** a resource to a record by hand (module and record
  ID) and **Remove link**. Existing links stay.

The other direction already works: inventory, asset and portal can ask
this module which Teleport resources reach a host. See
[the Access gRPC API](reference/grpc-access.md).

### Identity-file credentials only

The platform signs in to a cluster with an identity file from
`tctl auth sign --format=file`. Machine ID (`tbot`) credentials that renew
themselves are not supported. Rotate the identity before it expires: the
cluster page and the notifications warn you in advance. Choose the TTL
with that in mind, for example `--ttl=720h` and a monthly rotation. See
[register an existing cluster](examples/register-cluster.md#rotate-before-it-expires).

### Only SSH sessions play in the portal

SSH terminal sessions play inside the portal with `sessions:play` (see
[play recorded SSH sessions](guides/session-playback.md)). Desktop,
Kubernetes, database and application sessions, and recordings over
500 MiB, still open in the Teleport web UI (**Open in Teleport**), where
you sign in with your own Teleport account. Sessions still in progress
cannot be watched live. Several replicas of the module do not share
playbacks: if a page goes to another replica the player starts the
playback again.

### Smaller limits

- **Alert recipients** are tangra user ids typed as text. Channel ids are
  stored but nothing is delivered to them.
- **Audit search filters** for user and resource are applied to the events
  read from Teleport. A search with a narrow filter over a busy month can
  take several pages.
- **Concurrent edits.** The platform refuses a stale user or role edit with
  a conflict. A change made with `tctl` at almost the same moment as one
  made in the portal can still be overwritten, because Teleport does not
  make every update conditional.
- **Backup** of the module configuration exists inside the module but has
  no API route yet.
