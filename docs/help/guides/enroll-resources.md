---
title: Enroll servers, apps and databases
summary: Issue a short-lived join token, run the install command on the host, and watch the resource come online; link it to its inventory or asset record.
kind: guide
order: 30
tags: [teleport, enroll, join-token, resources, inventory, asset, offline]
requires: resources:read
---
Open a cluster and choose the **Resources** tab. The list shows every
enrolled server, application, database, Kubernetes cluster and desktop:
online ones live from Teleport, offline ones from the last time they were
seen.

## Enroll a resource

1. Choose **Enroll**, pick the resource type and a validity period
   (default 30 minutes, at most 24 hours). Operators and administrators can
   do this (`tokens:manage`).
2. Copy the **install command** (or, for Kubernetes and desktops, the
   **configuration snippet** for `/etc/teleport.yaml`) and run it on the host.
3. Close the dialog. The token, the command and the snippet are shown
   **once**: tangra keeps only a fingerprint of the token, so they cannot be
   shown again. Issue a new token if you lost them.
4. The resource appears as **online** within seconds of joining.

The **Tokens** tab lists the tokens issued from tangra, who issued them and
when they expire. **Revoke** a token you no longer need: Teleport refuses
any later join with it.

## Enroll inventory hosts through their agent

Linux hosts that run the tangra inventory agent can join as SSH nodes
without anyone logging in to them. This needs `resources:enroll`
(operators and administrators).

1. Choose **Enroll inventory hosts** and search by hostname. Each host
   shows whether its agent is online, whether it can be enrolled, and the
   Teleport labels it will get: `tangra.io/inventory-host`,
   `tangra.io/hostname`, `tangra.io/os`, `tangra.io/os-version`,
   `tangra.io/arch`, `tangra.io/manufacturer`, `tangra.io/model` and one
   `tangra.io/tag.<key>` per inventory tag.
2. Select up to 50 hosts, set how long tangra keeps trying (1 to 72 hours,
   default 24) and choose **Enroll**. Hosts that cannot be enrolled are
   listed with the reason: no agent, more than one agent, not Linux, the
   agent needs an upgrade, or the host is retired.
3. When the agent picks up the request it fetches a single-use join token
   valid for 30 minutes, installs the Teleport release matching the
   cluster's version, verifies the cluster's CA pin and joins. No token is
   ever shown, stored or queued: it is created at the moment the agent asks.
4. Progress shows under **Inventory enrollments**: pending, delivered,
   fetched, installing, then joined. A joined node is linked to its
   inventory host automatically.

**Cancel** stops an enrollment that has not finished. **Retry** starts a
new one for a failed, expired or cancelled enrollment. If inventory cannot
be reached, the list shows the last known states.

## Offline resources

When a resource stops sending heartbeats, Teleport forgets it and tangra
marks it **offline**. After the cluster's offline threshold (15 minutes by
default, see the cluster settings) it is **flagged**, and the people in the
cluster's `resource_offline` alert rules are notified once. It turns online
again by itself when it comes back.

## Inventory and asset links

tangra links each resource to the inventory or asset record with the same
hostname or IP address. A single match is linked automatically; several
matches are shown as candidates: **Confirm** the right one (this needs
`resources:link`). You can also link a resource by hand, or **Remove** a
wrong link; a removed automatic link is not recreated.

If the list says *automatic matching unavailable*, the inventory and asset
lookup cannot be reached: existing links stay, and manual links still work.

## Examples

- [Enroll a server, an app, a database and a Kubernetes cluster](../examples/enroll-resources.md)
  shows the install command and `teleport.yaml` snippet for each type.
- Automatic linking is not available yet: see
  [known limitations](../known-limitations.md).
