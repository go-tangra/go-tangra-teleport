---
title: Teleport
summary: Register Teleport clusters, watch their health and manage users, roles, locks, join tokens and enrolled resources from the platform.
kind: guide
order: 0
tags: [teleport, overview, clusters, access]
requires: clusters:read
---
The Teleport module connects the platform to one or more Teleport clusters
you run. Each cluster is registered with its proxy address and a management
credential (a Teleport identity file kept in the platform's secret store,
never shown again after you save it).

## Concepts

- **Cluster** — a registered Teleport cluster. The module checks it
  periodically and shows its version, edition, credential expiry and health.
- **Credential** — the identity the module signs in with. Rotate it before it
  expires; the cluster page warns you in advance.
- **Resources** — servers, applications, databases, Kubernetes clusters and
  desktops enrolled in Teleport, which you can link to inventory hosts or
  assets.

## Start here

- [Get started](getting-started.md) — create the management identity on your
  cluster and register it.
- [Manage users, roles and locks](guides/users-roles-locks.md) — invite
  users, edit roles with a preview, and lock access during an incident.
- [Enroll servers, apps and databases](guides/enroll-resources.md) — join
  tokens shown once, offline detection and inventory/asset links.
- [Audit events, sessions and alerts](guides/audit-and-alerts.md) — search
  the audit log, play back sessions, and get notified about failed-login
  bursts.
- [Play recorded SSH sessions](guides/session-playback.md) — watch a
  session in the portal with `sessions:play`; every playback is audited.
- [Teleport access from the portal](guides/portal-access.md) — a terminal
  in the browser or an identity file for `tsh`, as your own provisioned
  Teleport user; needs MFA, every issuance is audited.
- [Provision tangra users](guides/provisioning.md) — map tangra roles or
  groups to Teleport roles, invite members, and de-provision leavers.
- [Deploy a new cluster](guides/deploy-new-cluster.md) — the wizard for a
  new Community Edition cluster: configuration, install script, checks and
  registration.
- [The tangra-manager role](reference/tangra-manager-role.md) — the
  least-privilege role the platform signs in with.
- [Teleport permissions](reference/permissions.md) — what each permission
  and module role allows.
- [HTTP API](reference/api.md) — `curl` against `/api/teleport/v1`, the
  CSRF header, every route and the error reasons.
- [The Access gRPC API](reference/grpc-access.md) — for module developers:
  `LookupHost` and `GetLinks`.
- [Operate Teleport](operations.md) — configuration, credential rotation,
  scheduled tasks, metrics and troubleshooting.
- [Known limitations](known-limitations.md) — what does not work yet and
  what to do meanwhile.

## Worked examples

- [Register an existing cluster](examples/register-cluster.md) — from
  `tctl` to a connected cluster, in the portal and with `curl`.
- [Onboard a user and adjust a role](examples/users-and-roles.md) — the
  one-time invite, and a role change with the diff preview.
- [Respond to an incident with locks](examples/incident-response.md) —
  lock a user, role or server, investigate, and unlock.
- [Enroll a server, an app, a database and a Kubernetes cluster](examples/enroll-resources.md)
  — the exact install commands and `teleport.yaml` snippets.
- [Audit searches and alert rules](examples/audit-and-alerts.md) — filters
  and time windows, a failed-login burst rule and a resource-offline rule.
- [Role mappings for provisioning](examples/provisioning-mappings.md) —
  map tangra roles and groups to Teleport roles and logins.
- [Deploy teleport.example.com with the wizard](examples/deploy-wizard.md)
  — a complete run of the deployment wizard.
