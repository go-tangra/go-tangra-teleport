---
title: The tangra-manager role
summary: The least-privilege Teleport role the platform signs in with, what each rule is for, and what the platform reports when a grant is missing.
kind: reference
order: 70
tags: [teleport, role, permissions, credential, security]
requires: clusters:read
---
The platform manages a cluster as one dedicated Teleport user that holds a
single role, `tangra-manager`. Create it on the cluster before you register
the cluster (see [Get started](../getting-started.md)).

## Role definition

```yaml
kind: role
version: v7
metadata:
  name: tangra-manager
  description: Least-privilege identity the tangra platform manages this cluster with
spec:
  allow:
    # Listing enrolled resources needs label access; no logins, database
    # users, Kubernetes groups or desktop logins are granted, so the identity
    # cannot open sessions to them.
    node_labels: { '*': '*' }
    app_labels: { '*': '*' }
    db_labels: { '*': '*' }
    kubernetes_labels: { '*': '*' }
    windows_desktop_labels: { '*': '*' }
    rules:
      - resources: [user, role, lock, token]
        verbs: [list, read, create, update, delete]
      - resources: [node, app_server, db_server, kube_server, windows_desktop]
        verbs: [list, read]
      - resources: [event, session]
        verbs: [list, read]
      - resources: [cluster_auth_preference]
        verbs: [read]
  deny: {}
```

## What each rule is for

| Rule | Used for |
|---|---|
| `user`, `role`, `lock`, `token` (read and write) | Managing users, roles, locks and join tokens from the platform |
| `node`, `app_server`, `db_server`, `kube_server`, `windows_desktop` (read) | The resource list, health counts and inventory links |
| `event`, `session` (read) | Audit event search, session lists, alert rules and playing recorded sessions in the portal |
| `cluster_auth_preference` (read) | Showing how the cluster authenticates users, and refusing brokered access when it requires per-session MFA |

The role grants no logins, so the management identity cannot open an SSH,
database, Kubernetes or desktop session as itself, and it does not
impersonate anyone: [portal terminals and tsh downloads](../guides/portal-access.md)
are issued with the separate [tangra-access role](tangra-access-role.md)
and its sign-in identity. Label access to applications does let an
application certificate be requested; keep the identity file in the
platform only.

**Updating an existing cluster.** Earlier versions put an `impersonate`
rule in this role. Apply the role again with `tctl create -f
tangra-manager-role.yaml` (it overwrites the role; running it twice changes
nothing) once the cluster has an access identity: from then on the
management identity can no longer impersonate.

## Missing permissions

At registration and on every health check the platform tries one small read
of each kind above. A kind it may not read is listed on the cluster page as
*missing permissions* (for example `token:read`). Write access is never
tested. The cluster still connects; only the features that need the missing
grant fail, with `teleport_rejected`.
