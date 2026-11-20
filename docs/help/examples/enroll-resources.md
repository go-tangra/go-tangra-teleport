---
title: "Example: enroll a server, an app, a database and a Kubernetes cluster"
summary: The exact install commands and teleport.yaml snippets the Enroll dialog produces for each resource type, what to edit in them, and how to check that the resource joined.
kind: example
order: 40
tags: [teleport, example, enroll, join-token, node, app, database, kubernetes]
requires: tokens:manage
---
**Goal.** Join four resources to the cluster at `teleport.example.com`: a
Linux server, an internal web app, a PostgreSQL database and a Kubernetes
cluster.

**What you need.** `tokens:manage` (operators and administrators). On each
host you need root and outbound HTTPS to the proxy. Teleport itself must be
installed on the app, database and Kubernetes hosts. The server script
installs it for you.

## How every enrollment works

1. Open the cluster, go to **Resources** and choose **Enroll**.
2. Pick the **Resource type** and **Valid for (minutes)**: 1 to 1440,
   default 30. Use the shortest time that gives you enough to reach the
   host.
3. Copy the **install command** and the **configuration snippet**. The
   token is in both. They are shown **once**: the platform keeps only a
   SHA-256 fingerprint of the token, so close the dialog only after you
   have copied what you need.
4. Run the command on the host. The resource shows up as **online** on the
   **Resources** tab within seconds.
5. **Revoke** the token on the **Tokens** tab once the host has joined, so
   nobody else can use it.

The same through the API (helpers from the [HTTP API](../reference/api.md)):

```bash
tsend -X POST "$API/clusters/$CLUSTER/tokens" -d '{"resource_type": "node", "ttl_minutes": 30}'
```

```json
{
  "id": "018f3a2b-0000-7000-8000-0000000000f1",
  "resource_type": "node",
  "token": "<token>",
  "expires_at": "2026-11-20T10:30:00Z",
  "install_command": "curl -fsSL 'https://teleport.example.com/scripts/<token>/install-node.sh' | sudo bash",
  "config_snippet": "version: v3\nteleport:\n    proxy_server: teleport.example.com:443\n..."
}
```

Below, `<token>` stands for the value the dialog shows. Values that come
from the proxy address and token are single-quoted for the shell.

## A Linux server (SSH)

**Resource type:** server (`node`). Run this on the server:

```bash
curl -fsSL 'https://teleport.example.com/scripts/<token>/install-node.sh' | sudo bash
```

This is Teleport's own install script, served by your proxy. It installs
Teleport, joins the node with the token and starts the service. If you
prefer to configure the node yourself, save the snippet as
`/etc/teleport.yaml` and run `sudo teleport start --config=/etc/teleport.yaml`:

```yaml
version: v3
teleport:
    proxy_server: teleport.example.com:443
    join_params:
        method: token
        token_name: <token>
auth_service:
    enabled: false
proxy_service:
    enabled: false
ssh_service:
    enabled: true
```

Check: `tctl nodes ls` on the cluster, or **Resources** filtered by type.
Users still need a role whose `node_labels` match the server, and a login
on it, before they can connect.

## An internal web app

**Resource type:** application (`app`). The command and snippet use the
placeholders `example-app` and `http://localhost:8080`. Replace them with
your app's name and its address as seen from the host:

```bash
sudo teleport app start --token='<token>' --proxy='teleport.example.com:443' \
  --name=example-app --uri='http://localhost:8080'
```

```yaml
version: v3
teleport:
    proxy_server: teleport.example.com:443
    join_params:
        method: token
        token_name: <token>
auth_service:
    enabled: false
proxy_service:
    enabled: false
ssh_service:
    enabled: false
app_service:
    enabled: true
    apps:
        - name: example-app
          uri: http://localhost:8080
```

For example, a Grafana at port 3000 becomes `--name=grafana
--uri='http://localhost:3000'`. Users then reach it at
`https://grafana.teleport.example.com`. This needs the wildcard DNS record
for the cluster domain.

## A PostgreSQL database

**Resource type:** database (`db`). Replace the placeholders `example-db`
and `localhost:5432` with your database:

```bash
sudo teleport db start --token='<token>' --proxy='teleport.example.com:443' \
  --name=example-db --protocol=postgres --uri='localhost:5432'
```

```yaml
version: v3
teleport:
    proxy_server: teleport.example.com:443
    join_params:
        method: token
        token_name: <token>
auth_service:
    enabled: false
proxy_service:
    enabled: false
ssh_service:
    enabled: false
db_service:
    enabled: true
    databases:
        - name: example-db
          protocol: postgres
          uri: localhost:5432
```

The database itself must trust Teleport's database client CA for
certificate sign-in; set that up as described in Teleport's database
access guides. The platform does not configure the database.

## A Kubernetes cluster

**Resource type:** Kubernetes (`kube`). There is no one-line installer
here. Save the snippet as `/etc/teleport.yaml` on a host that can reach
the Kubernetes API, put a kubeconfig for that cluster at
`/etc/teleport/kubeconfig`, and start Teleport:

```yaml
version: v3
teleport:
    proxy_server: teleport.example.com:443
    join_params:
        method: token
        token_name: <token>
auth_service:
    enabled: false
proxy_service:
    enabled: false
ssh_service:
    enabled: false
kubernetes_service:
    enabled: true
    kubeconfig_file: /etc/teleport/kubeconfig
```

```bash
sudo teleport start --config=/etc/teleport.yaml
```

Desktops (`desktop`) work the same way. Their snippet has a
`windows_desktop_service` with the placeholder host
`desktop.example.internal`.

## After joining

- **Offline resources.** If a resource stops sending heartbeats, it is
  shown as **offline**. After the cluster's offline threshold (15 minutes
  by default) it is **flagged**, and the recipients of `resource_offline`
  alert rules are notified once. See the
  [audit and alerts example](audit-and-alerts.md#rule-2-a-resource-went-offline).
- **Inventory and asset links.** You can link a resource to its inventory
  host or asset record with **Link**, giving the module and the record ID.
  Automatic matching is not available yet. See
  [known limitations](../known-limitations.md).
- **Find resources through the API:**

  ```bash
  tget "$API/clusters/$CLUSTER/resources?kind=node&q=staging"
  tget "$API/clusters/$CLUSTER/resources?status=flagged"
  ```

## Troubleshooting

| Symptom | Cause |
|---|---|
| The host says the token is invalid or expired | The token's time ran out or it was revoked. Issue a new one |
| The resource never appears | The host cannot reach `teleport.example.com:443`, or Teleport on the host failed. Check `journalctl -u teleport` |
| You closed the dialog too early | The token cannot be shown again. Revoke it and issue a new one |
