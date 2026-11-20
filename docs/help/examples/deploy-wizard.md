---
title: "Example: deploy teleport.example.com with the wizard"
summary: A complete run of the deployment wizard for a new Community Edition cluster with Let's Encrypt - inputs, DNS records, the generated teleport.yaml, the install, the checks and the handover to registration.
kind: example
order: 70
tags: [teleport, example, deployment, wizard, acme, dns, install]
requires: deployments:manage
---
**Goal.** Stand up a new Teleport cluster at `teleport.example.com` on a
fresh Ubuntu VM. It uses a Let's Encrypt certificate and has one first
administrator, `admin-jane`. Then manage it from the portal.

**What you need.** `deployments:manage` (administrators). A Linux VM with
systemd, at least 2 vCPU and 1 GB RAM, a public IP (`203.0.113.10` in this
example), and access to the DNS zone `example.com`.

The platform never connects to your VM to run anything. It generates
files, and you run them.

## 1. Inputs

Open **Teleport → Deployments** and fill in:

| Field | Value |
|---|---|
| Cluster domain | `teleport.example.com` |
| Certificate | Let's Encrypt (ACME) |
| ACME contact e-mail | `ops@example.com` |
| Teleport version | `19.1.2` |
| First administrator | `admin-jane` |
| Administrator logins | `ubuntu`, `root` |

**Save and continue** stores a draft. The same through the API (helpers
from the [HTTP API](../reference/api.md)):

```bash
tsend -X POST "$API/deployments" -d '{
  "domain": "teleport.example.com",
  "cert_mode": "acme",
  "acme_email": "ops@example.com",
  "teleport_version": "19.1.2",
  "admin_username": "admin-jane",
  "admin_logins": ["ubuntu", "root"]
}'
# 201 {"id": "<draft-id>", ..., "proxy_addr": "teleport.example.com:443", "checks": []}
DRAFT=<draft-id>
```

The values are checked strictly. A domain needs at least two labels of
letters, digits and `-`. The version must be `major.minor.patch`. There
must be 1 to 32 logins. Anything that looks like shell, YAML or Markdown
syntax is refused with `422 validation_failed`. For your own certificate,
use `"cert_mode": "own_cert"` and leave out `acme_email`.

## 2. DNS and network

Create both records, pointing at the VM:

```text
teleport.example.com.    300  IN  A  203.0.113.10
*.teleport.example.com.  300  IN  A  203.0.113.10
```

Open **TCP 443** to everyone. Let's Encrypt must reach it to issue the
certificate, and Teleport multiplexes all its traffic on that port.

## 3. Download and install

Download the five files from the wizard, or:

```bash
for f in teleport.yaml install.sh tangra-manager-role.yaml setup-commands.txt checklist.md; do
  tget -o "$f" "$API/deployments/$DRAFT/artifacts/$f"
done
```

The files are generated from the draft each time and are not stored.
Here is `teleport.yaml` for this draft, without its three header comment
lines:

```yaml
version: v3
teleport:
  nodename: "teleport.example.com"
  data_dir: /var/lib/teleport
  log:
    output: stderr
    severity: INFO
    format:
      output: text
auth_service:
  enabled: "yes"
  listen_addr: 0.0.0.0:3025
  cluster_name: "teleport.example.com"
  proxy_listener_mode: multiplex
  authentication:
    type: local
    second_factor: "on"
    webauthn:
      rp_id: "teleport.example.com"
ssh_service:
  enabled: "yes"
proxy_service:
  enabled: "yes"
  web_listen_addr: 0.0.0.0:443
  public_addr: "teleport.example.com:443"
  acme:
    enabled: "yes"
    email: "ops@example.com"
```

Copy the files to the VM, read `install.sh` (it is plain text), and run it
next to `teleport.yaml`:

```bash
scp teleport.yaml install.sh tangra-manager-role.yaml setup-commands.txt ubuntu@203.0.113.10:
ssh ubuntu@203.0.113.10 'chmod +x install.sh && sudo ./install.sh'
```

The script installs Teleport 19.1.2 with Teleport's official installer,
checks that the version matches, installs the configuration as
`/etc/teleport.yaml` and starts the service.

## 4. Run the checks

Choose **Run checks**, or:

```bash
tsend -X POST "$API/deployments/$DRAFT/checks" | jq '.checks'
```

```json
[
  {"name": "dns_apex", "ok": true, "detail": "...", "checked_at": "2026-11-20T10:12:00Z"},
  {"name": "dns_wildcard", "ok": true, "detail": "...", "checked_at": "2026-11-20T10:12:00Z"},
  {"name": "tls_443", "ok": true, "detail": "...", "checked_at": "2026-11-20T10:12:00Z"}
]
```

| Check fails | Fix |
|---|---|
| `dns_apex` | The A record for `teleport.example.com` is missing or has not propagated yet |
| `dns_wildcard` | The `*.teleport.example.com` record is missing (the check resolves a name under it) |
| `tls_443` | Port 443 is closed, Teleport is not running, or Let's Encrypt has not issued the certificate yet. Check `journalctl -u teleport` |

You can run the checks once every 10 seconds per draft. Running them again
sooner answers `429 rate_limited`. A domain that resolves to a private
address is refused unless your operator allowed that range.

## 5. Create the identities

On the VM, follow `setup-commands.txt`:

```bash
sudo tctl users add 'admin-jane' --roles=editor,access,auditor --logins='ubuntu,root'
sudo tctl create -f tangra-manager-role.yaml
sudo tctl users add tangra-mgmt --roles=tangra-manager
sudo tctl auth sign --user=tangra-mgmt --format=file --ttl=720h --out=tangra-mgmt.identity
```

Jane opens the invite link from the first command and sets her password
and second factor. Copy `tangra-mgmt.identity` to your workstation.

## 6. Register

Choose **Register this cluster**. The registration dialog opens with
`teleport.example.com:443` filled in. Upload `tangra-mgmt.identity` and
save. The draft records the new cluster, and you land on its page.
Afterwards, delete the identity file from the VM and your workstation.

Registration is the same as for any cluster. See
[register an existing cluster](register-cluster.md), including the
production [limitation on storing credentials](../known-limitations.md).
