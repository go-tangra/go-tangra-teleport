---
title: Deploy a new Teleport cluster
summary: Use the deployment wizard to plan a Teleport Community Edition cluster, download a version-pinned configuration and install script, check DNS and the certificate, and register the cluster.
kind: guide
order: 60
tags: [teleport, deployment, wizard, install, dns, certificate, acme, community-edition]
requires: deployments:manage
---
If you do not run a Teleport cluster yet, the deployment wizard prepares
everything a new Community Edition cluster needs and hands over to cluster
registration. Only **administrators** (`deployments:manage`) can use it.
tangra never runs anything on your host: you copy the generated files there
and run them yourself.

Open **Teleport → Deployments**.

## 1. Enter the inputs

- **Cluster domain** — the name users reach the cluster at, for example
  `teleport.example.com`. Letters, digits and `-` only, at least two labels.
- **Certificate** — **Let's Encrypt (ACME)** with a contact **e-mail**, or
  **my own certificate** (you install it on the host yourself).
- **Teleport version** — the exact release to install, such as `19.1.2`. The
  install script is pinned to it.
- **First administrator** and their **logins** (host users such as `root` or
  `ubuntu`).

Values are checked strictly: anything that is not a plain domain, e-mail,
version, username or login is refused, so the generated script and
configuration cannot carry unexpected commands. **Save and continue** keeps
the inputs as a draft you can reopen later.

## 2. Prepare the host, DNS and network

- A Linux host with systemd, at least **2 vCPU and 1 GB** of memory.
- DNS **A records** for the domain and for `*.` the domain (application
  access), both pointing to the host.
- **TCP port 443** open to all sources.
- With ACME, port 443 must be reachable from the internet so Let's Encrypt
  can issue the certificate. With your own certificate, put the full chain
  in `/etc/teleport/tls/fullchain.pem` and the key in
  `/etc/teleport/tls/privkey.pem`, valid for the domain and its wildcard.

## 3. Download the artifacts

| File | What it is |
|---|---|
| `teleport.yaml` | The Teleport configuration (`/etc/teleport.yaml`) |
| `install.sh` | Installs the chosen Teleport version from Teleport's official installer, installs the configuration and starts the service |
| `tangra-manager-role.yaml` | The least-privilege role tangra signs in with ([reference](../reference/tangra-manager-role.md)) |
| `setup-commands.txt` | The `tctl` commands for the first administrator and the management identity |
| `checklist.md` | The checklist above, for your records |

Copy the files to the host and run `sudo ./install.sh` next to
`teleport.yaml`. Review the script first: it is plain text.

## 4. Check the prerequisites

Choose **Run checks**. The module checks that:

- the domain resolves (**dns_apex**);
- names under the domain resolve, that is the wildcard record exists
  (**dns_wildcard**);
- port 443 answers with a certificate that is valid for the domain and
  trusted (**tls_443**).

Each check shows its result and a short explanation. The checks run at
most once every 10 seconds per draft. For safety they never contact
loopback, link-local, cloud metadata or private addresses; a domain that
resolves to a private network is refused unless the platform operator has
allowed that network for this deployment.

## 5. Create the identities and register

Follow `setup-commands.txt` on the host:

1. `tctl users add` creates the first administrator; open the invite link it
   prints.
2. `tctl create -f tangra-manager-role.yaml`, `tctl users add tangra-mgmt`
   and `tctl auth sign` create the management identity file
   `tangra-mgmt.identity`.

Then choose **Register this cluster**. The registration dialog opens with
the proxy address already filled in; upload `tangra-mgmt.identity` and
save. The draft records the registered cluster and you land on the
cluster's page. Delete the identity file from the host afterwards.

## Example

[Deploy teleport.example.com with the wizard](../examples/deploy-wizard.md)
is a complete run with sample values, the generated `teleport.yaml` and
the API calls.
