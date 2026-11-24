---
title: Teleport access from the portal
summary: Open a terminal on an SSH node in the browser, or download a short-lived identity file for tsh, as your own provisioned Teleport user - without signing in to Teleport. Needs MFA on the portal session; every issuance is audited.
kind: guide
order: 47
tags: [teleport, access, terminal, ssh, tsh, identity, mfa, impersonation, access-terminal, access-download]
requires: access:terminal
---
If an administrator has [provisioned](provisioning.md) you on a cluster,
the portal can give you Teleport access as **your own Teleport user**
without a separate Teleport sign-in. That user is named after your sign-in
e-mail (in lower case) and gets the Teleport roles and logins mapped to your
Teleport module roles and groups:

- **Terminal** — an interactive SSH shell on a node, in the browser.
- **Download access for tsh** — a short-lived identity file for
  `tsh -i <file>` on your own machine.

Teleport issues the certificates and enforces your Teleport roles, logins,
locks and session recording exactly as if you had signed in to Teleport.
The portal only asks Teleport for them on your behalf.

## Who can use it

| Permission | Allows |
|---|---|
| `access:terminal` | See your access on a cluster, list the nodes you can reach and open terminals (administrator and operator module roles) |
| `access:download` | Download an identity file for `tsh` (administrator module role) |

You also need, for every issuance:

- **A provisioned Teleport user on the cluster.** It is always the one the
  platform created for you; no request can choose another user, and the
  cluster's local users (such as its administrator) can never be used.
  Otherwise the portal answers *not provisioned* ("You have no Teleport
  user on this cluster"): ask an administrator to map one of your roles or
  groups and run **Sync now**, or to provision you with **Provision user**
  on the cluster's **Provisioning** tab.
- **A portal session signed in with a second factor (MFA).** A session that
  used only a password can see **My access** but is refused anything else
  with *MFA required*. Sign out and sign in again with your authenticator
  or security key.
- **No per-session MFA role.** If one of your Teleport roles (or the
  cluster) requires Teleport's own per-session MFA, the portal cannot
  satisfy it and refuses with *session MFA required*; use `tsh login` on
  that cluster instead.
- **No lock** on your Teleport user (*user locked*).

## Open a terminal

1. Open the cluster and choose the **Resources** tab.
2. On a node you can reach, choose **Terminal** and pick a login. Only the
   logins your Teleport user holds are offered; the node still decides.
3. The terminal opens in a new page. Close the page or choose **End** to
   end the session.

The session is a normal Teleport SSH session: Teleport records it under
your Teleport user and it appears in the **Sessions** tab.

A terminal ends when you end it, when the page has been closed for 30
seconds, when your portal session has not been seen for 3 minutes, after
8 hours, when its certificates expire, when the shell exits, or when the
platform finds within 30 seconds that your Teleport user was removed,
de-provisioned or locked. You can have at most 5 terminals open at once.

## Download access for tsh

On the cluster overview, **My access** shows your Teleport user, roles and
logins. **Download access for tsh** saves an identity file and shows the
command, for example:

```
tsh -i tangra-alice-prod.example.com.identity --proxy=teleport.example.com:443 ssh deploy@web-1
```

The file holds a private key: keep it to yourself and delete it when you
are done. It expires after the cluster's access lifetime (8 hours unless an
administrator changed it; Teleport may shorten it further with your roles'
`max_session_ttl`). The expiry shown is the one in the certificate.

## For administrators

- **Access lifetime.** The cluster's **Settings** tab sets the lifetime of
  issued access, 15 minutes to 12 hours (`clusters:manage`).
- **The access identity.** Terminals and downloads are issued with the
  cluster's [access identity](../reference/tangra-access-role.md): a
  `tsh login` identity of the Teleport user `tangra-access`, whose role may
  only impersonate provisioned users. Upload it on the cluster overview
  (**Access identity for portal terminals**, `clusters:manage`); the panel
  shows its expiry and the exact `tsh login` command. Without it the portal
  answers *access identity missing* (unless the management identity itself
  came from a sign-in), and after it expires *access identity expired*.
  The platform warns before it expires like it does for the management
  credential.

### Setting it up on an existing cluster

On a cluster registered before the access identity existed, in this order:

1. Create the role and the user (the role YAML is in the
   [reference](../reference/tangra-access-role.md) and in the deployment
   wizard's `tangra-access-role.yaml`):

   ```bash
   tctl create -f tangra-access-role.yaml
   tctl users add tangra-access --roles=tangra-access
   ```

2. Open the invite link and set a password and a second factor.
3. Sign in once and write the identity file:

   ```bash
   tsh login --proxy=teleport.example.com:443 --user=tangra-access --ttl=525600 --format=file --out=tangra-access.identity
   ```

4. Upload `tangra-access.identity` on the cluster overview, then delete it.
   Open a terminal to check it works.
5. Apply the current [tangra-manager role](../reference/tangra-manager-role.md)
   (`tctl create -f tangra-manager-role.yaml`), which no longer impersonates.

## What is recorded

Uploading, replacing and removing the access identity are audit entries
(`teleport.access_identity.upload`, `.replace`, `.delete`). Every download
and refusal is an audit entry
(`teleport.access.issued`), and every terminal has a start and an end entry
(`teleport.terminal.started`, `teleport.terminal.ended`, with the reason it
ended and its duration). Entries name your Teleport user, the node and the
login. No key, certificate or terminal content is ever logged, audited or
stored: certificates live in memory for the request or the terminal only.

## Limitations

- **Fresh MFA confirmation is not asked.** The portal relies on the MFA of
  your sign-in; it cannot yet ask you to confirm with your second factor at
  the moment of issuance (it needs a step-up proof from the platform's
  authentication service).
- **Terminals live in one module instance.** A terminal belongs to the
  instance that opened it; running several replicas needs sticky routing,
  and a restart ends open terminals.
- **SSH nodes only.** Applications, databases, Kubernetes and desktops are
  reached with the downloaded identity and `tsh`.
