---
title: The tangra-access role
summary: The Teleport role and user that portal terminals and tsh downloads are issued with, how to bootstrap them, sign in with tsh login and upload the access identity, and how long it lasts.
kind: reference
order: 72
tags: [teleport, role, access-identity, impersonation, tsh, credential, security]
requires: clusters:read
---
[Portal terminals and tsh downloads](../guides/portal-access.md) need
certificates *as the provisioned user*. Teleport issues those only to a
certificate obtained by **signing in**: it never lets an impersonated
certificate impersonate again, and every identity made with
`tctl auth sign` - such as the management identity - is one. So brokered
access uses a second, optional identity per cluster: the **access
identity**, a `tsh login` identity of the dedicated Teleport user
`tangra-access`. The management identity keeps doing everything else.

## Role definition

```yaml
kind: role
version: v7
metadata:
  name: tangra-access
  description: Portal terminals and tsh downloads of the tangra platform (brokered access)
spec:
  options:
    # The sign-in identity of tangra-access lives as long as tsh login asks
    # for, up to this (Teleport 18 applies no lower ceiling of its own).
    max_session_ttl: 8760h
  allow:
    # Obtain short-lived certificates as the Teleport users the platform
    # provisioned (labelled tangra.io/managed), never as a local user such
    # as the cluster administrator. Nothing else: no logins, no reads.
    impersonate:
      users: ['*']
      roles: ['*']
      where: 'equals(impersonate_user.metadata.labels["tangra.io/managed"], "true")'
  deny: {}
```

The role grants **only** the impersonate rule. Teleport applies its `where`
clause itself: it refuses any user without the label
`tangra.io/managed=true`, so local users such as the cluster administrator
can never be impersonated. The role has no logins and no read rules (the
platform reads users, roles and locks with the management identity), so the
access identity cannot open a session or read anything as itself. The
platform additionally checks that the user is the caller's own before every
issuance.

## Bootstrap

Run on a host with `tctl` access to the cluster (the cluster administrator):

```bash
tctl create -f tangra-access-role.yaml
tctl users add tangra-access --roles=tangra-access
```

Open the invite link `tctl` prints and set a password and a second factor
(an authenticator app). Then, from any machine with `tsh`, sign in once
and write the identity file (`--ttl` is in minutes; `--format=file` is the
default):

```bash
tsh login --proxy=teleport.example.com:443 --user=tangra-access --ttl=525600 --format=file --out=tangra-access.identity
```

Open the cluster in the platform, choose **Access identity for portal
terminals → Upload**, select `tangra-access.identity`, and delete the file.

The platform checks the file before it stores it: it must be unexpired,
signed in (not made with `tctl auth sign`: *access identity not sign-in*),
for the same Teleport cluster, and - when a provisioned user exists - able
to get certificates for that user (*access identity cannot impersonate*:
the user lacks the `tangra-access` role). It is stored encrypted in the
same secret store as the management credential and never shown again.

## Lifetime and renewal

The identity lasts what `tsh login --ttl` asked for, capped by the role's
`max_session_ttl`. Measured on Teleport 18.11: `tsh login --ttl=525600`
(one year) against `max_session_ttl: 8760h` gave an 8760-hour certificate,
and even a ten-year request was honoured when the role allowed it, so the
role's `max_session_ttl` is the only ceiling. Choose a shorter `--ttl` if
your policy prefers more frequent sign-ins.

The platform warns before the access identity expires with the same
thresholds as the management credential (7 days before, or at a quarter of
the lifetime when shorter, then with one day left, then when it has
expired), to the recipients of `credential_expiring` alert rules. To renew,
sign in again with the same `tsh login` command and choose **Replace**.
Terminals that are already open keep running until their own certificates
expire.

## Without an access identity

The platform then tries the management identity. That works only if the
management identity itself came from a sign-in and its role may
impersonate - the setup of earlier versions. Otherwise terminals and
downloads answer *access identity missing*; an expired access identity
answers *access identity expired*, and one Teleport rejects answers
*access identity invalid*.
