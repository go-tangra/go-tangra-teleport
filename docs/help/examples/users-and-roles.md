---
title: "Example: onboard a user and adjust a role"
summary: Create a Teleport user with a one-time invite, send the invite safely, and widen a role's logins and labels with the YAML diff preview before applying it.
kind: example
order: 20
tags: [teleport, example, users, invite, roles, yaml, diff]
requires: users:manage
---
**Goal.** Alice joins the support team. She needs SSH access as `ubuntu`
to staging servers, so you create her Teleport user. Later the team also
needs `deploy` logins on production servers, so you widen the team's
`support` role.

**What you need.** `users:manage` to create the user, `roles:manage` to
change the role. Both belong to the administrator role.

## 1. Create the user and get the invite

Open the cluster, go to **Users** and choose **New user**:

| Field | Value |
|---|---|
| Username | `alice` |
| Roles | `support` |
| Logins | `ubuntu` |

Choose **Create and invite**. The dialog shows the sign-up link and when it
expires. Use **Copy link**, then close the dialog.

The link is shown **only once**. The platform does not store it, log it or
put it in the audit trail. Send it to Alice over a channel you trust, such
as a direct message in your company chat. Do not post it in a shared
ticket. On the link, Alice sets her password and second factor.

The same through the API (helpers from the [HTTP API](../reference/api.md)):

```bash
tsend -X POST "$API/clusters/$CLUSTER/users" \
  -d '{"name": "alice", "roles": ["support"], "logins": ["ubuntu"]}'
```

```json
{
  "user": {"name": "alice", "roles": ["support"], "logins": ["ubuntu"],
           "managed": false, "locked": false, "revision": "<revision>"},
  "invite_url": "https://teleport.example.com/web/invite/<one-time-id>",
  "invite_expires_at": "2026-11-21T10:00:00Z"
}
```

What can go wrong:

| Answer | Cause |
|---|---|
| `422 validation_failed` | A role in `roles` does not exist on the cluster, or a name breaks the naming rules |
| `409 conflict` | A user `alice` already exists |
| `422 unsupported_version` | The cluster's Teleport version is too old, so changes are blocked |

If the link is lost or expires, choose **Reset** on the user. You get a new
one-time link, and Alice's password and second factors are reset too:

```bash
tsend -X POST "$API/clusters/$CLUSTER/users/alice/reset"
```

## 2. Change the role with a preview

Open **Roles**, select `support`. The definition is shown in its normal
form: keys sorted, Teleport's defaults filled in, two-space indentation.
The part that matters here looks like this:

```yaml
kind: role
metadata:
  name: support
spec:
  allow:
    logins:
      - ubuntu
    node_labels:
      env:
        - staging
version: v7
```

Edit **Definition (YAML)** to add the `deploy` login and the `production`
label value:

```yaml
    logins:
      - ubuntu
      - deploy
    node_labels:
      env:
        - staging
        - production
```

Choose **Preview changes**. The platform checks the definition with
Teleport's own rules and shows a unified diff of the normal forms. Nothing
has changed yet:

```diff
--- current
+++ proposed
@@ -14,9 +14,11 @@
     logins:
       - ubuntu
+      - deploy
     node_labels:
       env:
         - staging
+        - production
```

The line numbers depend on the whole role. If the definition is invalid,
the preview lists the errors instead and **Apply** stays disabled.

Choose **Apply** and confirm. Teleport applies the role at once to every
user who holds it, Alice included.

The same through the API. `support.yaml` holds the whole edited
definition, and `<revision>` comes from `GET /clusters/{id}/roles/support`:

```bash
tget "$API/clusters/$CLUSTER/roles/support"        # {yaml, revision, preset}

jq -n --rawfile y support.yaml --arg rev '<revision>' '{yaml: $y, revision: $rev}' |
  tsend -X POST "$API/clusters/$CLUSTER/roles/preview" --data-binary @-
# {"valid": true, "errors": [], "diff": "--- current\n+++ proposed\n@@ ..."}

jq -n --rawfile y support.yaml --arg rev '<revision>' '{yaml: $y, revision: $rev}' |
  tsend -X PUT "$API/clusters/$CLUSTER/roles/support" --data-binary @-
```

Rules for role definitions:

- one `kind: role` document, `version: v7` or `v8`, at most 64 KiB;
- `metadata.name` must match the role in the path;
- an empty `revision` creates a new role. If the role already exists, the
  answer is `409 conflict`;
- if someone changed the role since you read it, **Apply** answers
  `409 conflict`. Choose **Reload** (or read it again) and redo the edit;
- if Teleport rejects the definition, the answer is `422 teleport_rejected`
  with Teleport's first line in `detail.message`.

## 3. Give Alice a second role

Edit Alice on **Users** and add `auditor`, or:

```bash
tsend -X PUT "$API/clusters/$CLUSTER/users/alice" \
  -d '{"roles": ["support", "auditor"], "logins": ["ubuntu"], "revision": "<revision>"}'
```

`PUT` replaces both lists, so send every role and login she should keep.

## What the module records

The module audit trail (**Teleport → Audit**) gets `teleport.user.create`,
`teleport.user.reset`, `teleport.role.update` and `teleport.user.update`
entries, each with you as the actor. The role entry has fingerprints of
the old and new definitions, not the YAML itself. The invite link is
never recorded.
