---
title: "For module developers: the Access gRPC API"
summary: How inventory, asset and portal ask whether a host is reachable through Teleport - teleport.v1.Access LookupHost and GetLinks, the Go client, who may call it and the errors it returns.
kind: reference
order: 85
tags: [teleport, grpc, api, developers, lookup, mesh]
audience: operator
---
Other platform modules can ask the Teleport module whether a host is
enrolled in one of the tenant's Teleport clusters, for example to show a
"reachable through Teleport" badge with a link. The service is
`teleport.v1.Access`, defined in `api/proto/teleport/v1/access.proto`. It
is served on the module's mesh gRPC port only and is **not** proxied by
the gateway.

## Who may call it

Only the services **inventory**, **asset** and **portal** may call it.
They are identified by their SPIFFE identity over mTLS (`deploy/policy.yaml`).
The handler checks the caller's verified service name against the same
list. Any other caller gets `PermissionDenied`, and the refusal is
recorded in the module audit trail as `teleport.access.refused`.

The caller acts for the tenant named in `tenant_id`, with read-only access
to resources (`resources:read`). It sees only that tenant's clusters.

## The service

```proto
service Access {
  // Hosts enrolled in any of the tenant's clusters that match a hostname or IP.
  rpc LookupHost(LookupHostRequest) returns (LookupHostResponse);
  // Teleport reachability for records the caller owns, in bulk (at most 500 ids).
  rpc GetLinks(GetLinksRequest) returns (GetLinksResponse);
}

message LookupHostRequest { string tenant_id = 1; string hostname = 2; string ip = 3; }
message HostAccess {
  string cluster_id = 1; string cluster_name = 2; string resource_name = 3;
  bool online = 4; google.protobuf.Timestamp last_seen = 5;
  string web_url = 6; string resource_id = 7; string kind = 8;
}
message LookupHostResponse { repeated HostAccess hosts = 1; }
message GetLinksRequest { string tenant_id = 1; string target_module = 2; repeated string target_ids = 3; }
message GetLinksResponse { map<string, HostAccess> by_target_id = 1; }
```

**LookupHost** rules:

- `tenant_id` must be a UUID;
- give **exactly one** of `hostname` (an RFC 1123 name; a trailing dot is
  ignored) and `ip` (IPv4 or IPv6 without a zone; IPv4-mapped addresses
  are unmapped);
- the module matches against what it knows about enrolled resources (their
  hostname or address), online or offline. `online` and `last_seen` tell
  you which.

**GetLinks** returns, for each of your records (`target_module` is
`inventory` or `asset`, 1 to 500 ids), the resource linked to it. Only
automatic and confirmed links count, not candidates, and an online
resource is preferred. Records without a link are missing from the map.

## Go example

Use the typed client `pkg/teleportclient`. It does not dial: pass it the
mesh connection from Freya.

```go
import (
	"context"
	"errors"
	"fmt"

	freya "github.com/go-tangra/go-tangra/v4"

	"github.com/go-tangra/go-tangra-teleport/v4/pkg/teleportclient"
)

func teleportBadge(ctx context.Context, app *freya.App, tenantID, hostname string) error {
	conn, err := app.Client(ctx, teleportclient.Service) // "teleport", SPIFFE mTLS
	if err != nil {
		return err
	}
	tc := teleportclient.New(conn)

	hosts, err := tc.LookupHost(ctx, tenantID, hostname, "") // or ("", "192.0.2.10")
	switch {
	case errors.Is(err, teleportclient.ErrUnavailable):
		return nil // Teleport module down: show no badge, do not fail the page
	case err != nil:
		return err
	}
	for _, h := range hosts {
		fmt.Printf("%s on %s (%s), online=%v: %s\n", h.ResourceName, h.ClusterName, h.Kind, h.Online, h.WebURL)
	}
	return nil
}
```

For a list page, call `GetLinks` once for the visible records instead of
`LookupHost` per row:

```go
links, err := tc.GetLinks(ctx, tenantID, teleportclient.TargetInventory, hostIDs) // at most 500
```

## grpcurl example

For debugging from a host that holds the SVID of an allowed service (the
certificate, key and trust bundle paths are placeholders):

```bash
grpcurl -cacert bundle.pem -cert svid.pem -key svid-key.pem \
  -import-path api/proto -proto teleport/v1/access.proto \
  -d '{"tenant_id": "018f3a2b-0000-7000-8000-0000000000aa", "hostname": "web-01.example.com"}' \
  teleport.mesh.example.com:<grpc-port> teleport.v1.Access/LookupHost
```

```json
{
  "hosts": [{
    "clusterId": "018f3a2b-0000-7000-8000-000000000001",
    "clusterName": "teleport.example.com",
    "resourceName": "<host-id>",
    "online": true,
    "lastSeen": "2026-11-20T10:00:00Z",
    "webUrl": "https://teleport.example.com/...",
    "resourceId": "018f3a2b-0000-7000-8000-0000000000b7",
    "kind": "node"
  }]
}
```

## Errors

The status message holds only a stable reason. The Go client turns the
code into a sentinel error:

| gRPC code | Client error | Cause |
|---|---|---|
| `PermissionDenied`, `Unauthenticated` | `ErrPermissionDenied` | The caller is not inventory, asset or portal |
| `InvalidArgument` | `ErrInvalid` | A bad `tenant_id`, both or neither of `hostname`/`ip`, a bad module, or too many ids |
| `NotFound` | `ErrNotFound` | Nothing by that reference |
| `Unavailable`, `DeadlineExceeded` | `ErrUnavailable` | The module or its database is unavailable; treat it as "unknown", not "not reachable" |
| other | `ErrFailed` | Anything else |

## Status

The API is served, but no module calls it yet. The reverse direction, where
the Teleport module asks inventory and asset for a host by name or address,
does not exist yet. That is why automatic linking is unavailable. See
[known limitations](../known-limitations.md).
