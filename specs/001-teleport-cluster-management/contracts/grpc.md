# Contract: Mesh gRPC API (`teleport.v1`)

- **Source**: `api/proto/teleport/v1/*.proto` (buf).
- **Typed client**: `pkg/teleportclient` (as dns-v4 `pkg/dnsclient`; a separate `sdk/` module is deferred, see plan.md deviations).
- **Transport**: SPIFFE mTLS only, authorized by `deploy/policy.yaml` (deny by default).
- **Tenant scoping**: every request names its tenant in a `tenant_id` field (uuid; the dns-v4 pattern). The caller is admitted by its verified SPIFFE service name first, then acts as a module subject of that tenant (`resources:read` only), scoped by RLS.

## `teleport.v1.Access` (read-only, for other modules)

Lets inventory, asset and portal show "reachable through Teleport" for a host.

```proto
service Access {
  // Hosts enrolled in any of the tenant's clusters that match a hostname or IP.
  rpc LookupHost(LookupHostRequest) returns (LookupHostResponse);
  // Teleport reachability for records the caller owns, in bulk (≤ 500 ids).
  rpc GetLinks(GetLinksRequest) returns (GetLinksResponse);
}

message LookupHostRequest  { string tenant_id = 1; string hostname = 2; string ip = 3; } // exactly one of hostname/ip; validated
message HostAccess         { string cluster_id = 1; string cluster_name = 2;
                             string resource_name = 3; bool online = 4;
                             google.protobuf.Timestamp last_seen = 5;
                             string web_url = 6;                            // deep link to the proxy UI
                             string resource_id = 7; string kind = 8; }
message LookupHostResponse { repeated HostAccess hosts = 1; }
message GetLinksRequest    { string tenant_id = 1; string target_module = 2; repeated string target_ids = 3; } // 1–500 ids
message GetLinksResponse   { map<string, HostAccess> by_target_id = 1; }
```

Policy: callers `svc/inventory`, `svc/asset` and `svc/portal` may call `Access/*`. Every other caller is denied (`PermissionDenied`, audited as `teleport.access.refused`), and the handler re-checks the same list. Errors carry only a stable reason (`invalid_<field>`, `forbidden`, `not_found`, `temporarily_unavailable`). `GetLinks` returns auto and confirmed links only (not candidates), preferring an online resource.

## `scheduler.v1.TaskExecutor` (served, called by the scheduler)

The module serves this through `sdktask.NewServer`. Only `svc/scheduler` may call it. The task types are listed in [events-and-tasks.md](./events-and-tasks.md).

## Outbound gRPC used by this module

| Peer | Calls | Purpose |
|---|---|---|
| auth | token verify, `Authorization/Check`, membership/role reads | Authorization; re-verification of membership events (SR-006) |
| portal gateway | `gatewayclient` lease | Registration, manifest, helpdocs digest |
| lcm | SVID | Mesh identity |
| warden | secret put/get/delete in the module folder | Management credentials |
| notification | send | Alerts, invites |
| scheduler | `Registrar` | Periodic tasks |
| inventory / asset | host lookup (read) | Resource links (research D11) |

Peers are dialled lazily. If a peer is unavailable, only the features that need it are reported as unavailable (FR-034).
