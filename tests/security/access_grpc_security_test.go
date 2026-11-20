package security

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra/v4/authn"
	"github.com/go-tangra/go-tangra/v4/identity"

	teleportv1 "github.com/go-tangra/go-tangra-teleport/v4/api/proto/teleport/v1"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/grpcapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/resources"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

func asPeer(svc string) context.Context {
	if svc == "" {
		return authn.WithPeer(context.Background(), authn.PeerIdentity{})
	}
	return authn.WithPeer(context.Background(), authn.PeerIdentity{ID: identity.ForService("example.org", svc), ServiceName: svc})
}

// teleport.v1.Access (SR-001, contracts/grpc.md): an unlisted SVID is
// denied before anything is read; answers are scoped to the named tenant;
// malformed hostnames and IPs are refused.
func TestAccessGRPCRefusals(t *testing.T) {
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	e.Teleport.Resources = []teleportapi.Resource{{Kind: teleportapi.KindNode, Name: "n1", Hostname: "web-1", Addr: "10.0.0.5:3022"}}
	rs := &resources.Service{Clusters: e.Service, Repo: e.Repo, Now: e.Now}
	if _, err := rs.List(ct.As(ct.TenantA, ct.Viewer), c.ID, resources.ListInput{}); err != nil {
		t.Fatal(err)
	}
	srv := &grpcapi.AccessServer{}
	grpcapi.Register(registrar{func(s any) { srv = s.(*grpcapi.AccessServer) }}, grpcapi.Deps{Resources: rs, Audit: e.Audit})

	code := func(err error) codes.Code { return status.Code(err) }
	for _, svc := range []string{"billing", "teleport", "", "inventory-evil"} {
		if _, err := srv.LookupHost(asPeer(svc), &teleportv1.LookupHostRequest{TenantId: ct.TenantA, Hostname: "web-1"}); code(err) != codes.PermissionDenied {
			t.Errorf("%q: %v", svc, err)
		}
	}
	if _, err := srv.LookupHost(context.Background(), &teleportv1.LookupHostRequest{TenantId: ct.TenantA, Hostname: "web-1"}); code(err) != codes.PermissionDenied {
		t.Errorf("no peer: %v", err)
	}
	inv := asPeer("inventory")
	if r, err := srv.LookupHost(inv, &teleportv1.LookupHostRequest{TenantId: ct.TenantA, Hostname: "web-1"}); err != nil || len(r.GetHosts()) != 1 {
		t.Fatalf("own tenant: %v %v", r, err)
	}
	if r, err := srv.LookupHost(inv, &teleportv1.LookupHostRequest{TenantId: ct.TenantB, Hostname: "web-1"}); err != nil || len(r.GetHosts()) != 0 {
		t.Fatalf("other tenant sees %v %v", r, err)
	}
	for _, req := range []*teleportv1.LookupHostRequest{
		{TenantId: ct.TenantA, Hostname: "web_1"}, {TenantId: ct.TenantA, Hostname: "-web"}, {TenantId: ct.TenantA, Hostname: string(make([]byte, 300))},
		{TenantId: ct.TenantA, Hostname: "web-1%00"}, {TenantId: ct.TenantA, Ip: "10.0.0.256"}, {TenantId: ct.TenantA, Ip: "fe80::1%eth0"},
		{TenantId: ct.TenantA, Ip: "10.0.0.5/32"}, {TenantId: "'; drop", Hostname: "web-1"},
	} {
		if _, err := srv.LookupHost(inv, req); code(err) != codes.InvalidArgument {
			t.Errorf("%+v: %v", req, err)
		}
	}
	if _, err := srv.GetLinks(inv, &teleportv1.GetLinksRequest{TenantId: ct.TenantA, TargetModule: "asset", TargetIds: make([]string, 501)}); code(err) != codes.InvalidArgument {
		t.Errorf("501 ids: %v", err)
	}
}

type registrar struct{ f func(any) }

func (r registrar) RegisterService(_ *grpc.ServiceDesc, impl any) { r.f(impl) }
