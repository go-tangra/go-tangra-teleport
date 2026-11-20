package contract

import (
	"context"
	"errors"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/go-tangra/go-tangra/v4/authn"
	"github.com/go-tangra/go-tangra/v4/identity"

	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/grpcapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/resources"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/pkg/teleportclient"
)

// accessClient serves teleport.v1 over an in-memory connection; every call
// arrives as the verified peer svc (what the Freya authn interceptor sets).
func accessClient(t *testing.T, svc string) (*teleportclient.Client, *ct.Env, string) {
	t.Helper()
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	e.Teleport.Resources = []teleportapi.Resource{{Kind: teleportapi.KindNode, Name: "n1", Hostname: "web-1", Addr: "10.0.0.5:3022"}}
	rs := &resources.Service{Clusters: e.Service, Repo: e.Repo, Linker: &resources.Linker{Repo: e.Repo, Directory: resources.UnavailableDirectory{}},
		Audit: e.Audit, Events: e.Events, Now: e.Now}
	page, err := rs.List(ct.As(ct.TenantA, ct.Viewer), c.ID, resources.ListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rs.ConfirmLink(ct.As(ct.TenantA, ct.Admin), c.ID, page.Items[0].ID, resources.LinkInput{TargetModule: repo.TargetAsset, TargetID: "a-1"}); err != nil {
		t.Fatal(err)
	}
	peer := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		return h(authn.WithPeer(ctx, authn.PeerIdentity{ID: identity.ForService("example.org", svc), ServiceName: svc}), req)
	}
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(grpc.UnaryInterceptor(peer))
	grpcapi.Register(gs, grpcapi.Deps{Resources: rs, Audit: e.Audit})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return teleportclient.New(conn), e, c.ID
}

func TestAccessLookupAndLinks(t *testing.T) {
	cl, _, id := accessClient(t, "inventory")
	ctx := context.Background()
	for _, q := range [][2]string{{"web-1", ""}, {"WEB-1.", ""}, {"", "10.0.0.5"}, {"", "::ffff:10.0.0.5"}} {
		hosts, err := cl.LookupHost(ctx, ct.TenantA, q[0], q[1])
		if err != nil || len(hosts) != 1 || hosts[0].ClusterID != id || hosts[0].ResourceName != "n1" || !hosts[0].Online ||
			hosts[0].LastSeen.IsZero() || hosts[0].Kind != repo.KindNode {
			t.Fatalf("lookup %v: %+v %v", q, hosts, err)
		}
	}
	if hosts, err := cl.LookupHost(ctx, ct.TenantB, "web-1", ""); err != nil || len(hosts) != 0 {
		t.Fatalf("other tenant sees %+v %v", hosts, err)
	}
	links, err := cl.GetLinks(ctx, ct.TenantA, teleportclient.TargetAsset, []string{"a-1", "a-2"})
	if err != nil || len(links) != 1 || links["a-1"].ResourceName != "n1" {
		t.Fatalf("links %+v %v", links, err)
	}
	for _, bad := range []func() error{
		func() error { _, err := cl.LookupHost(ctx, ct.TenantA, "", ""); return err },
		func() error { _, err := cl.LookupHost(ctx, ct.TenantA, "web-1", "10.0.0.5"); return err },
		func() error { _, err := cl.LookupHost(ctx, ct.TenantA, "bad_host!", ""); return err },
		func() error { _, err := cl.LookupHost(ctx, ct.TenantA, "", "10.0.0"); return err },
		func() error { _, err := cl.LookupHost(ctx, "not-a-uuid", "web-1", ""); return err },
		func() error { _, err := cl.GetLinks(ctx, ct.TenantA, "cmdb", []string{"x"}); return err },
		func() error { _, err := cl.GetLinks(ctx, ct.TenantA, teleportclient.TargetAsset, nil); return err },
		func() error {
			_, err := cl.GetLinks(ctx, ct.TenantA, teleportclient.TargetAsset, make([]string, 501))
			return err
		},
	} {
		if err := bad(); !errors.Is(err, teleportclient.ErrInvalid) {
			t.Fatalf("invalid request answered %v", err)
		}
	}
}

// Only inventory, asset and portal may call Access; a refusal is audited
// and reveals nothing.
func TestAccessCallerAllowList(t *testing.T) {
	for _, svc := range []string{"portal", "asset"} {
		cl, _, _ := accessClient(t, svc)
		if _, err := cl.LookupHost(context.Background(), ct.TenantA, "web-1", ""); err != nil {
			t.Fatalf("%s refused: %v", svc, err)
		}
	}
	cl, e, _ := accessClient(t, "billing")
	if _, err := cl.LookupHost(context.Background(), ct.TenantA, "web-1", ""); !errors.Is(err, teleportclient.ErrPermissionDenied) {
		t.Fatalf("billing allowed: %v", err)
	}
	if _, err := cl.GetLinks(context.Background(), "bad", teleportclient.TargetAsset, []string{"a-1"}); !errors.Is(err, teleportclient.ErrPermissionDenied) {
		t.Fatalf("refusal must come before validation: %v", err)
	}
	e.Audit.Flush(context.Background())
	refused := 0
	for _, r := range e.Repo.Audit() {
		if r.Action == "teleport.access.refused" && r.TenantID == repo.NilTenant {
			refused++
		}
	}
	if refused != 2 {
		t.Fatalf("%d refusals audited", refused)
	}
}

func TestAccessUnwired(t *testing.T) {
	var s grpcapi.AccessServer
	if _, err := s.LookupHost(context.Background(), nil); err == nil {
		t.Fatal("unwired lookup answered")
	}
	if _, err := s.GetLinks(context.Background(), nil); err == nil {
		t.Fatal("unwired links answered")
	}
	if err := grpcapi.GRPCError(errors.New("boom")); err == nil {
		t.Fatal("nil status")
	}
}
