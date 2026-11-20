package security

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	inventoryv1 "github.com/go-tangra/go-tangra-inventory/sdk/v4/api/proto/inventory/v1"

	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/enroll"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/enroll/enrolltest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/grpcapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// inventory.v1.TeleportJoinSource (spec 002): only svc/inventory may render
// join material, only for the enrollment's own tenant and host; the token
// is a working single-use Node token that is never stored or audited.
func TestJoinSourceRefusals(t *testing.T) {
	e := ct.New(t, nil)
	c := e.Register(t, ct.TenantA, "prod")
	e.Teleport.TokenPrefix = "TELEPORT-MARKER-JOIN-" // the redaction scan's sentinel (spec 002 SR-006)
	const host = "a1a1a1a1-1111-7111-8111-111111111111"
	inv := enrolltest.New()
	inv.AddHost(ct.TenantA, &inventoryv1.TeleportJoinTarget{HostId: host, Hostname: "web-1", AgentOnline: true})
	svc := &enroll.Service{Clusters: e.Service, Repo: e.Repo, Inventory: inv.Dial(), Audit: e.Audit, Events: e.Events, Now: e.Now}
	out, err := svc.Create(ct.As(ct.TenantA, ct.Operator), c.ID, enroll.CreateInput{HostIDs: []string{host}})
	if err != nil || len(out.Items) != 1 {
		t.Fatalf("create %+v %v", out, err)
	}
	eid := out.Items[0].ID
	var srv *grpcapi.SourceServer
	grpcapi.Register(registrar{func(s any) {
		if x, ok := s.(*grpcapi.SourceServer); ok {
			srv = x
		}
	}}, grpcapi.Deps{Enroll: svc, Audit: e.Audit})

	req := &inventoryv1.RenderTeleportJoinRequest{TenantId: ct.TenantA, EnrollmentId: eid, HostId: host}
	code := func(err error) codes.Code { return status.Code(err) }
	for _, peer := range []string{"asset", "portal", "teleport", "", "inventory-evil"} {
		if _, err := srv.RenderTeleportJoin(asPeer(peer), req); code(err) != codes.PermissionDenied {
			t.Errorf("%q: %v", peer, err)
		}
	}
	inv1 := asPeer("inventory")
	for _, r := range []*inventoryv1.RenderTeleportJoinRequest{
		{TenantId: ct.TenantB, EnrollmentId: eid, HostId: host},
		{TenantId: ct.TenantA, EnrollmentId: eid, HostId: "a2a2a2a2-2222-7222-8222-222222222222"},
		{TenantId: ct.TenantA, EnrollmentId: "nope", HostId: host},
	} {
		if _, err := srv.RenderTeleportJoin(inv1, r); code(err) != codes.NotFound {
			t.Errorf("%+v: %v", r, err)
		}
	}
	if _, err := srv.RenderTeleportJoin(inv1, &inventoryv1.RenderTeleportJoinRequest{TenantId: "x", EnrollmentId: eid, HostId: host}); code(err) != codes.InvalidArgument {
		t.Errorf("bad tenant: %v", err)
	}
	m, err := srv.RenderTeleportJoin(inv1, req)
	if err != nil || !strings.HasPrefix(m.GetToken(), "TELEPORT-MARKER-JOIN-") || len(m.GetCaPins()) != 1 || m.GetEnrollmentId() != eid || m.GetLabels()["tangra.io/hostname"] != "web-1" {
		t.Fatalf("render %v %v", m, err)
	}
	if err := e.Teleport.Join(m.GetToken(), teleportapi.RoleNode, e.Now()); err != nil {
		t.Fatalf("token does not join: %v", err)
	}
	// The token never reaches the audit trail or the store.
	e.Audit.Flush(t.Context())
	for _, row := range e.AuditRows() {
		if strings.Contains(row, m.GetToken()) {
			t.Fatalf("audit carries the token: %s", row)
		}
	}
	toks, _ := e.Repo.ListJoinTokens(t.Context(), ct.TenantA, c.ID)
	for _, tk := range toks {
		if strings.Contains(string(tk.TokenHash), m.GetToken()) {
			t.Fatal("token stored")
		}
	}
	unwired := &grpcapi.SourceServer{}
	if _, err := unwired.RenderTeleportJoin(inv1, req); code(err) != codes.Unimplemented {
		t.Fatalf("unwired: %v", err)
	}
}
