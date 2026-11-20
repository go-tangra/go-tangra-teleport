package deploy

// T020: the development service-to-service policy of the Teleport module.
// Deny by default; teleport.v1.Access only from inventory, asset and portal;
// the task executor only from the scheduler; the gateway forwards browser
// traffic only. Evaluated with the framework's own policy engine.

import (
	"context"
	"os"
	"testing"

	"github.com/go-tangra/go-tangra/v4/authz"
	"github.com/go-tangra/go-tangra/v4/identity"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/config"
)

func load(t *testing.T) *authz.Policy {
	t.Helper()
	f, err := os.Open("policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	p, err := authz.Load(f)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func allowed(t *testing.T, p *authz.Policy, peer, op string) bool {
	t.Helper()
	id, err := identity.ParseSPIFFEID(peer)
	if err != nil {
		t.Fatal(err)
	}
	return p.Authorize(context.Background(), id, "teleport", op).Allowed
}

const svc = "spiffe://example.org/svc/"

var access = []string{"/teleport.v1.Access/LookupHost", "/teleport.v1.Access/GetLinks"}

func TestAccessOnlyFromInventoryAssetPortal(t *testing.T) {
	p := load(t)
	for _, op := range access {
		for _, peer := range []string{"inventory", "asset", "portal"} {
			if !allowed(t, p, svc+peer, op) {
				t.Errorf("%s refused %s", peer, op)
			}
		}
		for _, peer := range []string{"gateway", "scheduler", "dns", "lcm", "teleport"} {
			if allowed(t, p, svc+peer, op) {
				t.Errorf("%s may call %s", peer, op)
			}
		}
	}
	if allowed(t, p, svc+"inventory", "/teleport.v1.Access/Other") {
		t.Error("inventory may call an undeclared Access method")
	}
	if allowed(t, p, "spiffe://other.org/svc/inventory", access[0]) {
		t.Error("a foreign trust domain is admitted")
	}
}

// Spec 002: only inventory renders an enrollment's join material.
func TestJoinSourceOnlyFromInventory(t *testing.T) {
	p := load(t)
	const op = "/inventory.v1.TeleportJoinSource/RenderTeleportJoin"
	if !allowed(t, p, svc+"inventory", op) {
		t.Fatal("inventory refused")
	}
	for _, peer := range []string{"gateway", "asset", "portal", "scheduler", "lcm", "teleport"} {
		if allowed(t, p, svc+peer, op) {
			t.Errorf("%s may render join material", peer)
		}
	}
	if allowed(t, p, "spiffe://other.org/svc/inventory", op) {
		t.Error("a foreign trust domain is admitted")
	}
}

func TestTaskExecutorOnlyFromScheduler(t *testing.T) {
	p := load(t)
	const op = "/scheduler.v1.TaskExecutor/ExecuteTask"
	if !allowed(t, p, svc+"scheduler", op) {
		t.Fatal("scheduler refused")
	}
	for _, peer := range []string{"gateway", "inventory", "asset", "portal", "lcm"} {
		if allowed(t, p, svc+peer, op) {
			t.Errorf("%s may run tasks", peer)
		}
	}
}

func TestGatewayForwardsHTTPOnly(t *testing.T) {
	p := load(t)
	const gw = svc + "gateway"
	for _, op := range []string{"GET /api/teleport/v1/clusters", "POST /api/teleport/v1/clusters", "DELETE /api/teleport/v1/clusters/x", "GET /ui/remoteEntry.js", "GET /docs/v1/bundle"} {
		if !allowed(t, p, gw, op) {
			t.Errorf("gateway refused %s", op)
		}
	}
	if allowed(t, p, svc+"inventory", "GET /api/teleport/v1/clusters") {
		t.Error("a module may call the browser API")
	}
}

func TestDenyByDefault(t *testing.T) {
	p := load(t)
	for _, c := range [][2]string{
		{"lcm", "/teleport.v1.Other/Do"},
		{"warden", "GET /api/teleport/v1/clusters"},
		{"scheduler", "/teleport.v1.Access/LookupHost"},
		{"portal", "/scheduler.v1.TaskExecutor/ExecuteTask"},
	} {
		if allowed(t, p, svc+c[0], c[1]) {
			t.Errorf("%s may call %s", c[0], c[1])
		}
	}
}

// The shipped container configuration loads and validates.
func TestContainerConfigValid(t *testing.T) {
	c, err := config.Load("container.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.ServiceName != "teleport" || len(c.Teleport.AllowedPrivateNetworks) != 0 {
		t.Fatalf("config %+v", c.Teleport)
	}
}
