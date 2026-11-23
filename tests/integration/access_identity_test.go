//go:build integration

package integration

// Spec 005 end to end against Teleport 18 (T015): the cluster is registered
// with a tctl auth sign management identity, as in production. Uploading a
// tctl auth sign identity as the access identity is refused and stores
// nothing; the documented tsh login identity of tangra-access is verified
// (including a 1-minute dry issuance for the managed user) and stored; a
// portal terminal opened through access.Service and the terminal hub runs a
// command on the node; removing the access identity leaves brokered access
// with access_identity_missing (the management identity cannot impersonate).
// Run with:
//
//	go test -tags integration ./tests/integration/ -run AccessIdentity

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/access"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/terminal"
)

func TestAccessIdentityTeleport(t *testing.T) {
	ctx := context.Background()
	bc := startBrokeredCluster(t)

	st, sec := memstore.New(), secrets.NewFake()
	limits := teleportapi.Limits{CallTimeout: 15 * time.Second}
	dial := func(ctx context.Context, k teleportapi.Key) (teleportapi.Client, error) {
		ref, err := secrets.ParseRef(k.CredentialRef)
		if err != nil {
			return nil, teleportapi.ErrCredentialInvalid
		}
		id, err := sec.Get(ctx, ref)
		if err != nil {
			return nil, teleportapi.ErrCredentialInvalid
		}
		return teleportapi.Dial(ctx, teleportapi.DialParams{ProxyAddr: k.ProxyAddr, Identity: id, Guard: bc.guard, Limits: limits})
	}
	pool, accessPool := teleportapi.NewPool(dial), teleportapi.NewPool(dial)
	t.Cleanup(pool.Close)
	t.Cleanup(accessPool.Close)
	aud := &recorder{}
	perms := authz.Static{itAdmin: authz.Permissions, accessTangraUser: []string{authz.AccessTerminal, authz.AccessDownload}}
	cs := &clusters.Service{Repo: st, Secrets: sec, Pool: pool, AccessPool: accessPool, Guard: bc.guard, Limits: limits,
		Authz: &authz.Authorizer{Checker: perms, Clusters: st}, Audit: aud, Events: &events.Recorder{}, Notify: notify.NewFake(),
		Log: slog.New(slog.DiscardHandler)}
	admin := authz.WithSubjects(ctx, authz.User(itTenant, itAdmin, nil))
	cl, err := cs.Register(admin, clusters.RegisterInput{DisplayName: "it", ProxyAddr: bc.proxy, Credential: clusters.NewCredential(bc.signed)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := st.CreateManagedUser(ctx, repo.ManagedUser{ID: store.NewID(), TenantID: itTenant, ClusterID: cl.ID, TangraUserID: accessTangraUser,
		TeleportUsername: "tangra-alice", State: repo.UserActive, AppliedRoles: []string{"it-ssh"}, AppliedLogins: []string{"root"},
		CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	put := func(raw []byte) (clusters.AccessIdentityView, error) {
		return cs.PutAccessIdentity(admin, cl.ID, clusters.AccessIdentityInput{Credential: clusters.NewCredential(raw)})
	}

	// 005 SC-002: a tctl auth sign identity is refused; nothing is stored.
	if _, err := put(bc.accessSigned); !errors.Is(err, clusters.ErrNotSignIn) || clusters.ReasonOf(err) != "access_identity_not_sign_in" {
		t.Fatalf("tctl auth sign identity: %v", err)
	}
	// So is the sign-in management identity: its role may not impersonate.
	if _, err := put(bc.ident); !errors.Is(err, clusters.ErrCannotImpersonate) {
		t.Fatalf("management sign-in identity: %v", err)
	}
	if v, _ := cs.AccessIdentity(admin, cl.ID); v.Configured || sec.Len() != 1 {
		t.Fatalf("stored after refusals: %+v secrets %d", v, sec.Len())
	}

	// The documented tsh login identity is verified and stored.
	v, err := put(bc.access)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if !v.Configured || v.TeleportUser != "tangra-access" || v.State != clusters.AccessStateOK || v.ImpersonationChecked == nil || !*v.ImpersonationChecked {
		t.Fatalf("view %+v", v)
	}

	// 005 SC-003: a portal terminal with certificates issued by the access
	// identity runs a command on the node.
	svc := &access.Service{Clusters: cs, Repo: st, Audit: aud}
	hub := &terminal.Hub{Access: svc}
	t.Cleanup(hub.Shutdown)
	alice := authz.WithSubjects(ctx, authz.User(itTenant, accessTangraUser, nil).WithAMR([]string{"pwd", "otp"}))
	my, err := svc.Mine(alice, cl.ID)
	if err != nil || my.AccessIdentity != clusters.AccessStateOK || my.TeleportUser != "tangra-alice" {
		t.Fatalf("my access %+v %v", my, err)
	}
	nodes, err := svc.Nodes(alice, cl.ID)
	if err != nil || len(nodes) != 1 || nodes[0].Name != bc.nodeID {
		t.Fatalf("nodes %+v %v", nodes, err)
	}
	view, err := hub.Create(alice, cl.ID, teleportapi.ShellRequest{Node: bc.nodeID, Login: "root", Cols: 100, Rows: 30})
	if err != nil {
		t.Fatalf("terminal: %v", err)
	}
	term, err := hub.Output(alice, cl.ID, view.ID)
	if err != nil {
		t.Fatal(err)
	}
	detach := term.Attach()
	defer detach()
	if err := hub.Input(alice, cl.ID, view.ID, []byte("echo ACCESS-$((40+2))-ID\n")); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	var from int64
	deadline := time.After(30 * time.Second)
	for {
		c, changed := term.Read(from)
		out.Write(c.Data)
		from = c.Next
		// The command line echoes the expression; only its result has 42.
		if strings.Contains(out.String(), "ACCESS-42-ID") {
			break
		}
		if c.Ended {
			t.Fatalf("terminal ended (%s): %q", c.Reason, out.String())
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("no output: %q", out.String())
		}
	}
	if err := hub.Close(alice, cl.ID, view.ID); err != nil {
		t.Fatal(err)
	}

	// Without the access identity the management identity is tried, and
	// Teleport refuses it.
	if err := cs.DeleteAccessIdentity(admin, cl.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Download(alice, cl.ID, 0); !errors.Is(err, access.ErrAccessIdentityMissing) {
		t.Fatalf("without an access identity: %v", err)
	}
	if sec.Len() != 1 || accessPool.Len() != 0 {
		t.Fatalf("after removal: secrets %d access pool %d", sec.Len(), accessPool.Len())
	}

	var rows []string
	for _, r := range aud.rows {
		rows = append(rows, r.Action+":"+r.Outcome)
	}
	for _, want := range []string{"teleport.access_identity.upload:failure", "teleport.access_identity.upload:success",
		"teleport.terminal.started:success", "teleport.access_identity.delete:success", "teleport.access.issued:failure"} {
		if !slices.Contains(rows, want) {
			t.Errorf("audit lacks %s: %v", want, rows)
		}
	}
}
