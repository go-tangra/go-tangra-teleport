package terminal_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/trace"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/access"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/terminal"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/users"
)

const (
	alice = "aaaaaaaa-aaaa-7aaa-8aaa-aaaaaaaaaaaa"
	bob   = "bbbbbbbb-bbbb-7bbb-8bbb-bbbbbbbbbbbb"
)

type env struct {
	*ct.Env
	hub     *terminal.Hub
	cluster string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{Env: ct.New(t, nil)}
	e.cluster = e.Register(t, ct.TenantA, "prod").ID
	for _, u := range []string{alice, bob} {
		e.Perms[u] = []string{authz.AccessTerminal}
		name := "tangra-" + u[:1]
		if err := e.Repo.CreateManagedUser(context.Background(), repo.ManagedUser{ID: store.NewID(), TenantID: ct.TenantA, ClusterID: e.cluster,
			TangraUserID: u, TeleportUsername: name, State: repo.UserActive, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		e.Teleport.Users = append(e.Teleport.Users, teleportapi.User{Name: name, Roles: []string{"access"}, Logins: []string{"deploy"},
			Labels: map[string]string{users.LabelManaged: "true", users.LabelTenant: ct.TenantA, users.LabelUser: u}})
	}
	e.Teleport.Resources = append(e.Teleport.Resources, teleportapi.Resource{Kind: teleportapi.KindNode, Name: "node-1", Hostname: "web-1"})
	e.hub = &terminal.Hub{Access: &access.Service{Clusters: e.Service, Repo: e.Repo, Audit: e.Audit, Now: e.Now}, Now: e.Now}
	t.Cleanup(e.hub.Shutdown)
	return e
}

func as(user string) context.Context {
	return authz.WithSubjects(context.Background(), authz.User(ct.TenantA, user, nil).WithAMR([]string{"otp"}))
}

var req = teleportapi.ShellRequest{Node: "node-1", Login: "deploy", Cols: 80, Rows: 24}

func (e *env) open(t *testing.T, user string) terminal.View {
	t.Helper()
	v, err := e.hub.Create(as(user), e.cluster, req)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// readUntil reads the terminal's output from offset 0 until want appears.
func readUntil(t *testing.T, tm *terminal.Terminal, want string) terminal.Chunk {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		c, ch := tm.Read(0)
		if strings.Contains(string(c.Data), want) {
			return c
		}
		select {
		case <-ch:
		case <-deadline:
			t.Fatalf("no %q in %q", want, c.Data)
		}
	}
}

func waitEnded(t *testing.T, tm *terminal.Terminal) terminal.Chunk {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		c, ch := tm.Read(0)
		if c.Ended {
			return c
		}
		select {
		case <-ch:
		case <-deadline:
			t.Fatal("terminal did not end")
		}
	}
}

func endRow(t *testing.T, e *env) map[string]any {
	t.Helper()
	e.Audit.Flush(context.Background())
	for _, r := range e.Repo.Audit() {
		if r.Action == string(audit.TerminalEnded) {
			return r.Detail
		}
	}
	t.Fatal("no end row")
	return nil
}

func TestTerminalRunsAsTheOwnerAndIsPrivate(t *testing.T) {
	e := newEnv(t)
	v := e.open(t, alice)
	if v.TeleportUser != "tangra-a" || v.Node != "node-1" || len(v.ID) != 32 {
		t.Fatalf("view %+v", v)
	}
	sh := e.Teleport.Shells()[0]
	if sh.User != "tangra-a" || sh.Login != "deploy" {
		t.Fatalf("shell %+v", sh)
	}
	tm, err := e.hub.Output(as(alice), e.cluster, v.ID)
	if err != nil {
		t.Fatal(err)
	}
	detach := tm.Attach()
	defer detach()
	if err := e.hub.Input(as(alice), e.cluster, v.ID, []byte("echo hi\n")); err != nil {
		t.Fatal(err)
	}
	c := readUntil(t, tm, "echo hi")
	if c.From != 0 || c.Next != int64(len(c.Data)) {
		t.Fatalf("chunk %+v", c)
	}
	// Resume from an offset.
	c2, _ := tm.Read(c.Next - 3)
	if string(c2.Data) != string(c.Data[len(c.Data)-3:]) {
		t.Fatalf("resume %q", c2.Data)
	}
	if err := e.hub.Resize(as(alice), e.cluster, v.ID, 120, 40); err != nil || sh.Sizes()[len(sh.Sizes())-1] != [2]int{120, 40} {
		t.Fatalf("resize %v %v", err, sh.Sizes())
	}
	// Bob, and alice on another cluster id, see nothing.
	for _, ctx := range []context.Context{as(bob), authz.WithSubjects(context.Background(), authz.User(ct.TenantB, alice, nil))} {
		if _, err := e.hub.Output(ctx, e.cluster, v.ID); !errors.Is(err, terminal.ErrNotFound) && !errors.Is(err, authz.ErrForbidden) {
			t.Fatalf("other caller: %v", err)
		}
		if err := e.hub.Close(ctx, e.cluster, v.ID); err == nil {
			t.Fatal("other caller closed it")
		}
	}
	if _, err := e.hub.Output(as(alice), "018f3a2b-0000-7000-8000-0000000000ff", v.ID); !errors.Is(err, terminal.ErrNotFound) {
		t.Fatalf("other cluster: %v", err)
	}
	if err := e.hub.Input(as(alice), e.cluster, v.ID, make([]byte, terminal.MaxInputBytes+1)); !errors.Is(err, terminal.ErrInputTooBig) {
		t.Fatalf("big input: %v", err)
	}
	if err := e.hub.Close(as(alice), e.cluster, v.ID); err != nil {
		t.Fatal(err)
	}
	if c := waitEnded(t, tm); c.Reason != terminal.EndClosed || !sh.Closed() {
		t.Fatalf("end %+v", c)
	}
	if err := e.hub.Input(as(alice), e.cluster, v.ID, []byte("x")); !errors.Is(err, terminal.ErrEnded) {
		t.Fatalf("input after end: %v", err)
	}
	d := endRow(t, e)
	if d["end_reason"] != terminal.EndClosed || d["node"] != "node-1" || d["login"] != "deploy" || d["teleport_user"] != "tangra-a" {
		t.Fatalf("end row %v", d)
	}
	// No terminal content in audit rows.
	all, _ := json.Marshal(e.Repo.Audit())
	if bytes.Contains(all, []byte("echo hi")) {
		t.Fatal("terminal content audited")
	}
}

func TestLimitsAndRefusals(t *testing.T) {
	e := newEnv(t)
	for range terminal.MaxPerUser {
		e.open(t, alice)
	}
	if _, err := e.hub.Create(as(alice), e.cluster, req); !errors.Is(err, terminal.ErrTooMany) {
		t.Fatalf("6th: %v", err)
	}
	e.open(t, bob)
	e.hub.MaxTotal = 6
	if _, err := e.hub.Create(as(bob), e.cluster, req); !errors.Is(err, terminal.ErrTooMany) {
		t.Fatalf("total: %v", err)
	}
	e.hub.MaxTotal = 0
	bad := req
	bad.Login = "root"
	if _, err := e.hub.Create(as(bob), e.cluster, bad); !errors.Is(err, terminal.ErrLogin) {
		t.Fatalf("login: %v", err)
	}
	pwd := authz.WithSubjects(context.Background(), authz.User(ct.TenantA, bob, nil))
	if _, err := e.hub.Create(pwd, e.cluster, req); !errors.Is(err, access.ErrMFARequired) {
		t.Fatalf("no mfa: %v", err)
	}
	if e.hub.Count() != 6 {
		t.Fatalf("count %d", e.hub.Count())
	}
	e.Audit.Flush(context.Background())
	fails := 0
	for _, r := range e.Repo.Audit() {
		if r.Action == string(audit.TerminalStarted) && r.Outcome == audit.OutcomeFailure {
			fails++
		}
	}
	if fails != 4 {
		t.Fatalf("failure rows %d", fails)
	}
}

func TestTimeouts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		step   func(e *env, tm *terminal.Terminal, id string)
		reason string
	}{
		{"reader gone", func(e *env, tm *terminal.Terminal, _ string) { e.Advance(terminal.ReaderGrace) }, terminal.EndReaderGone},
		{"reader attached", func(e *env, tm *terminal.Terminal, id string) {
			tm.Attach()
			e.Advance(2 * time.Minute)
			_ = e.hub.Keepalive(as(alice), e.cluster, id)
			e.hub.Sweep()
			if c, _ := tm.Read(0); c.Ended {
				panic("ended while attached and kept alive")
			}
			e.Advance(terminal.KeepaliveGrace)
		}, terminal.EndKeepalive},
		{"max", func(e *env, tm *terminal.Terminal, id string) {
			tm.Attach()
			for range 8 * 60 / 2 {
				e.Advance(2 * time.Minute)
				_ = e.hub.Keepalive(as(alice), e.cluster, id)
			}
		}, terminal.EndMaxTime},
		{"exit", func(e *env, tm *terminal.Terminal, _ string) { e.Teleport.Shells()[0].Exit(nil) }, terminal.EndExit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			v := e.open(t, alice)
			tm, _ := e.hub.Output(as(alice), e.cluster, v.ID)
			tc.step(e, tm, v.ID)
			e.hub.Sweep()
			if c := waitEnded(t, tm); c.Reason != tc.reason {
				t.Fatalf("reason %q", c.Reason)
			}
			if !e.Teleport.Shells()[0].Closed() {
				t.Fatal("shell not closed")
			}
			// Forgotten after the retention.
			e.Advance(terminal.EndedRetention)
			e.hub.Sweep()
			if _, err := e.hub.Output(as(alice), e.cluster, v.ID); !errors.Is(err, terminal.ErrNotFound) {
				t.Fatalf("kept: %v", err)
			}
		})
	}
}

func TestCertificateExpiryEnds(t *testing.T) {
	e := newEnv(t)
	if _, err := e.hub.Access.PutSettings(authz.WithSubjects(context.Background(), authz.User(ct.TenantA, ct.Admin, nil)), e.cluster, 15); err != nil {
		t.Fatal(err)
	}
	v := e.open(t, alice)
	if d := v.ExpiresAt.Sub(v.StartedAt); d > 16*time.Minute {
		t.Fatalf("expires after %v", d)
	}
	tm, _ := e.hub.Output(as(alice), e.cluster, v.ID)
	tm.Attach()
	e.Advance(16 * time.Minute)
	_ = e.hub.Keepalive(as(alice), e.cluster, v.ID)
	e.hub.Sweep()
	if c := waitEnded(t, tm); c.Reason != terminal.EndExpired {
		t.Fatalf("reason %q", c.Reason)
	}
}

// R7: the watchdog ends terminals whose access was revoked, and keeps them
// through transient failures.
func TestWatchdog(t *testing.T) {
	e := newEnv(t)
	va, vb := e.open(t, alice), e.open(t, bob)
	ta, _ := e.hub.Output(as(alice), e.cluster, va.ID)
	tb, _ := e.hub.Output(as(bob), e.cluster, vb.ID)
	e.Teleport.FailNext("GetUser", trace.ConnectionProblem(nil, "unreachable"))
	e.hub.Watch(context.Background())
	if c, _ := ta.Read(0); c.Ended {
		t.Fatal("ended on a transient failure")
	}
	e.Teleport.Locks = []teleportapi.Lock{{Name: "l", TargetKind: "user", Target: "tangra-a"}}
	e.hub.Watch(context.Background())
	if c := waitEnded(t, ta); c.Reason != terminal.EndRevoked {
		t.Fatalf("locked: %q", c.Reason)
	}
	if c, _ := tb.Read(0); c.Ended {
		t.Fatal("bob ended")
	}
	e.Perms[bob] = nil
	e.hub.Watch(context.Background())
	if c := waitEnded(t, tb); c.Reason != terminal.EndRevoked {
		t.Fatalf("permission: %q", c.Reason)
	}
}

func TestShutdownEndsAll(t *testing.T) {
	e := newEnv(t)
	v := e.open(t, alice)
	tm, _ := e.hub.Output(as(alice), e.cluster, v.ID)
	e.hub.Shutdown()
	if c := waitEnded(t, tm); c.Reason != terminal.EndShutdown {
		t.Fatalf("reason %q", c.Reason)
	}
	if _, err := e.hub.Create(as(alice), e.cluster, req); err == nil {
		t.Fatal("created after shutdown")
	}
}

func TestRingKeepsTheTail(t *testing.T) {
	e := newEnv(t)
	v := e.open(t, alice)
	tm, _ := e.hub.Output(as(alice), e.cluster, v.ID)
	sh := e.Teleport.Shells()[0]
	chunk := strings.Repeat("x", 64<<10)
	for range 5 {
		sh.Print(chunk)
	}
	sh.Print("END")
	c := readUntil(t, tm, "END")
	if !c.Gap || c.From == 0 || len(c.Data) > terminal.RingBytes || c.Next-c.From != int64(len(c.Data)) {
		t.Fatalf("from %d next %d len %d gap %v", c.From, c.Next, len(c.Data), c.Gap)
	}
}
