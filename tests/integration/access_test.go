//go:build integration

package integration

// Specs 004 and 005 against a real Teleport Community Edition (T025, 005
// T015): the documented tangra-manager role no longer impersonates (not
// even from a sign-in identity); a `tsh login` identity of tangra-access,
// holding only the documented tangra-access role, impersonates a managed
// user (labelled tangra.io/managed=true) and Teleport itself refuses the
// local administrator and any tctl auth sign identity; a shell opened
// through the proxy with the impersonated certificates runs a command on the
// container's own node, and Teleport lists the session under the managed
// user. Run with:
//
//	go test -tags integration ./tests/integration/ -run Brokered

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	tclient "github.com/gravitational/teleport/api/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/access"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

const accessTangraUser = "99999999-9999-7999-8999-999999999999"

// brokeredCluster is a Teleport 18 container with an SSH node, the
// documented management and access roles, a local administrator and one
// managed user (it-ssh role: login root).
type brokeredCluster struct {
	c            testcontainers.Container
	proxy        string
	guard        *netguard.Guard
	ident        []byte             // tangra-mgmt by sign-in
	signed       []byte             // tangra-mgmt by tctl auth sign (impersonated), as in production
	access       []byte             // tangra-access by tsh login (the access identity)
	accessSigned []byte             // tangra-access by tctl auth sign (impersonated)
	client       teleportapi.Client // the management identity (signed)
	nodeID       string
}

// accessTTLMinutes is the documented tsh login --ttl of the access identity
// (one year, the tangra-access role's max_session_ttl).
const accessTTLMinutes = 525600

// accessRoleYAML extracts the tangra-access role from its help page, so the
// documented role is the one the test proves.
func accessRoleYAML(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../docs/help/reference/tangra-access-role.md"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)```yaml\n(kind: role.*?)```").FindSubmatch(raw)
	if m == nil {
		t.Fatal("role YAML block not found in the help page")
	}
	return string(m[1])
}

func startBrokeredCluster(t *testing.T) *brokeredCluster {
	t.Helper()
	ctx := context.Background()
	image := os.Getenv("TELEPORT_IT_SSH_IMAGE")
	if image == "" {
		image = "public.ecr.aws/gravitational/teleport-distroless-debug:18"
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:      image,
			Entrypoint: []string{"teleport", "start", "-c", "/etc/teleport/teleport.yaml"},
			Env:        map[string]string{"PATH": "/usr/local/bin:/usr/bin:/bin:/busybox"},
			Files: []testcontainers.ContainerFile{
				{Reader: strings.NewReader(brokeredConfig), ContainerFilePath: "/etc/teleport/teleport.yaml", FileMode: 0o644},
				{Reader: strings.NewReader(roleYAML(t)), ContainerFilePath: "/etc/teleport/tangra-manager-role.yaml", FileMode: 0o644},
				{Reader: strings.NewReader(accessRoleYAML(t)), ContainerFilePath: "/etc/teleport/tangra-access-role.yaml", FileMode: 0o644},
				{Reader: strings.NewReader(playerRole), ContainerFilePath: "/etc/teleport/it-ssh-role.yaml", FileMode: 0o644},
				{Reader: strings.NewReader(passwd), ContainerFilePath: "/etc/passwd", FileMode: 0o644},
			},
			WaitingFor: wait.ForLog(teleportReady).WithStartupTimeout(3 * time.Minute),
		}, Started: true,
	})
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	tctl(t, ctx, c, "create", "-f", "/etc/teleport/tangra-manager-role.yaml")
	// Applying the role again is idempotent (FR-018).
	tctl(t, ctx, c, "create", "-f", "/etc/teleport/tangra-manager-role.yaml")
	tctl(t, ctx, c, "create", "-f", "/etc/teleport/tangra-access-role.yaml")
	tctl(t, ctx, c, "create", "-f", "/etc/teleport/it-ssh-role.yaml")
	tctl(t, ctx, c, "users", "add", "admin", "--roles=editor,access", "--logins=root")
	tctl(t, ctx, c, "auth", "sign", "--user=admin", "--format=file", "--ttl=2h", "--out=/tmp/admin.identity", "--overwrite")
	if !eventually(60*time.Second, func() bool { return strings.Contains(tctlOut(t, ctx, c, "nodes", "ls"), "it") }) {
		t.Fatal("the node never registered")
	}
	ip, err := c.ContainerIP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proxy := ip + ":3080"
	guard, err := netguard.New(netguard.Policy{AllowedPrivate: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")}})
	if err != nil {
		t.Fatal(err)
	}
	admin := copyOut(t, ctx, c, "/tmp/admin.identity")
	ident := signInIdentity(t, ctx, c, guard, proxy, "tangra-mgmt", "tangra-manager", admin)
	tctl(t, ctx, c, "auth", "sign", "--user=tangra-mgmt", "--format=file", "--ttl=2h", "--out=/tmp/tangra-mgmt.identity", "--overwrite")
	signed := copyOut(t, ctx, c, "/tmp/tangra-mgmt.identity")
	// The access identity as the bootstrap documents it: tctl users add
	// tangra-access --roles=tangra-access, the invite (password + TOTP),
	// then tsh login --format=file --out.
	si := signIn(t, ctx, c, guard, proxy, "tangra-access", "tangra-access", admin, time.Hour)
	access := tshLogin(t, ctx, c, si, "tangra-access", accessTTLMinutes)
	tctl(t, ctx, c, "auth", "sign", "--user=tangra-access", "--format=file", "--ttl=2h", "--out=/tmp/tangra-access-signed.identity", "--overwrite")
	accessSigned := copyOut(t, ctx, c, "/tmp/tangra-access-signed.identity")
	cl, err := teleportapi.Dial(ctx, teleportapi.DialParams{ProxyAddr: proxy, Identity: secrets.NewSecret(signed), Guard: guard,
		Limits: teleportapi.Limits{CallTimeout: 15 * time.Second}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	// The managed user, as provisioning creates it.
	if _, err := cl.CreateUser(ctx, teleportapi.UserSpec{Name: "tangra-alice", Roles: []string{"it-ssh"}, Logins: []string{"root"},
		Labels: map[string]string{"tangra.io/managed": "true", "tangra.io/tenant": itTenant, "tangra.io/user": accessTangraUser}}); err != nil {
		t.Fatalf("create managed user: %v", err)
	}
	nodes, err := cl.ListResources(ctx, teleportapi.KindNode, teleportapi.ListOptions{})
	if err != nil || len(nodes.Items) == 0 {
		t.Fatalf("nodes %+v %v", nodes, err)
	}
	return &brokeredCluster{c: c, proxy: proxy, guard: guard, ident: ident, signed: signed, access: access, accessSigned: accessSigned,
		client: cl, nodeID: nodes.Items[0].Name}
}

// readUntil reads r until want appears or d passes.
func readUntil(t *testing.T, r io.Reader, want string, d time.Duration) string {
	t.Helper()
	var out bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for !strings.Contains(out.String(), want) {
			n, err := r.Read(buf)
			out.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("no %q within %v: %q", want, d, out.String())
	}
	return out.String()
}

// dialIdentity connects with an identity file (closed with the test).
func (bc *brokeredCluster) dialIdentity(t *testing.T, raw []byte) teleportapi.Client {
	t.Helper()
	cl, err := teleportapi.Dial(context.Background(), teleportapi.DialParams{ProxyAddr: bc.proxy, Identity: secrets.NewSecret(raw), Guard: bc.guard,
		Limits: teleportapi.Limits{CallTimeout: 15 * time.Second}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	return cl
}

func TestBrokeredAccessTeleport(t *testing.T) {
	ctx := context.Background()
	bc := startBrokeredCluster(t)
	cl := bc.client // management (tctl auth sign)

	// 005 SC-001: the management role no longer impersonates, neither the
	// production (tctl auth sign) identity nor a sign-in one.
	for name, raw := range map[string][]byte{"tctl auth sign": bc.signed, "sign-in": bc.ident} {
		_, err := bc.dialIdentity(t, raw).IssueUserCerts(ctx, "tangra-alice", time.Hour)
		if !errors.Is(err, teleportapi.ErrAccessDenied) || !strings.Contains(teleportapi.Detail(err), "impersonation is not allowed") {
			t.Fatalf("%s management identity: %v", name, err)
		}
	}
	// A tctl auth sign identity of tangra-access cannot impersonate even
	// with the role: Teleport never lets an impersonated certificate
	// impersonate again (005 SC-002).
	_, err := bc.dialIdentity(t, bc.accessSigned).IssueUserCerts(ctx, "tangra-alice", time.Hour)
	if !errors.Is(err, teleportapi.ErrAccessDenied) || !strings.Contains(teleportapi.Detail(err), "impersonated user") {
		t.Fatalf("tctl auth sign identity of tangra-access: %v", err)
	}

	// The access identity: a sign-in identity (no impersonator) lasting what
	// tsh login asked for, within the role's max_session_ttl.
	meta, err := teleportapi.ParseIdentity(secrets.NewSecret(bc.access))
	if err != nil || meta.Impersonator != "" || meta.Subject != "tangra-access" || meta.ClusterName != itCluster {
		t.Fatalf("access identity %+v %v", meta, err)
	}
	if life := meta.ExpiresAt.Sub(meta.IssuedAt); life < 8759*time.Hour || life > 8761*time.Hour {
		t.Fatalf("tsh login --ttl=%d lifetime %v", accessTTLMinutes, life)
	}
	t.Logf("tsh login --ttl=%d: %v", accessTTLMinutes, meta.ExpiresAt.Sub(meta.IssuedAt))
	acl := bc.dialIdentity(t, bc.access)
	// Least privilege: it reads nothing.
	if _, err := acl.GetUser(ctx, "tangra-alice"); !errors.Is(err, teleportapi.ErrAccessDenied) {
		t.Fatalf("access identity read a user: %v", err)
	}
	if _, err := acl.ListLocks(ctx); !errors.Is(err, teleportapi.ErrAccessDenied) {
		t.Fatalf("access identity listed locks: %v", err)
	}

	// Teleport itself refuses to impersonate a local user (SC-003, US5-1).
	if _, err := acl.IssueUserCerts(ctx, "admin", time.Hour); !errors.Is(err, teleportapi.ErrAccessDenied) {
		t.Fatalf("local admin impersonated: %v", err)
	}

	certs, err := acl.IssueUserCerts(ctx, "tangra-alice", time.Hour)
	if err != nil {
		t.Fatalf("impersonate managed user: %v", err)
	}
	defer certs.Drop()
	if certs.User != "tangra-alice" || !strings.Contains(strings.Join(certs.Logins, ","), "root") {
		t.Fatalf("certs %v logins %v", certs, certs.Logins)
	}
	if d := time.Until(certs.Expires); d <= 50*time.Minute || d > 61*time.Minute {
		t.Fatalf("lifetime %v", d)
	}
	t.Logf("8 h request: %v", func() time.Duration {
		long, err := acl.IssueUserCerts(ctx, "tangra-alice", 8*time.Hour)
		if err != nil {
			t.Fatalf("8 h: %v", err)
		}
		defer long.Drop()
		return time.Until(long.Expires).Round(time.Minute)
	}())

	// The downloaded identity file works with the Teleport client library as
	// the managed user (what tsh -i does), verifying the proxy against the
	// host CA it carries.
	file, err := access.EncodeIdentity(certs)
	if err != nil {
		t.Fatal(err)
	}
	pinned := bc.guard.Dialer(bc.proxy)
	asUser, err := tclient.New(ctx, tclient.Config{
		Dialer:                     tclient.ContextDialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) { return pinned(ctx, network, bc.proxy) }),
		Credentials:                []tclient.Credentials{tclient.LoadIdentityFileFromString(string(file.Reveal()))},
		ALPNSNIAuthDialClusterName: itCluster,
	})
	file.Wipe()
	if err != nil {
		t.Fatalf("identity file client: %v", err)
	}
	ping, err := asUser.Ping(ctx)
	_ = asUser.Close()
	if err != nil || ping.ClusterName != itCluster {
		t.Fatalf("ping as the user: %+v %v", ping, err)
	}

	nodes, err := cl.ListNodesAs(ctx, certs)
	if err != nil || len(nodes) != 1 || nodes[0].Name != bc.nodeID {
		t.Fatalf("nodes as the user: %+v %v", nodes, err)
	}

	// A login the user does not hold is refused by the node.
	if sh, err := cl.OpenShell(ctx, certs, teleportapi.ShellRequest{Node: bc.nodeID, Login: "nobody", Cols: 80, Rows: 24}); err == nil {
		_ = sh.Close()
		t.Fatal("login nobody accepted")
	}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sh, err := cl.OpenShell(sctx, certs, teleportapi.ShellRequest{Node: bc.nodeID, Login: "root", Cols: 100, Rows: 30})
	if err != nil {
		t.Fatalf("open shell: %v", err)
	}
	if _, err := sh.Write([]byte("echo BROKER-$((40+2))-OK\n")); err != nil {
		t.Fatal(err)
	}
	readUntil(t, sh.Output(), "BROKER-42-OK", 30*time.Second)
	if err := sh.Resize(120, 40); err != nil {
		t.Fatalf("resize: %v", err)
	}
	go func() { _, _ = io.Copy(io.Discard, sh.Output()) }() // keep the output flowing, as the terminal hub does
	if _, err := sh.Write([]byte("exit\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sh.Done():
	case <-time.After(30 * time.Second):
		t.Fatal("shell did not end on exit")
	}
	_ = sh.Close()

	// Teleport records the session under the managed user (FR-007, SC-004).
	if !eventually(2*time.Minute, func() bool {
		now := time.Now().UTC()
		p, err := cl.SearchSessions(ctx, teleportapi.EventQuery{From: now.Add(-time.Hour), To: now.Add(time.Minute), Limit: 50})
		if err != nil {
			t.Logf("sessions: %v", err)
			return false
		}
		for _, e := range p.Items {
			var f struct {
				User string `json:"user"`
			}
			if json.Unmarshal(e.Raw, &f) == nil && f.User == "tangra-alice" {
				return true
			}
		}
		return false
	}) {
		t.Fatal("the session is not listed under tangra-alice")
	}
}
