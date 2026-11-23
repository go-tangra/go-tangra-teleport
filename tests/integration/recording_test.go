//go:build integration

package integration

// Spec 003 against a real Teleport Community Edition (T024, plan
// Quickstart 2): an SSH session with a terminal is recorded on the
// container's own node, then played through recording.Service page by
// page over the real teleportapi.Dial with the documented tangra-manager
// role. The output relayed must contain what the session printed, in
// order; the first page writes exactly one successful teleport.session.played
// row and the later pages none; the session list marks the session playable.
//
// The node runs a shell, so this test uses the -debug image (busybox) and
// gives root /busybox/sh as its login shell. Override the image with
// TELEPORT_IT_SSH_IMAGE. Run with:
//
//	go test -tags integration ./tests/integration/ -run Recording

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/auditlog"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/memstore"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/recording"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// recordingConfig is teleportConfig with the SSH service on (the node the
// session runs on), recording at the node.
var recordingConfig = strings.Replace(teleportConfig, "ssh_service:\n  enabled: false\n",
	"ssh_service:\n  enabled: true\n  labels: { env: it }\n", 1)

// playerRole lets the session user log in as root on the node.
const playerRole = `kind: role
version: v7
metadata: { name: it-ssh }
spec:
  allow:
    logins: [root]
    node_labels: { '*': '*' }
`

// passwd gives root a shell that exists in the -debug image.
const passwd = "root:x:0:0:root:/root:/busybox/sh\nnobody:x:65534:65534:nobody:/nonexistent:/busybox/false\n"

func TestRecordingPlayback(t *testing.T) {
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
				{Reader: strings.NewReader(recordingConfig), ContainerFilePath: "/etc/teleport/teleport.yaml", FileMode: 0o644},
				{Reader: strings.NewReader(roleYAML(t)), ContainerFilePath: "/etc/teleport/tangra-manager-role.yaml", FileMode: 0o644},
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
	tctl(t, ctx, c, "create", "-f", "/etc/teleport/it-ssh-role.yaml")
	addManager(t, ctx, c)
	tctl(t, ctx, c, "users", "add", "alice", "--roles=it-ssh", "--logins=root")
	tctl(t, ctx, c, "auth", "sign", "--user=tangra-mgmt", "--format=file", "--ttl=2h", "--out=/tmp/tangra-mgmt.identity", "--overwrite")
	tctl(t, ctx, c, "auth", "sign", "--user=alice", "--format=file", "--ttl=1h", "--out=/tmp/alice.identity", "--overwrite")
	identity := copyOut(t, ctx, c, "/tmp/tangra-mgmt.identity")
	if !eventually(60*time.Second, func() bool { return strings.Contains(tctlOut(t, ctx, c, "nodes", "ls"), "it") }) {
		t.Fatal("the node never registered")
	}

	// Record a session with a terminal: three marked lines with pauses, so
	// there are several print events. tsh joins the command words with
	// spaces for root's login shell, so the script is one word.
	script := "echo REC-START-7f3a; /busybox/sleep 2; printf 'REC-%s-7f3a\\n' MIDDLE; /busybox/sleep 1; echo REC-END-7f3a"
	code, out, err := c.Exec(ctx, []string{"tsh", "-i", "/tmp/alice.identity", "--proxy=127.0.0.1:3080", "--insecure",
		"ssh", "-t", "root@it", script})
	if err != nil || code != 0 {
		b, _ := io.ReadAll(out)
		t.Fatalf("tsh ssh: %d %v\n%s", code, err, b)
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
	store, sec := memstore.New(), secrets.NewFake()
	limits := teleportapi.Limits{CallTimeout: 10 * time.Second}
	pool := teleportapi.NewPool(func(ctx context.Context, k teleportapi.Key) (teleportapi.Client, error) {
		ref, err := secrets.ParseRef(k.CredentialRef)
		if err != nil {
			return nil, teleportapi.ErrCredentialInvalid
		}
		id, err := sec.Get(ctx, ref)
		if err != nil {
			return nil, teleportapi.ErrCredentialInvalid
		}
		return teleportapi.Dial(ctx, teleportapi.DialParams{ProxyAddr: proxy, Identity: id, Guard: guard, Limits: limits})
	})
	t.Cleanup(pool.Close)
	aud := &recorder{}
	cs := &clusters.Service{Repo: store, Secrets: sec, Pool: pool, Guard: guard, Limits: limits,
		Authz: &authz.Authorizer{Checker: authz.Static{itAdmin: authz.Permissions}, Clusters: store}, Audit: aud,
		Events: &events.Recorder{}, Notify: notify.NewFake(), Log: slog.New(slog.DiscardHandler)}
	as := authz.WithSubjects(ctx, authz.User(itTenant, itAdmin, nil))
	cl, err := cs.Register(as, clusters.RegisterInput{DisplayName: "it", ProxyAddr: proxy, Credential: clusters.NewCredential(identity)})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// The session list shows it as playable once Teleport has its end event.
	list := &auditlog.Service{Clusters: cs}
	var sid string
	if !eventually(2*time.Minute, func() bool {
		now := time.Now().UTC()
		p, err := list.Sessions(as, cl.ID, auditlog.SessionQuery{From: now.Add(-time.Hour), To: now.Add(time.Minute)})
		if err != nil {
			t.Logf("sessions: %v", err)
			return false
		}
		for _, s := range p.Items {
			if s.Kind == auditlog.KindSSH && s.Playable {
				sid = s.SID
				return true
			}
		}
		return false
	}) {
		t.Fatal("the recorded session never appeared as playable")
	}

	// Play it page by page (small pages, so there are several).
	svc := &recording.Service{Clusters: cs, Audit: aud, Signer: recording.NewSigner(), Limiter: recording.NewLimiter(0, 0), PageEvents: 2}
	var first recording.Page
	if !eventually(2*time.Minute, func() bool { // the node uploads the recording after the session ends
		first, err = svc.Page(as, cl.ID, sid, "")
		if err != nil {
			t.Logf("first page: %v", err)
		}
		return err == nil
	}) {
		t.Fatalf("recording never became available: %v", err)
	}
	if first.Width < 1 || first.Height < 1 {
		t.Fatalf("first page %+v", first)
	}
	var output strings.Builder
	pages, last := 0, first
	for p := first; ; {
		pages++
		for _, e := range p.Events {
			if e.Kind == recording.KindOutput {
				raw, err := base64.StdEncoding.DecodeString(e.Data)
				if err != nil {
					t.Fatal(err)
				}
				output.Write(raw)
			}
		}
		last = p
		if p.Done {
			break
		}
		if pages > 1000 {
			t.Fatal("never done")
		}
		if p, err = svc.Page(as, cl.ID, sid, p.Next); err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
	}
	got := output.String()
	iStart, iMid, iEnd := strings.Index(got, "REC-START-7f3a"), strings.Index(got, "REC-MIDDLE-7f3a"), strings.Index(got, "REC-END-7f3a")
	if iStart < 0 || iMid < iStart || iEnd < iMid {
		t.Fatalf("output (%d pages) does not replay the session: %q", pages, got)
	}
	if last.Bytes != int64(len(got)) || pages < 2 {
		t.Fatalf("bytes %d for %d bytes of output, %d pages", last.Bytes, len(got), pages)
	}
	// One successful start for the whole playback; the starts refused while
	// the node was still uploading are recorded as failures.
	played, refused := 0, 0
	for _, r := range aud.rows {
		if r.Action != string(audit.SessionPlayed) {
			continue
		}
		switch r.Outcome {
		case audit.OutcomeSuccess:
			played++
		case audit.OutcomeFailure:
			refused++
		default:
			t.Fatalf("outcome %q", r.Outcome)
		}
	}
	if played != 1 {
		t.Fatalf("%d successful teleport.session.played rows for one playback (%d refused)", played, refused)
	}
}
