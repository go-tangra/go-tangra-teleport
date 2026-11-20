//go:build spike

// Spike tests for research D1 and D2. They need a live Teleport cluster and
// are never run in CI:
//
//	TELEPORT_SPIKE_PROXY=teleport.example.com:443 \
//	TELEPORT_SPIKE_IDENTITY=/path/to/identity \
//	TELEPORT_SPIKE_ALLOW_PRIVATE=10.0.0.0/8 \
//	go test -tags spike -run Spike -v ./internal/teleportapi/
//
// D1: dial the proxy address with TLS routing and an identity file loaded
// from memory, through the netguard pinned dialler, and Ping/list.
// D2: re-issue user certificates with only the api module
// (Client.GenerateUserCerts) — the primitive a bot/renewable identity would
// need. The outcome is recorded in research.md D2.
package teleportapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	tclient "github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"golang.org/x/crypto/ssh"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
)

func spikeEnv(t *testing.T) (string, secrets.Secret, *netguard.Guard) {
	t.Helper()
	proxy := os.Getenv("TELEPORT_SPIKE_PROXY")
	idPath := os.Getenv("TELEPORT_SPIKE_IDENTITY")
	if proxy == "" || idPath == "" {
		t.Skip("TELEPORT_SPIKE_PROXY and TELEPORT_SPIKE_IDENTITY not set")
	}
	raw, err := os.ReadFile(idPath)
	if err != nil {
		t.Fatal(err)
	}
	var allowed []netip.Prefix
	if p := os.Getenv("TELEPORT_SPIKE_ALLOW_PRIVATE"); p != "" {
		allowed = append(allowed, netip.MustParsePrefix(p))
	}
	g, err := netguard.New(netguard.Policy{AllowedPrivate: allowed})
	if err != nil {
		t.Fatal(err)
	}
	return proxy, secrets.NewSecret(raw), g
}

// TestSpikeD1DialThroughProxy: TLS routing via the proxy address, pinned dialler.
func TestSpikeD1DialThroughProxy(t *testing.T) {
	proxy, id, g := spikeEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := Dial(ctx, DialParams{ProxyAddr: proxy, Identity: id, Guard: g})
	if err != nil {
		t.Fatalf("dial: %v (reason %s)", err, Reason(err))
	}
	defer func() { _ = c.Close() }()
	info, err := c.Ping(ctx)
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Logf("cluster=%s version=%s edition=%s", info.ClusterName, info.ServerVersion, info.Edition)
	users, err := c.ListUsers(ctx, ListOptions{Limit: 10})
	t.Logf("users: %d (err %v)", len(users.Items), err)
	nodes, err := c.ListResources(ctx, KindNode, ListOptions{Limit: 10})
	t.Logf("nodes: %d (err %v)", len(nodes.Items), err)
}

// TestSpikeD2ReissueCerts: GenerateUserCerts for the identity's own user with
// a fresh key, using only the api module.
func TestSpikeD2ReissueCerts(t *testing.T) {
	proxy, id, g := spikeEnv(t)
	meta, err := ParseIdentity(id)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pinned := g.Dialer(proxy)
	c, err := tclient.New(ctx, tclient.Config{
		Dialer: tclient.ContextDialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
			return pinned(ctx, network, proxy)
		}),
		Credentials:                []tclient.Credentials{tclient.LoadIdentityFileFromString(string(id.Reveal()))},
		ALPNSNIAuthDialClusterName: meta.ClusterName,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sshPub, _ := ssh.NewPublicKey(&key.PublicKey)
	tlsPub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	certs, err := c.GenerateUserCerts(ctx, proto.UserCertsRequest{
		SSHPublicKey: ssh.MarshalAuthorizedKey(sshPub),
		TLSPublicKey: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: tlsPub}),
		Username:     meta.Subject,
		Expires:      time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("GenerateUserCerts: %v (reason %s)", err, Reason(MapError(err)))
	}
	t.Logf("re-issued: tls %d bytes, ssh %d bytes", len(certs.TLS), len(certs.SSH))
}
