//go:build integration

package integration

// A management identity obtained by signing in (password and TOTP through
// the proxy's web login, what `tsh login --out=... --format=file` does).
// Teleport refuses impersonation from an impersonated certificate, which
// every `tctl auth sign` identity is (plan.md Deviations), so brokered
// access needs a sign-in identity.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- TOTP (RFC 6238) is HMAC-SHA1
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	tclient "github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/identityfile"
	"github.com/testcontainers/testcontainers-go"
	"golang.org/x/crypto/ssh"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
)

// brokeredConfig is recordingConfig with TOTP as the second factor, so a
// test can sign in.
var brokeredConfig = strings.Replace(recordingConfig, "  proxy_listener_mode: multiplex\n",
	"  proxy_listener_mode: multiplex\n  authentication: { type: local, second_factor: otp }\n", 1)

// totp is RFC 6238 (SHA-1, 30 s, 6 digits) of a base32 secret at t.
func totp(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		t.Fatalf("totp secret: %v", err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30)) // #nosec G115 -- current time
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1000000)
}

// signInIdentity creates user with roles, sets a password and a TOTP
// device from the invite, signs in through the proxy web login and returns
// the identity file. bootstrap is any identity able to reach the auth API
// (the invite token is its own authorization).
func signInIdentity(t *testing.T, ctx context.Context, c testcontainers.Container, guard *netguard.Guard, proxy, user, roles string, bootstrap []byte) []byte {
	t.Helper()
	return signIn(t, ctx, c, guard, proxy, user, roles, bootstrap, 2*time.Hour).identity
}

// signedIn is the outcome of signIn: the identity file and what signs in
// again (the password and the TOTP secret).
type signedIn struct {
	identity []byte
	password string
	secret   string
}

// itPassword is the password signIn sets.
const itPassword = "it-Brokered-Access-0123456789"

// signIn is signInIdentity asking for ttl.
func signIn(t *testing.T, ctx context.Context, c testcontainers.Container, guard *netguard.Guard, proxy, user, roles string, bootstrap []byte, ttl time.Duration) signedIn {
	t.Helper()
	out := tctlOut(t, ctx, c, "users", "add", user, "--roles="+roles)
	m := regexp.MustCompile(`/web/invite/([A-Za-z0-9]+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no invite in %q", out)
	}
	token := m[1]
	pinned := guard.Dialer(proxy)
	api, err := tclient.New(ctx, tclient.Config{
		Dialer:                     tclient.ContextDialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) { return pinned(ctx, network, proxy) }),
		Credentials:                []tclient.Credentials{tclient.LoadIdentityFileFromString(string(bootstrap))},
		ALPNSNIAuthDialClusterName: itCluster,
	})
	if err != nil {
		t.Fatalf("bootstrap client: %v", err)
	}
	defer api.Close()
	ch, err := api.CreateRegisterChallenge(ctx, &proto.CreateRegisterChallengeRequest{TokenID: token, DeviceType: proto.DeviceType_DEVICE_TYPE_TOTP,
		DeviceUsage: proto.DeviceUsage_DEVICE_USAGE_MFA})
	if err != nil {
		t.Fatalf("register challenge: %v", err)
	}
	secret := ch.GetTOTP().GetSecret()
	const password = itPassword
	start := time.Now()
	if _, err := api.ChangeUserAuthentication(ctx, &proto.ChangeUserAuthenticationRequest{TokenID: token, NewPassword: []byte(password),
		NewDeviceName: "otp", NewMFARegisterResponse: &proto.MFARegisterResponse{Response: &proto.MFARegisterResponse_TOTP{
			TOTP: &proto.TOTPRegisterResponse{Code: totp(t, secret, start)}}}}); err != nil {
		t.Fatalf("set password and otp: %v", err)
	}
	// A TOTP code is used once: wait for the next window.
	next := time.Unix((start.Unix()/30+1)*30, 0).Add(time.Second)
	time.Sleep(time.Until(next))

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sshPub, _ := ssh.NewPublicKey(&key.PublicKey)
	pkix, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	hc := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DialContext:     func(ctx context.Context, network, _ string) (net.Conn, error) { return pinned(ctx, network, proxy) },
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- the test container's self-signed web certificate
	}}
	post := func(path string, v any) ([]byte, int) {
		t.Helper()
		body, _ := json.Marshal(v)
		resp, err := hc.Post("https://"+proxy+path, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return raw, resp.StatusCode
	}
	// Teleport 18 web login with a second factor: begin with the password,
	// finish with the TOTP code and the public keys.
	if raw, code := post("/v1/webapi/mfa/login/begin", map[string]any{"user": user, "pass": password}); code != http.StatusOK {
		t.Fatalf("mfa login begin: %d %.300s", code, raw)
	}
	raw, code := post("/v1/webapi/mfa/login/finish", map[string]any{"user": user, "password": password, "totp_code": totp(t, secret, time.Now()),
		"ssh_pub_key": ssh.MarshalAuthorizedKey(sshPub), "tls_pub_key": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}),
		"ttl": int64(ttl)})
	var login struct {
		Cert        []byte `json:"cert"`
		TLSCert     []byte `json:"tls_cert"`
		HostSigners []struct {
			Domain string   `json:"domain_name"`
			Keys   [][]byte `json:"checking_keys"`
			TLS    [][]byte `json:"tls_certs"`
		} `json:"host_signers"`
	}
	if err := json.Unmarshal(raw, &login); err != nil || code != http.StatusOK || len(login.TLSCert) == 0 {
		t.Fatalf("mfa login finish: %d %v %.300s", code, err, raw)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	id := &identityfile.IdentityFile{PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		Certs: identityfile.Certs{SSH: login.Cert, TLS: login.TLSCert}}
	for _, hs := range login.HostSigners {
		id.CACerts.TLS = append(id.CACerts.TLS, hs.TLS...)
		for _, k := range hs.Keys {
			id.CACerts.SSH = append(id.CACerts.SSH, []byte("@cert-authority "+hs.Domain+",*."+hs.Domain+" "+strings.TrimSpace(string(k))+" type=host\n"))
		}
	}
	b, err := identityfile.Encode(id)
	if err != nil {
		t.Fatal(err)
	}
	return signedIn{identity: b, password: password, secret: secret}
}

// tshLogin runs the documented `tsh login --format=file --out` inside the
// container as the signed-in user si (spec 005: how an operator obtains the
// access identity) and returns the identity file. tsh needs a terminal for
// the password and the TOTP code: busybox script provides one, and the
// answers to its terminal queries (background colour, cursor position)
// are typed before the password. ttlMinutes is tsh's --ttl.
func tshLogin(t *testing.T, ctx context.Context, c testcontainers.Container, si signedIn, user string, ttlMinutes int) []byte {
	t.Helper()
	// A TOTP code is used once: start in a fresh window.
	time.Sleep(time.Until(time.Unix((time.Now().Unix()/30+1)*30, 0).Add(time.Second)))
	code := totp(t, si.secret, time.Now())
	const out = "/tmp/tsh-login.identity"
	cmd := fmt.Sprintf("(sleep 3; printf '\\033]11;rgb:0000/0000/0000\\033\\\\\\033[1;1R'; sleep 2; echo '%s'; sleep 4; echo '%s'; sleep 15) | "+
		"HOME=/tmp timeout 60 script -q -c 'tsh login --insecure --proxy=localhost:3080 --user=%s --ttl=%d --format=file --out=%s --overwrite' /dev/null 2>&1; echo rc=$?",
		si.password, code, user, ttlMinutes, out)
	_, r, err := c.Exec(ctx, []string{"/busybox/sh", "-c", cmd})
	if err != nil {
		t.Fatalf("tsh login: %v", err)
	}
	b, _ := io.ReadAll(r)
	if !strings.Contains(string(b), "rc=0") {
		t.Fatalf("tsh login: %q", b)
	}
	return copyOut(t, ctx, c, out)
}
