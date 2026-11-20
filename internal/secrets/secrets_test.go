package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	wardenv1 "github.com/go-tangra/go-tangra-warden/sdk/v4/api/proto/warden/v1"
)

const marker = "TELEPORT-MARKER-SECRET-VALUE"

var ctx = context.Background()

func TestSecretRedactsEverywhere(t *testing.T) {
	s := NewSecret([]byte(marker))
	var logBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("x", "secret", s)
	slog.New(slog.NewTextHandler(&logBuf, nil)).Info("x", "secret", s)
	js, err := json.Marshal(struct{ S Secret }{s})
	if err != nil {
		t.Fatal(err)
	}
	outs := []string{s.String(), s.GoString(), fmt.Sprintf("%v %+v %#v %s", s, s, s, s), string(js), logBuf.String()}
	for _, o := range outs {
		if strings.Contains(o, marker) {
			t.Fatalf("secret leaked: %q", o)
		}
		if !strings.Contains(o, Redacted) {
			t.Fatalf("missing redaction marker: %q", o)
		}
	}
	if string(s.Reveal()) != marker || s.Len() != len(marker) || s.IsZero() {
		t.Fatal("Reveal/Len/IsZero")
	}
	// Reveal hands out a copy.
	b := s.Reveal()
	b[0] = 'X'
	if string(s.Reveal()) != marker {
		t.Fatal("Reveal shares the backing array")
	}
	var z Secret
	if !z.IsZero() || z.Len() != 0 {
		t.Fatal("zero secret")
	}
	if err := json.Unmarshal([]byte(`"x"`), &s); err == nil {
		t.Fatal("a Secret must not be decodable from JSON")
	}
}

func TestParseRef(t *testing.T) {
	good := map[string]Ref{
		"warden:abc-123":       {Scheme: SchemeWarden, ID: "abc-123"},
		"file:cluster/x.ident": {Scheme: SchemeFile, ID: "cluster/x.ident"},
		" warden:id ":          {Scheme: SchemeWarden, ID: "id"},
		"file:0190f7c2.ident":  {Scheme: SchemeFile, ID: "0190f7c2.ident"},
	}
	for in, want := range good {
		got, err := ParseRef(in)
		if err != nil || got != want {
			t.Errorf("ParseRef(%q) = %+v, %v", in, got, err)
		}
		if got.String() != strings.TrimSpace(in) {
			t.Errorf("String() = %q", got.String())
		}
	}
	for _, in := range []string{"", "abc", "warden:", "file:", "vault:x", "env:X", "http://x", "warden:a b", "warden:" + strings.Repeat("a", 300)} {
		if _, err := ParseRef(in); !errors.Is(err, ErrInvalidRef) {
			t.Errorf("ParseRef(%q) accepted: %v", in, err)
		}
	}
}

func TestFakePutGetDelete(t *testing.T) {
	f := NewFake()
	ref, err := f.Put(ctx, "cluster-1", NewSecret([]byte(marker)))
	if err != nil || ref.Scheme != SchemeWarden {
		t.Fatalf("put: %v %v", ref, err)
	}
	got, err := f.Get(ctx, ref)
	if err != nil || string(got.Reveal()) != marker {
		t.Fatalf("get: %v", err)
	}
	if err := f.Delete(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Get(ctx, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete: %v", err)
	}
	if err := f.Delete(ctx, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	f.SetErr(ErrUnavailable)
	if _, err := f.Put(ctx, "x", NewSecret([]byte("v"))); !errors.Is(err, ErrUnavailable) {
		t.Fatal("put err")
	}
	if _, err := f.Get(ctx, ref); !errors.Is(err, ErrUnavailable) {
		t.Fatal("get err")
	}
	if err := f.Delete(ctx, ref); !errors.Is(err, ErrUnavailable) {
		t.Fatal("delete err")
	}
	f.SetErr(nil)
	if _, err := f.Put(ctx, "x", Secret{}); !errors.Is(err, ErrEmpty) {
		t.Fatal("empty secret stored")
	}
	if f.Len() != 0 {
		t.Fatalf("len %d", f.Len())
	}
}

func TestFileStore(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStore(""); err == nil {
		t.Fatal("empty dir accepted")
	}
	if _, err := NewFileStore(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing dir accepted")
	}
	ref, err := fs.Put(ctx, "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55", NewSecret([]byte(marker)))
	if err != nil || ref.Scheme != SchemeFile {
		t.Fatalf("put %v %v", ref, err)
	}
	st, err := os.Stat(filepath.Join(dir, ref.ID))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v %v", st, err)
	}
	got, err := fs.Get(ctx, ref)
	if err != nil || string(got.Reveal()) != marker {
		t.Fatalf("get %v", err)
	}
	// Rotation overwrites in place.
	if _, err := fs.Put(ctx, "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55", NewSecret([]byte("v2"))); err != nil {
		t.Fatal(err)
	}
	if got, _ := fs.Get(ctx, ref); string(got.Reveal()) != "v2" {
		t.Fatal("rotation")
	}
	if err := fs.Delete(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Get(ctx, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete %v", err)
	}
	if err := fs.Delete(ctx, ref); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice %v", err)
	}
	// Path confinement: no traversal, no absolute paths, no other schemes.
	outside := filepath.Join(filepath.Dir(dir), "outside.txt")
	_ = os.WriteFile(outside, []byte("x"), 0o600)
	for _, id := range []string{"../outside.txt", "/etc/passwd", "a/../../outside.txt", "..", "."} {
		if _, err := fs.Get(ctx, Ref{Scheme: SchemeFile, ID: id}); !errors.Is(err, ErrInvalidRef) {
			t.Errorf("Get(%q) not refused: %v", id, err)
		}
		if err := fs.Delete(ctx, Ref{Scheme: SchemeFile, ID: id}); !errors.Is(err, ErrInvalidRef) {
			t.Errorf("Delete(%q) not refused: %v", id, err)
		}
	}
	for _, name := range []string{"../x", "a/b", "", ".hidden", strings.Repeat("a", 200)} {
		if _, err := fs.Put(ctx, name, NewSecret([]byte("v"))); !errors.Is(err, ErrInvalidRef) {
			t.Errorf("Put(%q) not refused: %v", name, err)
		}
	}
	if _, err := fs.Get(ctx, Ref{Scheme: SchemeWarden, ID: "x"}); !errors.Is(err, ErrInvalidRef) {
		t.Fatal("warden ref through file store")
	}
	if _, err := fs.Put(ctx, "empty", Secret{}); !errors.Is(err, ErrEmpty) {
		t.Fatal("empty stored")
	}
	// An empty file is an empty secret.
	_ = os.WriteFile(filepath.Join(dir, "blank"), nil, 0o600)
	if _, err := fs.Get(ctx, Ref{Scheme: SchemeFile, ID: "blank"}); !errors.Is(err, ErrEmpty) {
		t.Fatalf("blank %v", err)
	}
	// An unwritable directory fails without leaking the value.
	ro := t.TempDir()
	rofs, _ := NewFileStore(ro)
	_ = os.Chmod(ro, 0o500)
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
	if os.Geteuid() != 0 {
		if _, err := rofs.Put(ctx, "x", NewSecret([]byte(marker))); err == nil || strings.Contains(err.Error(), marker) {
			t.Fatalf("read-only put: %v", err)
		}
	}
	// A directory where a file is expected is unavailable, not a leak.
	_ = os.MkdirAll(filepath.Join(dir, "sub", "inner"), 0o700)
	if _, err := fs.Get(ctx, Ref{Scheme: SchemeFile, ID: "sub"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("dir get %v", err)
	}
	if err := fs.Delete(ctx, Ref{Scheme: SchemeFile, ID: "sub"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("dir delete %v", err)
	}
	// The directory vanishing after construction.
	gone := t.TempDir()
	gfs, _ := NewFileStore(gone)
	_ = os.Remove(gone)
	if _, err := gfs.Get(ctx, Ref{Scheme: SchemeFile, ID: "x"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("gone get %v", err)
	}
	if _, err := gfs.Put(ctx, "x", NewSecret([]byte("v"))); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("gone put %v", err)
	}
	if err := gfs.Delete(ctx, Ref{Scheme: SchemeFile, ID: "x"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("gone delete %v", err)
	}
	if fs.String() != "secrets.FileStore{dir}" {
		t.Fatal(fs.String())
	}
}

// fakeWarden is a scriptable warden.v1.Secrets client.
type fakeWarden struct {
	wardenv1.SecretsClient
	pw   map[string]string
	err  error
	auth string
}

func (f *fakeWarden) GetPassword(ctx context.Context, in *wardenv1.GetPasswordRequest, _ ...grpc.CallOption) (*wardenv1.GetPasswordResponse, error) {
	if md, ok := metadata.FromOutgoingContext(ctx); ok {
		if v := md.Get("authorization"); len(v) > 0 {
			f.auth = v[0]
		}
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("no deadline")
	}
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.pw[in.GetId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "secret "+in.GetId()+" not found")
	}
	return &wardenv1.GetPasswordResponse{Password: v}, nil
}

func TestWarden(t *testing.T) {
	fw := &fakeWarden{pw: map[string]string{"id1": marker, "blank": ""}}
	tok := func(context.Context) (string, error) { return "platform-token", nil }
	w := &Warden{Client: fw, Token: tok, Timeout: time.Second}
	got, err := w.Get(ctx, Ref{Scheme: SchemeWarden, ID: "id1"})
	if err != nil || string(got.Reveal()) != marker || fw.auth != "Bearer platform-token" {
		t.Fatalf("get %v %q", err, fw.auth)
	}
	if _, err := w.Get(ctx, Ref{Scheme: SchemeWarden, ID: "missing"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing %v", err)
	}
	if _, err := w.Get(ctx, Ref{Scheme: SchemeWarden, ID: "blank"}); !errors.Is(err, ErrEmpty) {
		t.Fatalf("blank %v", err)
	}
	fw.err = status.Error(codes.Unavailable, "dial "+marker)
	if _, err := w.Get(ctx, Ref{Scheme: SchemeWarden, ID: "id1"}); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), marker) {
		t.Fatalf("unavailable %v", err)
	}
	if _, err := w.Get(ctx, Ref{Scheme: SchemeFile, ID: "x"}); !errors.Is(err, ErrInvalidRef) {
		t.Fatal("file ref through warden")
	}
	// warden.v1 has no write RPC: put and delete are refused, never faked.
	if _, err := w.Put(ctx, "x", NewSecret([]byte("v"))); !errors.Is(err, ErrWriteUnsupported) {
		t.Fatalf("put %v", err)
	}
	if err := w.Delete(ctx, Ref{Scheme: SchemeWarden, ID: "id1"}); !errors.Is(err, ErrWriteUnsupported) {
		t.Fatalf("delete %v", err)
	}
	// Token failure and an unwired client.
	bad := &Warden{Client: fw, Token: func(context.Context) (string, error) { return "", ErrUnavailable }}
	if _, err := bad.Get(ctx, Ref{Scheme: SchemeWarden, ID: "id1"}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("token err")
	}
	var nilW *Warden
	if _, err := nilW.Get(ctx, Ref{Scheme: SchemeWarden, ID: "id1"}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil warden")
	}
	// Default timeout applies when unset.
	fw.err = nil
	if _, err := (&Warden{Client: fw, Token: tok}).Get(ctx, Ref{Scheme: SchemeWarden, ID: "id1"}); err != nil {
		t.Fatal(err)
	}
	if NewWarden(nil, tok).Client == nil {
		t.Fatal("NewWarden")
	}
}

func TestFileToken(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tok")
	if _, err := FileToken(p)(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing")
	}
	_ = os.WriteFile(p, []byte("  \n"), 0o600)
	if _, err := FileToken(p)(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("empty")
	}
	_ = os.WriteFile(p, []byte("tok\n"), 0o600)
	if v, err := FileToken(p)(ctx); err != nil || v != "tok" {
		t.Fatal(v, err)
	}
}

func TestRouter(t *testing.T) {
	files, _ := NewFileStore(t.TempDir())
	fw := &fakeWarden{pw: map[string]string{"w1": "warden-value"}}
	w := &Warden{Client: fw, Token: func(context.Context) (string, error) { return "t", nil }}

	r := Router{Warden: w, Files: files, Write: SchemeFile}
	ref, err := r.Put(ctx, "c1", NewSecret([]byte(marker)))
	if err != nil || ref.Scheme != SchemeFile {
		t.Fatalf("put %v %v", ref, err)
	}
	if v, err := r.Get(ctx, ref); err != nil || string(v.Reveal()) != marker {
		t.Fatal("get file", err)
	}
	if v, err := r.Get(ctx, Ref{Scheme: SchemeWarden, ID: "w1"}); err != nil || string(v.Reveal()) != "warden-value" {
		t.Fatal("get warden", err)
	}
	if err := r.Delete(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete(ctx, Ref{Scheme: SchemeWarden, ID: "w1"}); !errors.Is(err, ErrWriteUnsupported) {
		t.Fatal("warden delete")
	}
	// Writing to warden is refused until warden exposes a write RPC.
	if _, err := (Router{Warden: w, Write: SchemeWarden}).Put(ctx, "c1", NewSecret([]byte("v"))); !errors.Is(err, ErrWriteUnsupported) {
		t.Fatal("warden write")
	}
	// Unwired backends.
	empty := Router{}
	if _, err := empty.Get(ctx, Ref{Scheme: SchemeFile, ID: "x"}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("no files")
	}
	if _, err := empty.Get(ctx, Ref{Scheme: SchemeWarden, ID: "x"}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("no warden")
	}
	if err := empty.Delete(ctx, Ref{Scheme: SchemeFile, ID: "x"}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("no files delete")
	}
	if _, err := empty.Put(ctx, "x", NewSecret([]byte("v"))); !errors.Is(err, ErrUnavailable) {
		t.Fatal("no write backend")
	}
	if _, err := empty.Get(ctx, Ref{Scheme: "vault", ID: "x"}); !errors.Is(err, ErrInvalidRef) {
		t.Fatal("bad scheme")
	}
	if err := empty.Delete(ctx, Ref{Scheme: "vault", ID: "x"}); !errors.Is(err, ErrInvalidRef) {
		t.Fatal("bad scheme delete")
	}
	if _, err := (Router{Files: files, Write: SchemeFile}).Put(ctx, "../x", NewSecret([]byte("v"))); !errors.Is(err, ErrInvalidRef) {
		t.Fatal("traversal through router")
	}
}
