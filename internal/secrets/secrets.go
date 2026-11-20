// Package secrets holds the Teleport module's per-cluster credentials (the
// identity files the module signs in with) behind secret references, adapted
// from dns-v4 internal/secrets. The database stores only the reference; the
// value is fetched at use time and handed around as a Secret, which redacts
// itself in every printing, JSON and slog path. Values are never logged, never
// returned by the API and never appear in errors.
//
// Reference forms (nothing else is accepted):
//
//	warden:<secret-id>   a warden secret (production)
//	file:<name>          a file under the configured directory (development
//	                     opt-out; config warns)
//
// Known platform gap: warden.v1.Secrets exposes only Get, GetPassword and
// Check — there is no write RPC — so the module cannot yet store or delete an
// identity in warden. Warden.Put and Warden.Delete return ErrWriteUnsupported
// (never a silent fallback); the dev stack writes through FileStore. Closing
// the gap needs a warden change (NEEDS CROSS-REPO, see plan.md).
package secrets

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	wardenv1 "github.com/go-tangra/go-tangra-warden/sdk/v4/api/proto/warden/v1"
)

// Errors (never carry secret material).
var (
	ErrInvalidRef       = errors.New("secrets: invalid secret reference")
	ErrNotFound         = errors.New("secrets: secret not found")
	ErrUnavailable      = errors.New("secrets: secret source unavailable")
	ErrEmpty            = errors.New("secrets: secret is empty")
	ErrWriteUnsupported = errors.New("secrets: the secret source does not support writes")
)

// Redacted is what a Secret prints as.
const Redacted = "[REDACTED]"

// ---- Secret

// Secret is a credential value. Every formatting path prints Redacted; only
// Reveal yields the bytes, as a copy.
type Secret struct{ b []byte }

// NewSecret wraps a copy of b.
func NewSecret(b []byte) Secret { return Secret{b: append([]byte(nil), b...)} }

// Reveal returns a copy of the value.
func (s Secret) Reveal() []byte { return append([]byte(nil), s.b...) }

// Len is the value's length.
func (s Secret) Len() int { return len(s.b) }

// IsZero reports an empty value.
func (s Secret) IsZero() bool { return len(s.b) == 0 }

// String implements fmt.Stringer.
func (Secret) String() string { return Redacted }

// GoString implements fmt.GoStringer (%#v).
func (Secret) GoString() string { return Redacted }

// MarshalJSON implements json.Marshaler.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// UnmarshalJSON refuses: a Secret is never read from a request body.
func (*Secret) UnmarshalJSON([]byte) error { return errors.New("secrets: a secret cannot be decoded") }

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }

// ---- references

// Reference schemes.
const (
	SchemeWarden = "warden"
	SchemeFile   = "file"
)

// Ref is a parsed secret reference.
type Ref struct{ Scheme, ID string }

// String renders the reference ("<scheme>:<id>"); it holds no secret.
func (r Ref) String() string { return r.Scheme + ":" + r.ID }

var refID = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,256}$`)

// ParseRef parses a "warden:" or "file:" reference.
func ParseRef(s string) (Ref, error) {
	scheme, id, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || (scheme != SchemeWarden && scheme != SchemeFile) || !refID.MatchString(id) {
		return Ref{}, ErrInvalidRef
	}
	return Ref{Scheme: scheme, ID: id}, nil
}

// Store reads, writes and deletes secrets by reference.
type Store interface {
	Get(ctx context.Context, ref Ref) (Secret, error)
	// Put stores the value under name (a cluster id) and returns its reference;
	// putting the same name again rotates the value in place.
	Put(ctx context.Context, name string, v Secret) (Ref, error)
	Delete(ctx context.Context, ref Ref) error
}

// ---- warden

// TokenFunc yields the module's platform token for warden calls.
type TokenFunc func(ctx context.Context) (string, error)

// FileToken reads the platform token from a file on every call (rotation).
func FileToken(path string) TokenFunc {
	return func(context.Context) (string, error) {
		raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured token path
		if err != nil {
			return "", fmt.Errorf("%w: platform token unreadable", ErrUnavailable)
		}
		tok := strings.TrimSpace(string(raw))
		if tok == "" {
			return "", fmt.Errorf("%w: platform token empty", ErrUnavailable)
		}
		return tok, nil
	}
}

// Warden reads warden references over the mesh. It cannot write (see the
// package comment).
type Warden struct {
	Client wardenv1.SecretsClient
	Token  TokenFunc
	// Timeout bounds one fetch (default 5 s).
	Timeout time.Duration
}

// NewWarden builds a warden store over a mesh connection to the warden module.
func NewWarden(cc grpc.ClientConnInterface, token TokenFunc) *Warden {
	return &Warden{Client: wardenv1.NewSecretsClient(cc), Token: token}
}

// Get implements Store.
func (w *Warden) Get(ctx context.Context, ref Ref) (Secret, error) {
	if ref.Scheme != SchemeWarden {
		return Secret{}, ErrInvalidRef
	}
	if w == nil || w.Client == nil || w.Token == nil {
		return Secret{}, ErrUnavailable
	}
	tok, err := w.Token(ctx)
	if err != nil {
		return Secret{}, err
	}
	timeout := w.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tok)
	res, err := w.Client.GetPassword(ctx, &wardenv1.GetPasswordRequest{Id: ref.ID})
	if err != nil {
		// Keep only the status code: nothing of the call leaks into logs.
		if status.Code(err) == codes.NotFound {
			return Secret{}, ErrNotFound
		}
		return Secret{}, fmt.Errorf("%w: warden: %s", ErrUnavailable, status.Code(err))
	}
	if res.GetPassword() == "" {
		return Secret{}, ErrEmpty
	}
	return NewSecret([]byte(res.GetPassword())), nil
}

// Put implements Store: refused, warden has no write RPC.
func (*Warden) Put(context.Context, string, Secret) (Ref, error) { return Ref{}, ErrWriteUnsupported }

// Delete implements Store: refused, warden has no write RPC.
func (*Warden) Delete(context.Context, Ref) error { return ErrWriteUnsupported }

// ---- file store (development)

// FileStore keeps secrets as 0600 files confined to one directory (os.Root:
// no traversal, no absolute paths, no symlink escape).
type FileStore struct{ dir string }

var fileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// NewFileStore opens dir, which must exist.
func NewFileStore(dir string) (*FileStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("%w: file store directory not set", ErrUnavailable)
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%w: file store directory missing", ErrUnavailable)
	}
	return &FileStore{dir: dir}, nil
}

func (f *FileStore) local(ref Ref) (string, error) {
	if ref.Scheme != SchemeFile || ref.ID == "." || !filepath.IsLocal(ref.ID) || !refID.MatchString(ref.ID) {
		return "", ErrInvalidRef
	}
	return ref.ID, nil
}

func (f *FileStore) root() (*os.Root, error) {
	r, err := os.OpenRoot(f.dir)
	if err != nil {
		return nil, fmt.Errorf("%w: file store directory unreadable", ErrUnavailable)
	}
	return r, nil
}

func fileErr(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNotFound
	}
	return fmt.Errorf("%w: file store", ErrUnavailable)
}

// Get implements Store.
func (f *FileStore) Get(_ context.Context, ref Ref) (Secret, error) {
	name, err := f.local(ref)
	if err != nil {
		return Secret{}, err
	}
	r, err := f.root()
	if err != nil {
		return Secret{}, err
	}
	defer func() { _ = r.Close() }()
	raw, err := r.ReadFile(name)
	if err != nil {
		return Secret{}, fileErr(err)
	}
	if len(raw) == 0 {
		return Secret{}, ErrEmpty
	}
	return Secret{b: raw}, nil
}

// Put implements Store (writes "<name>" with mode 0600).
func (f *FileStore) Put(_ context.Context, name string, v Secret) (Ref, error) {
	if !fileName.MatchString(name) {
		return Ref{}, ErrInvalidRef
	}
	if v.IsZero() {
		return Ref{}, ErrEmpty
	}
	r, err := f.root()
	if err != nil {
		return Ref{}, err
	}
	defer func() { _ = r.Close() }()
	// Rotation replaces the file so it is always created afresh with 0600
	// (WriteFile keeps an existing file's mode). A failed remove surfaces as
	// the write error below.
	_ = r.Remove(name)
	if err := r.WriteFile(name, v.b, 0o600); err != nil {
		return Ref{}, fileErr(err)
	}
	return Ref{Scheme: SchemeFile, ID: name}, nil
}

// Delete implements Store.
func (f *FileStore) Delete(_ context.Context, ref Ref) error {
	name, err := f.local(ref)
	if err != nil {
		return err
	}
	r, err := f.root()
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	if err := r.Remove(name); err != nil {
		return fileErr(err)
	}
	return nil
}

// String never prints the directory contents.
func (*FileStore) String() string { return "secrets.FileStore{dir}" }

// ---- router

// Router dispatches reads and deletes by scheme and sends writes to the
// backend named by Write.
type Router struct {
	Warden *Warden    // nil refuses warden references
	Files  *FileStore // nil refuses file references
	Write  string     // SchemeWarden or SchemeFile
}

func (r Router) backend(scheme string) (Store, error) {
	switch scheme {
	case SchemeWarden:
		if r.Warden == nil {
			return nil, fmt.Errorf("%w: warden not wired", ErrUnavailable)
		}
		return r.Warden, nil
	case SchemeFile:
		if r.Files == nil {
			return nil, fmt.Errorf("%w: file references are disabled", ErrUnavailable)
		}
		return r.Files, nil
	}
	return nil, ErrInvalidRef
}

// Get implements Store.
func (r Router) Get(ctx context.Context, ref Ref) (Secret, error) {
	b, err := r.backend(ref.Scheme)
	if err != nil {
		return Secret{}, err
	}
	return b.Get(ctx, ref)
}

// Put implements Store.
func (r Router) Put(ctx context.Context, name string, v Secret) (Ref, error) {
	b, err := r.backend(r.Write)
	if err != nil {
		return Ref{}, fmt.Errorf("%w: no writable secret backend", ErrUnavailable)
	}
	return b.Put(ctx, name, v)
}

// Delete implements Store.
func (r Router) Delete(ctx context.Context, ref Ref) error {
	b, err := r.backend(ref.Scheme)
	if err != nil {
		return err
	}
	return b.Delete(ctx, ref)
}

// ---- fake

// Fake is an in-memory Store for tests.
type Fake struct {
	mu  sync.Mutex
	m   map[string][]byte
	err error
}

// NewFake builds an empty fake.
func NewFake() *Fake { return &Fake{m: map[string][]byte{}} }

// Get implements Store.
func (f *Fake) Get(_ context.Context, ref Ref) (Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return Secret{}, f.err
	}
	v, ok := f.m[ref.String()]
	if !ok {
		return Secret{}, ErrNotFound
	}
	return NewSecret(v), nil
}

// Put implements Store (refs are "warden:fake/<name>").
func (f *Fake) Put(_ context.Context, name string, v Secret) (Ref, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return Ref{}, f.err
	}
	if v.IsZero() {
		return Ref{}, ErrEmpty
	}
	ref := Ref{Scheme: SchemeWarden, ID: "fake/" + name}
	f.m[ref.String()] = v.Reveal()
	return ref, nil
}

// Delete implements Store.
func (f *Fake) Delete(_ context.Context, ref Ref) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if _, ok := f.m[ref.String()]; !ok {
		return ErrNotFound
	}
	delete(f.m, ref.String())
	return nil
}

// SetErr sets (or with nil clears) the fake's failure.
func (f *Fake) SetErr(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

// Len is the number of stored secrets.
func (f *Fake) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.m)
}

var (
	_ Store = (*Warden)(nil)
	_ Store = (*FileStore)(nil)
	_ Store = Router{}
	_ Store = (*Fake)(nil)
)
