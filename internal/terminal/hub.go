// Package terminal runs brokered SSH terminals (spec 004, US1): a shell on
// a node, opened through the cluster's proxy with certificates Teleport
// issued for the caller's own managed user (internal/access), relayed to
// the browser as server-sent output and POSTed input (the gateway refuses
// WebSocket upgrades, research R5).
//
// A terminal belongs to the portal user who opened it; any other caller,
// even of the same tenant, gets not found. It ends (R6) when the user ends
// it, when no output reader has been attached for ReaderGrace, when no
// keepalive arrived for KeepaliveGrace (the portal session ended), after
// MaxDuration, when its certificates expire, when the shell exits, when the
// watchdog finds the access revoked (R7), or on shutdown. Certificates and
// output live only in memory and are dropped when it ends; nothing of the
// terminal's content is logged or audited.
package terminal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/access"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// Limits and timeouts (R6, R8).
const (
	MaxPerUser     = 5
	MaxTotal       = 64
	RingBytes      = 256 << 10
	ReaderGrace    = 30 * time.Second
	KeepaliveGrace = 3 * time.Minute
	MaxDuration    = 8 * time.Hour
	EndedRetention = 60 * time.Second
	WatchEvery     = 30 * time.Second
	SweepEvery     = 5 * time.Second
	MaxInputBytes  = 64 << 10
)

// End reasons (audit detail end_reason).
const (
	EndClosed     = "closed"
	EndExit       = "exit"
	EndReaderGone = "reader_gone"
	EndKeepalive  = "keepalive_lost"
	EndMaxTime    = "max_duration"
	EndExpired    = "certificate_expired"
	EndRevoked    = "revoked"
	EndShutdown   = "shutdown"
	EndError      = "error"
)

// Refusals.
var (
	ErrNotFound    = errors.New("terminal: not found")
	ErrTooMany     = errors.New("terminal: too many terminals")
	ErrEnded       = errors.New("terminal: ended")
	ErrLogin       = errors.New("terminal: login not allowed")
	ErrInputTooBig = errors.New("terminal: input too large")
)

// Hub holds the process's terminals.
type Hub struct {
	Access *access.Service
	Log    *slog.Logger
	Now    func() time.Time

	// MaxPerUser and MaxTotal override the limits (tests); 0 = default.
	MaxPerUser, MaxTotal int

	mu      sync.Mutex
	terms   map[string]*Terminal
	pending map[string]int // reservations being opened, by tenant|user
	shut    bool
}

func (h *Hub) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

func (h *Hub) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.New(slog.DiscardHandler)
}

// View is a terminal as the API shows it.
type View struct {
	ID           string    `json:"terminal_id"`
	Node         string    `json:"node"`
	Login        string    `json:"login"`
	TeleportUser string    `json:"teleport_user"`
	StartedAt    time.Time `json:"started_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Terminal is one open shell.
type Terminal struct {
	ID, ClusterID, Node, Login, TeleportUser string
	Started, Expires                         time.Time

	hub   *Hub
	grant access.Grant // the owner and their managed user (no credential)
	certs *teleportapi.UserCerts
	shell teleportapi.Shell
	stop  context.CancelFunc

	mu        sync.Mutex
	ring      []byte
	total     int64 // bytes ever written; ring holds [total-len(ring), total)
	changed   chan struct{}
	readers   int
	detached  time.Time // last time the reader count fell to 0 (or the start)
	keepalive time.Time
	ended     bool
	reason    string
	endedAt   time.Time
	once      sync.Once
}

func (t *Terminal) view() View {
	return View{ID: t.ID, Node: t.Node, Login: t.Login, TeleportUser: t.TeleportUser, StartedAt: t.Started, ExpiresAt: t.Expires}
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (h *Hub) limits() (perUser, total int) {
	perUser, total = MaxPerUser, MaxTotal
	if h.MaxPerUser > 0 {
		perUser = h.MaxPerUser
	}
	if h.MaxTotal > 0 {
		total = h.MaxTotal
	}
	return perUser, total
}

// Create opens a terminal on req.Node as req.Login for the caller's own
// managed user (access:terminal, MFA). Start and refusals are audited.
func (h *Hub) Create(ctx context.Context, clusterID string, req teleportapi.ShellRequest) (View, error) {
	details := map[string]any{"kind": access.KindTerminal, "node": req.Node, "login": req.Login}
	a := h.Access
	g, err := a.Resolve(ctx, clusterID, authz.AccessTerminal, true)
	if err != nil {
		a.Record(ctx, audit.TerminalStarted, g, err, details)
		return View{}, err
	}
	if err := h.reserve(g.Subject); err != nil {
		a.Record(ctx, audit.TerminalStarted, g, err, details)
		return View{}, err
	}
	t, err := h.open(ctx, g, req)
	if err != nil {
		h.release(g.Subject)
		a.Record(ctx, audit.TerminalStarted, g, err, details)
		return View{}, err
	}
	details["terminal_id"] = t.ID
	details["expires_at"] = t.Expires.Format(time.RFC3339)
	a.Record(ctx, audit.TerminalStarted, g, nil, details)
	return t.view(), nil
}

// reserve holds a slot for subj until open registers the terminal or
// release gives it back.
func (h *Hub) reserve(subj authz.Subjects) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.shut {
		return ErrEnded
	}
	perUser, total := h.limits()
	key := subj.TenantID + "|" + subj.UserID
	n, all := h.pending[key], 0
	for _, p := range h.pending {
		all += p
	}
	for _, t := range h.terms {
		if t.isEnded() {
			continue
		}
		all++
		if t.grant.Subject.TenantID == subj.TenantID && t.grant.Subject.UserID == subj.UserID {
			n++
		}
	}
	if n >= perUser || all >= total {
		return ErrTooMany
	}
	if h.pending == nil {
		h.pending = map[string]int{}
	}
	h.pending[key]++
	return nil
}

// release gives back a reservation of subj.
func (h *Hub) release(subj authz.Subjects) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := subj.TenantID + "|" + subj.UserID
	if h.pending[key]--; h.pending[key] <= 0 {
		delete(h.pending, key)
	}
}

func (h *Hub) open(ctx context.Context, g access.Grant, req teleportapi.ShellRequest) (*Terminal, error) {
	ttl, err := access.TTL(g.Settings, 0)
	if err != nil {
		return nil, err
	}
	certs, err := h.Access.Issue(ctx, g, ttl)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(certs.Logins, req.Login) {
		certs.Drop()
		return nil, ErrLogin
	}
	// The shell outlives the request; it ends with the terminal.
	sctx, stop := context.WithCancel(context.WithoutCancel(ctx))
	sh, err := g.Client.OpenShell(sctx, certs, req)
	if err != nil {
		stop()
		certs.Drop()
		return nil, err
	}
	now := h.now()
	t := &Terminal{ID: newID(), ClusterID: g.Cluster.ID, Node: req.Node, Login: req.Login, TeleportUser: certs.User,
		Started: now, Expires: now.Add(MaxDuration), hub: h, grant: g, certs: certs, shell: sh, stop: stop,
		changed: make(chan struct{}), detached: now, keepalive: now}
	if certs.Expires.Before(t.Expires) {
		t.Expires = certs.Expires.UTC()
	}
	h.release(g.Subject)
	h.mu.Lock()
	if h.shut {
		h.mu.Unlock()
		t.end(EndShutdown)
		return nil, ErrEnded
	}
	if h.terms == nil {
		h.terms = map[string]*Terminal{}
	}
	h.terms[t.ID] = t
	h.mu.Unlock()
	pumped := make(chan struct{})
	go func() {
		defer close(pumped)
		t.pump()
	}()
	go func() {
		<-sh.Done()
		// Keep the shell's last output: end once it is read (or soon).
		select {
		case <-pumped:
		case <-time.After(2 * time.Second):
		}
		t.end(EndExit)
	}()
	return t, nil
}

// pump copies the shell's output into the ring.
func (t *Terminal) pump() {
	buf := make([]byte, 32<<10)
	out := t.shell.Output()
	for {
		n, err := out.Read(buf)
		if n > 0 {
			t.write(buf[:n])
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
				t.end(EndError)
			}
			return
		}
	}
}

func (t *Terminal) write(p []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ring = append(t.ring, p...)
	if over := len(t.ring) - RingBytes; over > 0 {
		t.ring = append(t.ring[:0:0], t.ring[over:]...)
	}
	t.total += int64(len(p))
	close(t.changed)
	t.changed = make(chan struct{})
}

func (t *Terminal) isEnded() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ended
}

// end ends the terminal once: the shell is closed, the certificates
// dropped, the output kept (for a final read) until EndedRetention.
func (t *Terminal) end(reason string) {
	t.once.Do(func() {
		t.mu.Lock()
		t.ended, t.reason, t.endedAt = true, reason, t.hub.now()
		close(t.changed)
		t.changed = make(chan struct{})
		t.mu.Unlock()
		_ = t.shell.Close()
		t.stop()
		t.certs.Drop()
		ctx := authz.WithSubjects(context.Background(), t.grant.Subject)
		t.hub.Access.Record(ctx, audit.TerminalEnded, t.grant, nil, map[string]any{"kind": access.KindTerminal, "terminal_id": t.ID,
			"node": t.Node, "login": t.Login, "end_reason": reason, "duration_s": int64(t.endedAt.Sub(t.Started) / time.Second)})
	})
}

// ---- lookup and operations

// get returns the caller's own terminal on clusterID (not found otherwise).
func (h *Hub) get(ctx context.Context, clusterID, id string) (*Terminal, error) {
	subj, ok := authz.FromContext(ctx)
	if !ok || !subj.IsHuman() {
		return nil, authz.ErrForbidden
	}
	if err := h.Access.Clusters.Authz.Require(ctx, authz.AccessTerminal); err != nil {
		return nil, err
	}
	h.mu.Lock()
	t := h.terms[id]
	h.mu.Unlock()
	if t == nil || t.ClusterID != clusterID || t.grant.Subject.TenantID != subj.TenantID || t.grant.Subject.UserID != subj.UserID {
		return nil, ErrNotFound
	}
	return t, nil
}

// Chunk is output from an offset: Data starts at From and ends at Next.
// Gap reports output lost before From (the ring wrapped).
type Chunk struct {
	From, Next int64
	Data       []byte
	Gap        bool
	Ended      bool
	Reason     string
}

// Read returns the output from offset from and a channel closed on the
// next change.
func (t *Terminal) Read(from int64) (Chunk, <-chan struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	start := t.total - int64(len(t.ring))
	c := Chunk{From: from, Next: t.total, Ended: t.ended, Reason: t.reason}
	if from < start {
		c.From, c.Gap = start, from >= 0 && from < start
	}
	if c.From > t.total {
		c.From = t.total
	}
	c.Data = slices.Clone(t.ring[c.From-start:])
	return c, t.changed
}

// Attach registers an output reader; the returned func detaches it.
func (t *Terminal) Attach() func() {
	t.mu.Lock()
	t.readers++
	t.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			t.readers--
			if t.readers == 0 {
				t.detached = t.hub.now()
			}
			t.mu.Unlock()
		})
	}
}

// Output returns the caller's terminal for reading.
func (h *Hub) Output(ctx context.Context, clusterID, id string) (*Terminal, error) {
	return h.get(ctx, clusterID, id)
}

// Input sends keystrokes.
func (h *Hub) Input(ctx context.Context, clusterID, id string, p []byte) error {
	if len(p) > MaxInputBytes {
		return ErrInputTooBig
	}
	t, err := h.get(ctx, clusterID, id)
	if err != nil {
		return err
	}
	if t.isEnded() {
		return ErrEnded
	}
	if _, err := t.shell.Write(p); err != nil {
		return ErrEnded
	}
	return nil
}

// Resize changes the terminal size.
func (h *Hub) Resize(ctx context.Context, clusterID, id string, cols, rows int) error {
	t, err := h.get(ctx, clusterID, id)
	if err != nil {
		return err
	}
	if t.isEnded() {
		return ErrEnded
	}
	if err := t.shell.Resize(cols, rows); err != nil {
		return ErrEnded
	}
	return nil
}

// Keepalive records that the owner's portal session is alive.
func (h *Hub) Keepalive(ctx context.Context, clusterID, id string) error {
	t, err := h.get(ctx, clusterID, id)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ended {
		return ErrEnded
	}
	t.keepalive = t.hub.now()
	return nil
}

// Close ends the caller's terminal.
func (h *Hub) Close(ctx context.Context, clusterID, id string) error {
	t, err := h.get(ctx, clusterID, id)
	if err != nil {
		return err
	}
	t.end(EndClosed)
	return nil
}

// Count is the number of live terminals (tests, health).
func (h *Hub) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, t := range h.terms {
		if !t.isEnded() {
			n++
		}
	}
	return n
}

func (h *Hub) live() []*Terminal {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*Terminal, 0, len(h.terms))
	for _, t := range h.terms {
		out = append(out, t)
	}
	return out
}

// ---- timeouts, watchdog, shutdown

// Sweep ends terminals past a timeout and forgets ended ones after
// EndedRetention.
func (h *Hub) Sweep() {
	now := h.now()
	for _, t := range h.live() {
		t.mu.Lock()
		ended, endedAt := t.ended, t.endedAt
		reason := ""
		switch {
		case ended:
		case !now.Before(t.Started.Add(MaxDuration)):
			reason = EndMaxTime
		case !now.Before(t.Expires):
			reason = EndExpired
		case t.readers == 0 && now.Sub(t.detached) >= ReaderGrace:
			reason = EndReaderGone
		case now.Sub(t.keepalive) >= KeepaliveGrace:
			reason = EndKeepalive
		}
		t.mu.Unlock()
		if reason != "" {
			t.end(reason)
		}
		if ended && now.Sub(endedAt) >= EndedRetention {
			h.mu.Lock()
			delete(h.terms, t.ID)
			h.mu.Unlock()
		}
	}
}

// Watch re-checks every live terminal's access (R7): the owner still has
// access:terminal on the cluster and the same managed user, still labelled
// for them and not locked. A definitive refusal ends the terminal; a
// transient failure (cluster unreachable) does not.
func (h *Hub) Watch(ctx context.Context) {
	for _, t := range h.live() {
		if t.isEnded() {
			continue
		}
		sctx := authz.WithSubjects(ctx, t.grant.Subject)
		g, err := h.Access.Resolve(sctx, t.ClusterID, authz.AccessTerminal, false)
		switch {
		case err == nil && g.User.Name == t.TeleportUser:
		case err == nil, revoked(err):
			t.end(EndRevoked)
		default:
			h.log().WarnContext(ctx, "terminal access check failed", "terminal_id", t.ID, "cluster_id", t.ClusterID,
				"reason", access.AuditReason(err))
		}
	}
}

func revoked(err error) bool {
	return errors.Is(err, access.ErrNotProvisioned) || errors.Is(err, access.ErrLocked) ||
		errors.Is(err, authz.ErrForbidden) || errors.Is(err, repo.ErrNotFound)
}

// Run sweeps and watches until ctx ends, then ends every terminal.
func (h *Hub) Run(ctx context.Context) {
	sweep := time.NewTicker(SweepEvery)
	watch := time.NewTicker(WatchEvery)
	defer sweep.Stop()
	defer watch.Stop()
	for {
		select {
		case <-ctx.Done():
			h.Shutdown()
			return
		case <-sweep.C:
			h.Sweep()
		case <-watch.C:
			h.Watch(ctx)
		}
	}
}

// Shutdown ends every terminal (reason shutdown) and refuses new ones.
func (h *Hub) Shutdown() {
	h.mu.Lock()
	h.shut = true
	h.mu.Unlock()
	for _, t := range h.live() {
		t.end(EndShutdown)
	}
}
