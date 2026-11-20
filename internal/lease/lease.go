// Package lease is the Valkey-backed mutual exclusion the module's in-process
// background loops run under (watchers, alert pollers, the offline sweep;
// contracts/events-and-tasks.md): exactly one service instance holds a
// lease at a time. A lease is a key set with NX and a TTL (default 30 s)
// holding a random owner value; the holder renews it every 10 s and releases
// it on exit. Renew and release compare the owner value first (atomically in
// Valkey), so a holder that lost its lease can never extend or delete the new
// holder's.
package lease

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Defaults (contracts: TTL 30 s, renew every 10 s).
const (
	DefaultTTL   = 30 * time.Second
	DefaultRenew = 10 * time.Second
)

// ErrLost is returned when the lease expired or was taken by another holder.
var ErrLost = errors.New("lease: lost")

// KV is the atomic key operations a lease needs.
type KV interface {
	// SetNX sets key to val with ttl if key is absent.
	SetNX(ctx context.Context, key, val string, ttl time.Duration) (bool, error)
	// CompareAndExpire resets key's ttl if it still holds val.
	CompareAndExpire(ctx context.Context, key, val string, ttl time.Duration) (bool, error)
	// CompareAndDelete deletes key if it still holds val.
	CompareAndDelete(ctx context.Context, key, val string) (bool, error)
}

// Lease is one held lease.
type Lease struct {
	kv    KV
	key   string
	owner string
	ttl   time.Duration
}

// Key is the leased key.
func (l *Lease) Key() string { return l.key }

func ownerID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never fails on supported platforms
	return hex.EncodeToString(b)
}

// Acquire tries to take key. ok is false (and err nil) when another holder
// has it.
func Acquire(ctx context.Context, kv KV, key string, ttl time.Duration) (l *Lease, ok bool, err error) {
	if kv == nil || key == "" {
		return nil, false, errors.New("lease: kv and key required")
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	l = &Lease{kv: kv, key: key, owner: ownerID(), ttl: ttl}
	ok, err = kv.SetNX(ctx, key, l.owner, ttl)
	if err != nil || !ok {
		return nil, false, err
	}
	return l, true, nil
}

// Renew extends the lease by its TTL; ErrLost when it is no longer held.
func (l *Lease) Renew(ctx context.Context) error {
	ok, err := l.kv.CompareAndExpire(ctx, l.key, l.owner, l.ttl)
	if err != nil {
		return err
	}
	if !ok {
		return ErrLost
	}
	return nil
}

// Release gives the lease up (a no-op when it is no longer held).
func (l *Lease) Release(ctx context.Context) error {
	_, err := l.kv.CompareAndDelete(ctx, l.key, l.owner)
	return err
}

// Options tune Run.
type Options struct {
	TTL   time.Duration // default DefaultTTL
	Renew time.Duration // default DefaultRenew
}

// Run acquires key and runs fn under it, renewing every Renew. fn's context
// is cancelled when the lease is lost (ErrLost is returned) or ctx ends. A
// renewal transport error is tolerated until the TTL since the last good
// renewal has passed, after which the lease counts as lost. ran is false when
// another holder has the lease.
func Run(ctx context.Context, kv KV, key string, o Options, fn func(ctx context.Context)) (ran bool, err error) {
	if o.TTL <= 0 {
		o.TTL = DefaultTTL
	}
	if o.Renew <= 0 {
		o.Renew = DefaultRenew
	}
	l, ok, err := Acquire(ctx, kv, key, o.TTL)
	if err != nil || !ok {
		return false, err
	}
	work, cancel := context.WithCancel(ctx)
	var lost error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(o.Renew)
		defer t.Stop()
		lastOK := time.Now()
		for {
			select {
			case <-work.Done():
				return
			case <-t.C:
				err := l.Renew(work)
				switch {
				case err == nil:
					lastOK = time.Now()
				case errors.Is(err, ErrLost) || time.Since(lastOK) >= o.TTL:
					lost = ErrLost
					cancel()
					return
				}
			}
		}
	}()
	fn(work)
	cancel()
	wg.Wait()
	rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer rcancel()
	_ = l.Release(rctx)
	return true, lost
}

// ---- memory

// Memory is an in-process KV for tests and single-instance development.
type Memory struct {
	mu  sync.Mutex
	m   map[string]memEntry
	err error
	// Now is the clock (overridable in tests).
	Now func() time.Time

	onRenew func() // test hook, called before each CompareAndExpire
}

type memEntry struct {
	val string
	exp time.Time
}

// NewMemory builds an empty Memory KV.
func NewMemory() *Memory { return &Memory{m: map[string]memEntry{}, Now: time.Now} }

// SetErr makes every operation fail with err (nil clears).
func (m *Memory) SetErr(err error) {
	m.mu.Lock()
	m.err = err
	m.mu.Unlock()
}

// live returns key's entry if present and unexpired. Callers hold mu.
func (m *Memory) live(key string) (memEntry, bool) {
	e, ok := m.m[key]
	if ok && !m.Now().Before(e.exp) {
		delete(m.m, key)
		return memEntry{}, false
	}
	return e, ok
}

// SetNX implements KV.
func (m *Memory) SetNX(_ context.Context, key, val string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return false, m.err
	}
	if _, ok := m.live(key); ok {
		return false, nil
	}
	m.m[key] = memEntry{val: val, exp: m.Now().Add(ttl)}
	return true, nil
}

// CompareAndExpire implements KV.
func (m *Memory) CompareAndExpire(_ context.Context, key, val string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	hook := m.onRenew
	m.mu.Unlock()
	if hook != nil {
		hook()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return false, m.err
	}
	e, ok := m.live(key)
	if !ok || e.val != val {
		return false, nil
	}
	e.exp = m.Now().Add(ttl)
	m.m[key] = e
	return true, nil
}

// CompareAndDelete implements KV.
func (m *Memory) CompareAndDelete(_ context.Context, key, val string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return false, m.err
	}
	e, ok := m.live(key)
	if !ok || e.val != val {
		return false, nil
	}
	delete(m.m, key)
	return true, nil
}

// Held reports whether key is currently leased.
func (m *Memory) Held(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.live(key)
	return ok
}

// steal hands key to another owner (tests).
func (m *Memory) steal(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.m[key] = memEntry{val: "thief", exp: m.Now().Add(time.Hour)}
}

var _ KV = (*Memory)(nil)
