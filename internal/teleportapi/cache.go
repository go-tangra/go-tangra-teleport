package teleportapi

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"
)

// DefaultCacheTTL is the read-cache lifetime (research D4).
const DefaultCacheTTL = 15 * time.Second

// CacheKV is the storage the read cache needs (Valkey in production).
type CacheKV interface {
	Get(ctx context.Context, key string) (val string, ok bool, err error)
	Set(ctx context.Context, key, val string, ttl time.Duration) error
	Incr(ctx context.Context, key string) (int64, error)
}

// Cache is the short read cache in front of Teleport lists, keyed by tenant
// and cluster. Invalidate bumps the cluster's generation counter so every
// cached entry of that cluster is abandoned at once (watcher events and the
// module's own writes call it). Only read results without secret material
// (users are listed without secrets) go through it; a KV failure degrades to
// a direct load, never to an error.
type Cache struct {
	KV  CacheKV
	TTL time.Duration // default 15 s
}

func (c *Cache) ttl() time.Duration {
	if c.TTL <= 0 {
		return DefaultCacheTTL
	}
	return c.TTL
}

func genKey(tenantID, clusterID string) string {
	return "teleport:cache:gen:" + tenantID + ":" + clusterID
}

func (c *Cache) dataKey(tenantID, clusterID, gen, op string) string {
	return "teleport:cache:" + tenantID + ":" + clusterID + ":" + gen + ":" + op
}

// Cached returns op's cached value for the cluster, or loads and caches it.
func Cached[T any](ctx context.Context, c *Cache, tenantID, clusterID, op string, load func(context.Context) (T, error)) (T, error) {
	if c == nil || c.KV == nil {
		return load(ctx)
	}
	gen, ok, err := c.KV.Get(ctx, genKey(tenantID, clusterID))
	if err != nil {
		return load(ctx)
	}
	if !ok {
		gen = "0"
	}
	key := c.dataKey(tenantID, clusterID, gen, op)
	if raw, ok, err := c.KV.Get(ctx, key); err == nil && ok {
		var v T
		if json.Unmarshal([]byte(raw), &v) == nil {
			return v, nil
		}
	}
	v, err := load(ctx)
	if err != nil {
		return v, err
	}
	if b, err := json.Marshal(v); err == nil {
		_ = c.KV.Set(ctx, key, string(b), c.ttl())
	}
	return v, nil
}

// Invalidate abandons every cached entry of the cluster.
func (c *Cache) Invalidate(ctx context.Context, tenantID, clusterID string) error {
	if c == nil || c.KV == nil {
		return nil
	}
	_, err := c.KV.Incr(ctx, genKey(tenantID, clusterID))
	return err
}

// ---- memory

// MemoryKV is an in-process CacheKV for tests and development.
type MemoryKV struct {
	mu  sync.Mutex
	m   map[string]memVal
	err error
	// Now is the clock (overridable in tests).
	Now func() time.Time
}

type memVal struct {
	v   string
	exp time.Time // zero: no expiry
}

// NewMemoryKV builds an empty MemoryKV.
func NewMemoryKV() *MemoryKV { return &MemoryKV{m: map[string]memVal{}, Now: time.Now} }

// SetErr makes every operation fail with err (nil clears).
func (m *MemoryKV) SetErr(err error) {
	m.mu.Lock()
	m.err = err
	m.mu.Unlock()
}

// Len is the number of live keys.
func (m *MemoryKV) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.m)
}

// Get implements CacheKV.
func (m *MemoryKV) Get(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return "", false, m.err
	}
	v, ok := m.m[key]
	if ok && !v.exp.IsZero() && !m.Now().Before(v.exp) {
		delete(m.m, key)
		return "", false, nil
	}
	return v.v, ok, nil
}

// Set implements CacheKV.
func (m *MemoryKV) Set(_ context.Context, key, val string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.m[key] = memVal{v: val, exp: m.Now().Add(ttl)}
	return nil
}

// Incr implements CacheKV (the counter never expires).
func (m *MemoryKV) Incr(_ context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return 0, m.err
	}
	n, err := strconv.ParseInt(m.m[key].v, 10, 64)
	if err != nil && m.m[key].v != "" {
		return 0, errors.New("memorykv: not an integer")
	}
	n++
	m.m[key] = memVal{v: strconv.FormatInt(n, 10)}
	return n, nil
}

var _ CacheKV = (*MemoryKV)(nil)
