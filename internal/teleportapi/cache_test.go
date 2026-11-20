package teleportapi

import (
	"context"
	"errors"
	"testing"
	"time"
)

const (
	tA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	tB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c66"
)

func TestCacheHitsWithinTTL(t *testing.T) {
	kv := NewMemoryKV()
	now := time.Unix(1000, 0)
	kv.Now = func() time.Time { return now }
	c := &Cache{KV: kv}
	if c.ttl() != 15*time.Second {
		t.Fatal("default TTL is 15 s")
	}
	loads := 0
	load := func(context.Context) ([]User, error) { loads++; return []User{{Name: "alice"}}, nil }
	for range 3 {
		got, err := Cached(ctx, c, tA, "c1", "users", load)
		if err != nil || len(got) != 1 || got[0].Name != "alice" {
			t.Fatal(got, err)
		}
	}
	if loads != 1 {
		t.Fatalf("loads %d", loads)
	}
	// Keys are per tenant and per cluster.
	_, _ = Cached(ctx, c, tB, "c1", "users", load)
	_, _ = Cached(ctx, c, tA, "c2", "users", load)
	if loads != 3 {
		t.Fatalf("tenant/cluster isolation: loads %d", loads)
	}
	// Expiry.
	now = now.Add(16 * time.Second)
	_, _ = Cached(ctx, c, tA, "c1", "users", load)
	if loads != 4 {
		t.Fatalf("expiry: loads %d", loads)
	}
}

func TestCacheInvalidate(t *testing.T) {
	kv := NewMemoryKV()
	c := &Cache{KV: kv, TTL: time.Minute}
	loads := 0
	load := func(context.Context) (int, error) { loads++; return loads, nil }
	v1, _ := Cached(ctx, c, tA, "c1", "roles", load)
	if err := c.Invalidate(ctx, tA, "c1"); err != nil {
		t.Fatal(err)
	}
	v2, _ := Cached(ctx, c, tA, "c1", "roles", load)
	if v1 == v2 || loads != 2 {
		t.Fatal("invalidate did not force a reload")
	}
	// Invalidating one cluster leaves others cached.
	_, _ = Cached(ctx, c, tA, "c2", "roles", load)
	_ = c.Invalidate(ctx, tA, "c1")
	_, _ = Cached(ctx, c, tA, "c2", "roles", load)
	if loads != 3 {
		t.Fatalf("loads %d", loads)
	}
}

func TestCacheBypassAndErrors(t *testing.T) {
	loads := 0
	load := func(context.Context) (string, error) { loads++; return "v", nil }
	// nil cache loads directly.
	if v, err := Cached(ctx, nil, tA, "c", "op", load); err != nil || v != "v" {
		t.Fatal(v, err)
	}
	// Load errors are returned and not cached.
	kv := NewMemoryKV()
	c := &Cache{KV: kv}
	boom := errors.New("boom")
	if _, err := Cached(ctx, c, tA, "c", "op", func(context.Context) (string, error) { return "", boom }); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if kv.Len() != 0 {
		t.Fatal("error cached")
	}
	// A failing KV degrades to direct loads, never to an error.
	kv.SetErr(errors.New("valkey down"))
	loads = 0
	for range 2 {
		if v, err := Cached(ctx, c, tA, "c", "op", load); err != nil || v != "v" {
			t.Fatal(v, err)
		}
	}
	if loads != 2 {
		t.Fatalf("loads %d", loads)
	}
	if err := c.Invalidate(ctx, tA, "c"); err == nil {
		t.Fatal("invalidate must report the KV error")
	}
	if err := (*Cache)(nil).Invalidate(ctx, tA, "c"); err != nil {
		t.Fatal("nil cache invalidate")
	}
	// A corrupt cached value is ignored and reloaded.
	kv.SetErr(nil)
	_ = kv.Set(ctx, c.dataKey(tA, "c", "0", "op"), "{not json", time.Minute)
	loads = 0
	if v, _ := Cached(ctx, c, tA, "c", "op", load); v != "v" || loads != 1 {
		t.Fatal("corrupt entry")
	}
	// A value that cannot be encoded is returned uncached.
	ch, err := Cached(ctx, c, tA, "c", "chan", func(context.Context) (chan int, error) { return make(chan int), nil })
	if err != nil || ch == nil {
		t.Fatal("unencodable value")
	}
}
