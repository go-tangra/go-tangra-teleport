package lease

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var ctx = context.Background()

func TestDefaults(t *testing.T) {
	if DefaultTTL != 30*time.Second || DefaultRenew != 10*time.Second {
		t.Fatal("contract: TTL 30 s, renew every 10 s")
	}
}

func TestAcquireRenewRelease(t *testing.T) {
	kv := NewMemory()
	a, ok, err := Acquire(ctx, kv, "watch:c1", time.Minute)
	if err != nil || !ok || a.Key() != "watch:c1" {
		t.Fatalf("acquire %v %v", ok, err)
	}
	// A second holder is refused while the lease is held.
	if _, ok, err := Acquire(ctx, kv, "watch:c1", time.Minute); ok || err != nil {
		t.Fatalf("second acquire %v %v", ok, err)
	}
	if err := a.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Release(ctx); err != nil {
		t.Fatal(err)
	}
	// Released: renewal fails with ErrLost; release is idempotent.
	if err := a.Renew(ctx); !errors.Is(err, ErrLost) {
		t.Fatalf("renew after release %v", err)
	}
	if err := a.Release(ctx); err != nil {
		t.Fatal(err)
	}
	b, ok, _ := Acquire(ctx, kv, "watch:c1", time.Minute)
	if !ok {
		t.Fatal("re-acquire")
	}
	// The old holder can neither renew nor release the new holder's lease.
	if err := a.Renew(ctx); !errors.Is(err, ErrLost) {
		t.Fatal("stale renew")
	}
	_ = a.Release(ctx)
	if !kv.Held("watch:c1") {
		t.Fatal("stale release removed the new lease")
	}
	_ = b.Release(ctx)
	if kv.Held("watch:c1") {
		t.Fatal("release")
	}
}

func TestExpiry(t *testing.T) {
	kv := NewMemory()
	now := time.Unix(1000, 0)
	kv.Now = func() time.Time { return now }
	a, ok, _ := Acquire(ctx, kv, "k", 30*time.Second)
	if !ok {
		t.Fatal("acquire")
	}
	now = now.Add(31 * time.Second)
	if kv.Held("k") {
		t.Fatal("expired lease still held")
	}
	if err := a.Renew(ctx); !errors.Is(err, ErrLost) {
		t.Fatal("renew after expiry")
	}
	if _, ok, _ := Acquire(ctx, kv, "k", 30*time.Second); !ok {
		t.Fatal("acquire after expiry")
	}
}

func TestErrors(t *testing.T) {
	kv := NewMemory()
	kv.SetErr(errors.New("down"))
	if _, _, err := Acquire(ctx, kv, "k", time.Second); err == nil {
		t.Fatal("acquire error")
	}
	kv.SetErr(nil)
	a, _, _ := Acquire(ctx, kv, "k", time.Second)
	kv.SetErr(errors.New("down"))
	if err := a.Renew(ctx); err == nil || errors.Is(err, ErrLost) {
		t.Fatalf("renew transport error %v", err)
	}
	if err := a.Release(ctx); err == nil {
		t.Fatal("release error")
	}
	if _, _, err := Acquire(ctx, kv, "", time.Second); err == nil {
		t.Fatal("empty key")
	}
	if _, _, err := Acquire(ctx, nil, "k", time.Second); err == nil {
		t.Fatal("nil kv")
	}
	kv.SetErr(nil)
	if _, ok, err := Acquire(ctx, kv, "zero-ttl", 0); !ok || err != nil {
		t.Fatal("zero ttl uses the default")
	}
}

func TestRunHoldsAndRenews(t *testing.T) {
	kv := NewMemory()
	var renewals atomic.Int32
	kv.onRenew = func() { renewals.Add(1) }
	ran, err := Run(ctx, kv, "k", Options{TTL: time.Second, Renew: 10 * time.Millisecond}, func(ctx context.Context) {
		deadline := time.After(2 * time.Second)
		for renewals.Load() < 3 {
			select {
			case <-deadline:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	})
	if err != nil || !ran || renewals.Load() < 3 {
		t.Fatalf("ran=%v err=%v renewals=%d", ran, err, renewals.Load())
	}
	if kv.Held("k") {
		t.Fatal("lease not released after Run")
	}
}

func TestRunSkipsWhenHeld(t *testing.T) {
	kv := NewMemory()
	_, _, _ = Acquire(ctx, kv, "k", time.Minute)
	ran, err := Run(ctx, kv, "k", Options{}, func(context.Context) { t.Fatal("ran without the lease") })
	if ran || err != nil {
		t.Fatal(ran, err)
	}
	kv.SetErr(errors.New("down"))
	if _, err := Run(ctx, kv, "other", Options{}, func(context.Context) {}); err == nil {
		t.Fatal("acquire error")
	}
}

func TestRunCancelsWhenLeaseLost(t *testing.T) {
	kv := NewMemory()
	var once sync.Once
	kv.onRenew = func() { once.Do(func() { kv.steal("k") }) }
	done := make(chan struct{})
	ran, err := Run(ctx, kv, "k", Options{TTL: time.Second, Renew: 5 * time.Millisecond}, func(ctx context.Context) {
		select {
		case <-ctx.Done():
			close(done)
		case <-time.After(2 * time.Second):
		}
	})
	if !ran || !errors.Is(err, ErrLost) {
		t.Fatalf("ran=%v err=%v", ran, err)
	}
	select {
	case <-done:
	default:
		t.Fatal("work context not cancelled on lease loss")
	}
	if !kv.Held("k") {
		t.Fatal("the thief's lease must survive the loser's release")
	}
}

func TestRunStopsOnParentCancel(t *testing.T) {
	kv := NewMemory()
	c, cancel := context.WithCancel(ctx)
	ran, err := Run(c, kv, "k", Options{TTL: time.Second, Renew: time.Millisecond}, func(ctx context.Context) {
		cancel()
		<-ctx.Done()
	})
	if !ran || err != nil {
		t.Fatal(ran, err)
	}
}

func TestRunToleratesTransientRenewError(t *testing.T) {
	kv := NewMemory()
	var n atomic.Int32
	kv.onRenew = func() {
		if n.Add(1) == 1 {
			kv.SetErr(errors.New("blip"))
		} else {
			kv.SetErr(nil)
		}
	}
	ran, err := Run(ctx, kv, "k", Options{TTL: time.Second, Renew: 5 * time.Millisecond}, func(context.Context) {
		deadline := time.After(2 * time.Second)
		for n.Load() < 3 {
			select {
			case <-deadline:
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	})
	if !ran || err != nil || n.Load() < 3 {
		t.Fatalf("ran=%v err=%v n=%d", ran, err, n.Load())
	}
}
