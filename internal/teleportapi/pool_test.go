package teleportapi

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPoolKeysByClusterAndCredential(t *testing.T) {
	var dials atomic.Int32
	fakes := map[Key]*Fake{}
	var mu sync.Mutex
	p := NewPool(func(_ context.Context, k Key) (Client, error) {
		dials.Add(1)
		f := NewFake()
		mu.Lock()
		fakes[k] = f
		mu.Unlock()
		return f, nil
	})
	k1 := Key{ClusterID: "c1", CredentialRef: "warden:a"}
	a, err := p.Get(ctx, k1)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := p.Get(ctx, k1)
	if a != b || dials.Load() != 1 {
		t.Fatal("same key must reuse the connection")
	}
	// Another cluster gets its own connection.
	if c, _ := p.Get(ctx, Key{ClusterID: "c2", CredentialRef: "warden:a"}); c == a {
		t.Fatal("clusters share a connection")
	}
	// Credential rotation (new ref) closes the old connection and dials anew.
	k1b := Key{ClusterID: "c1", CredentialRef: "warden:b"}
	c, _ := p.Get(ctx, k1b)
	if c == a || !fakes[k1].Closed() || dials.Load() != 3 {
		t.Fatal("rotation did not replace the connection")
	}
	// Invalidate closes and forgets.
	p.Invalidate("c1")
	if !fakes[k1b].Closed() || p.Len() != 1 {
		t.Fatal("invalidate")
	}
	p.Invalidate("missing")
	p.Close()
	if p.Len() != 0 {
		t.Fatal("close")
	}
	if _, err := p.Get(ctx, k1); !errors.Is(err, ErrPoolClosed) {
		t.Fatal("get after close")
	}
}

func TestPoolDialError(t *testing.T) {
	p := NewPool(func(context.Context, Key) (Client, error) { return nil, ErrUnreachable })
	if _, err := p.Get(ctx, Key{ClusterID: "c"}); !errors.Is(err, ErrUnreachable) {
		t.Fatal(err)
	}
	if p.Len() != 0 {
		t.Fatal("failed dial cached")
	}
}

func TestPoolConcurrentDialKeepsOne(t *testing.T) {
	var closed atomic.Int32
	gate := make(chan struct{})
	p := NewPool(func(context.Context, Key) (Client, error) {
		<-gate
		return &closeCounter{Fake: NewFake(), n: &closed}, nil
	})
	k := Key{ClusterID: "c", CredentialRef: "r"}
	var wg sync.WaitGroup
	got := make([]Client, 4)
	for i := range got {
		wg.Add(1)
		go func() { defer wg.Done(); got[i], _ = p.Get(ctx, k) }()
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()
	for _, c := range got[1:] {
		if c != got[0] {
			t.Fatal("concurrent gets returned different clients")
		}
	}
	if int(closed.Load()) != len(got)-1 {
		t.Fatalf("surplus connections closed: %d", closed.Load())
	}
	// A concurrent dial that loses to a rotation is closed, not returned stale.
	p.Close()
}

type closeCounter struct {
	*Fake
	n *atomic.Int32
}

func (c *closeCounter) Close() error { c.n.Add(1); return nil }
