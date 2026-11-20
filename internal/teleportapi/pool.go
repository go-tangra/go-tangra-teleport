package teleportapi

import (
	"context"
	"errors"
	"sync"
)

// ErrPoolClosed is returned by Get after Close.
var ErrPoolClosed = errors.New("teleportapi: pool closed")

// Key names one pooled connection: the cluster and the credential it signs
// in with. A new credential reference (rotation) replaces the connection.
// TenantID and ProxyAddr are dial inputs only; an address change is applied
// by Invalidate (cluster edit).
type Key struct {
	ClusterID     string
	CredentialRef string
	TenantID      string
	ProxyAddr     string
}

// DialFunc opens the connection for a key (resolving the credential and
// applying netguard and limits; see Dial).
type DialFunc func(ctx context.Context, k Key) (Client, error)

type pooled struct {
	ref string
	c   Client
}

// Pool keeps one connection per cluster.
type Pool struct {
	dial   DialFunc
	mu     sync.Mutex
	m      map[string]pooled
	closed bool
}

// NewPool builds a pool over dial.
func NewPool(dial DialFunc) *Pool { return &Pool{dial: dial, m: map[string]pooled{}} }

// Get returns the cluster's connection, dialling (outside the lock) when
// there is none or its credential changed.
func (p *Pool) Get(ctx context.Context, k Key) (Client, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrPoolClosed
	}
	if e, ok := p.m[k.ClusterID]; ok && e.ref == k.CredentialRef {
		p.mu.Unlock()
		return e.c, nil
	}
	p.mu.Unlock()

	c, err := p.dial(ctx, k)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		_ = c.Close()
		return nil, ErrPoolClosed
	}
	if e, ok := p.m[k.ClusterID]; ok {
		if e.ref == k.CredentialRef {
			// Another caller dialled the same key first: keep theirs.
			_ = c.Close()
			return e.c, nil
		}
		_ = e.c.Close()
	}
	p.m[k.ClusterID] = pooled{ref: k.CredentialRef, c: c}
	return c, nil
}

// Invalidate closes and forgets the cluster's connection (credential
// rotation, cluster removal, a credential_invalid answer).
func (p *Pool) Invalidate(clusterID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.m[clusterID]; ok {
		_ = e.c.Close()
		delete(p.m, clusterID)
	}
}

// Len is the number of open connections.
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.m)
}

// Close closes every connection; later Gets fail.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, e := range p.m {
		_ = e.c.Close()
		delete(p.m, id)
	}
	p.closed = true
}
