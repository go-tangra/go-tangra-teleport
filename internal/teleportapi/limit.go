package teleportapi

import (
	"context"
	"time"
)

// Limits bound calls to one cluster (config teleport.*).
type Limits struct {
	CallTimeout     time.Duration // per call, default 10 s
	MaxMessageBytes int           // per gRPC message, default 4 MiB
	MaxConcurrent   int           // calls in flight per cluster, default 4
}

func (l Limits) withDefaults() Limits {
	if l.CallTimeout <= 0 {
		l.CallTimeout = 10 * time.Second
	}
	if l.MaxMessageBytes <= 0 {
		l.MaxMessageBytes = 4 << 20
	}
	if l.MaxConcurrent <= 0 {
		l.MaxConcurrent = 4
	}
	return l
}

// limited wraps a Client with the per-call timeout, the per-cluster
// semaphore and error mapping.
type limited struct {
	inner Client
	l     Limits
	sem   chan struct{}
}

// Limit wraps c with l (defaults applied).
func Limit(c Client, l Limits) Client {
	l = l.withDefaults()
	return &limited{inner: c, l: l, sem: make(chan struct{}, l.MaxConcurrent)}
}

// enter takes a semaphore slot within the call deadline.
func (c *limited) enter(ctx context.Context) (context.Context, func(), error) {
	ctx, cancel := context.WithTimeout(ctx, c.l.CallTimeout)
	select {
	case c.sem <- struct{}{}:
		return ctx, func() { <-c.sem; cancel() }, nil
	case <-ctx.Done():
		cancel()
		return nil, nil, MapError(ctx.Err())
	}
}

func call[T any](c *limited, ctx context.Context, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	ctx, done, err := c.enter(ctx)
	if err != nil {
		return zero, err
	}
	defer done()
	v, err := fn(ctx)
	if err != nil {
		return zero, MapError(err)
	}
	return v, nil
}

func (c *limited) Ping(ctx context.Context) (Info, error) { return call(c, ctx, c.inner.Ping) }

func (c *limited) ListUsers(ctx context.Context, o ListOptions) (Page[User], error) {
	return call(c, ctx, func(ctx context.Context) (Page[User], error) { return c.inner.ListUsers(ctx, o) })
}

func (c *limited) GetUser(ctx context.Context, name string) (User, error) {
	return call(c, ctx, func(ctx context.Context) (User, error) { return c.inner.GetUser(ctx, name) })
}

func (c *limited) ListRoles(ctx context.Context, o ListOptions) (Page[Role], error) {
	return call(c, ctx, func(ctx context.Context) (Page[Role], error) { return c.inner.ListRoles(ctx, o) })
}

func (c *limited) GetRole(ctx context.Context, name string) (Role, error) {
	return call(c, ctx, func(ctx context.Context) (Role, error) { return c.inner.GetRole(ctx, name) })
}

func (c *limited) ListLocks(ctx context.Context) ([]Lock, error) {
	return call(c, ctx, c.inner.ListLocks)
}

func (c *limited) ListResources(ctx context.Context, kind string, o ListOptions) (Page[Resource], error) {
	return call(c, ctx, func(ctx context.Context) (Page[Resource], error) { return c.inner.ListResources(ctx, kind, o) })
}

func (c *limited) Close() error { return c.inner.Close() }
