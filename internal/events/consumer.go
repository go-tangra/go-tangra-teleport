package events

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/stream"
)

// Defaults of the tenant lifecycle consumer.
const (
	// DefaultTenantDeletedType is the event type the consumer reacts to.
	DefaultTenantDeletedType = "auth.tenant.deleted"
	// DefaultConsumerPoll is the blocking read period.
	DefaultConsumerPoll = 5 * time.Second
	consumerBatch       = 100
)

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// TenantHandler removes everything the module keeps for a deleted tenant
// (clusters.Service.PurgeTenant). It must be idempotent: a failed entry is
// handed over again on the next pass.
type TenantHandler func(ctx context.Context, tenantID string) error

// TenantConsumer applies tenant-deleted events (contracts/events-and-tasks.md,
// "Events consumed": remove the tenant's registrations and warden secrets;
// Teleport is untouched). It reads one platform-wide stream and handles only
// entries of Type whose data is {"tenant_id": "<uuid>"}; every other entry is
// skipped. The cursor starts at the stream's tail when the consumer first
// runs (no replay of history) and only moves past an entry once it was
// handled or refused as malformed, so a failed deletion is retried on the
// next pass. It runs as a leased worker (one replica at a time).
//
// auth v4 publishes no tenant lifecycle event yet (research D10, T118): the
// consumer is wired only when events.tenant_stream is configured.
type TenantConsumer struct {
	Bus    stream.Client
	Stream string // stream key, e.g. platform:events:system
	Type   string // default DefaultTenantDeletedType
	Handle TenantHandler
	Log    *slog.Logger
	Poll   time.Duration // default DefaultConsumerPoll

	cursor string
}

func (c *TenantConsumer) log() *slog.Logger {
	if c.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return c.Log
}

func (c *TenantConsumer) typ() string {
	if c.Type == "" {
		return DefaultTenantDeletedType
	}
	return c.Type
}

// ErrConsumer reports a consumer without a stream, bus or handler.
var ErrConsumer = errors.New("events: tenant consumer needs a bus, a stream and a handler")

// Run consumes until ctx ends.
func (c *TenantConsumer) Run(ctx context.Context) {
	poll := c.Poll
	if poll <= 0 {
		poll = DefaultConsumerPoll
	}
	for ctx.Err() == nil {
		if _, err := c.RunOnce(ctx, poll); err != nil && ctx.Err() == nil {
			c.log().WarnContext(ctx, "tenant consumer", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(poll):
			}
		}
	}
}

// RunOnce reads the next batch (blocking up to block) and applies it. It
// returns the number of tenants handled; an error is a bus failure or the
// first failed deletion (the cursor stays before that entry).
func (c *TenantConsumer) RunOnce(ctx context.Context, block time.Duration) (int, error) {
	if c.Bus == nil || c.Stream == "" || c.Handle == nil {
		return 0, ErrConsumer
	}
	if c.cursor == "" {
		last, err := c.Bus.XLast(ctx, c.Stream)
		if err != nil {
			return 0, err
		}
		if last == "" {
			last = "0-0"
		}
		c.cursor = last
	}
	entries, err := c.Bus.XRead(ctx, c.Stream, c.cursor, block, consumerBatch)
	if err != nil {
		return 0, err
	}
	handled := 0
	for _, e := range entries {
		if e.Fields["type"] == c.typ() {
			tenant, ok := tenantOf(e.Fields["data"])
			if !ok {
				c.log().WarnContext(ctx, "tenant consumer: malformed tenant-deleted event skipped", "id", e.ID)
			} else {
				if err := c.Handle(ctx, tenant); err != nil {
					return handled, err
				}
				handled++
				c.log().InfoContext(ctx, "tenant data removed", "tenant_id", tenant)
			}
		}
		c.cursor = e.ID
	}
	return handled, nil
}

// tenantOf extracts the tenant id from a tenant-deleted payload.
func tenantOf(data string) (string, bool) {
	var p struct {
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal([]byte(data), &p); err != nil || !uuidRE.MatchString(p.TenantID) {
		return "", false
	}
	return p.TenantID, true
}
