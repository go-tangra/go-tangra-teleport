// Package valkeycache binds teleportapi.CacheKV to a Valkey server. It is
// exercised by the integration suite against a real server; unit tests use
// teleportapi.MemoryKV.
package valkeycache

import (
	"context"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// KV is a teleportapi.CacheKV over a valkey.Client.
type KV struct{ C valkey.Client }

// Get implements teleportapi.CacheKV.
func (k KV) Get(ctx context.Context, key string) (string, bool, error) {
	v, err := k.C.Do(ctx, k.C.B().Get().Key(key).Build()).ToString()
	if valkey.IsValkeyNil(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// Set implements teleportapi.CacheKV (SET key val PX ttl).
func (k KV) Set(ctx context.Context, key, val string, ttl time.Duration) error {
	return k.C.Do(ctx, k.C.B().Set().Key(key).Value(val).PxMilliseconds(max(ttl.Milliseconds(), 1)).Build()).Error()
}

// Incr implements teleportapi.CacheKV.
func (k KV) Incr(ctx context.Context, key string) (int64, error) {
	return k.C.Do(ctx, k.C.B().Incr().Key(key).Build()).AsInt64()
}

var _ teleportapi.CacheKV = KV{}
