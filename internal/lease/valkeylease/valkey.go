// Package valkeylease binds lease.KV to a Valkey server. Renew and release
// are Lua scripts so the owner comparison and the write are atomic. It is
// exercised by the integration suite against a real server; unit tests use
// lease.Memory.
package valkeylease

import (
	"context"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/lease"
)

var (
	expireScript = valkey.NewLuaScript(`if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("PEXPIRE", KEYS[1], ARGV[2]) else return 0 end`)
	deleteScript = valkey.NewLuaScript(`if redis.call("GET", KEYS[1]) == ARGV[1] then return redis.call("DEL", KEYS[1]) else return 0 end`)
)

// KV is a lease.KV over a valkey.Client.
type KV struct{ C valkey.Client }

// SetNX implements lease.KV (SET key val NX PX ttl).
func (k KV) SetNX(ctx context.Context, key, val string, ttl time.Duration) (bool, error) {
	err := k.C.Do(ctx, k.C.B().Set().Key(key).Value(val).Nx().PxMilliseconds(ttl.Milliseconds()).Build()).Error()
	if valkey.IsValkeyNil(err) {
		return false, nil
	}
	return err == nil, err
}

// CompareAndExpire implements lease.KV.
func (k KV) CompareAndExpire(ctx context.Context, key, val string, ttl time.Duration) (bool, error) {
	n, err := expireScript.Exec(ctx, k.C, []string{key}, []string{val, formatMS(ttl)}).AsInt64()
	return n == 1, err
}

// CompareAndDelete implements lease.KV.
func (k KV) CompareAndDelete(ctx context.Context, key, val string) (bool, error) {
	n, err := deleteScript.Exec(ctx, k.C, []string{key}, []string{val}).AsInt64()
	return n == 1, err
}

func formatMS(d time.Duration) string { return strconv.FormatInt(max(d.Milliseconds(), 1), 10) }

var _ lease.KV = KV{}
