// Package metrics holds the Teleport module's Prometheus instruments, adapted
// from dns-v4 internal/metrics. They are created on the framework's meter
// (freya App.Metrics().Meter), so the admin listener's /metrics renders them
// next to the framework instruments:
//
//	teleport_api_calls_total{op,result}             Teleport API calls by outcome
//	teleport_api_call_seconds{op}                   Teleport API call latency (histogram)
//	teleport_watchers{state}                        watchers by state (running|backoff|stopped)
//	teleport_alert_poll_lag_seconds                 audit poll lag behind now (histogram)
//	teleport_provisioning_total{action,result}      provisioning outcomes
//	teleport_credential_days_to_expiry_min          days until the soonest credential expiry
//
// Labels carry closed vocabularies only (never tenants, cluster names,
// usernames or ids). Every method is nil-safe so services can run without
// metrics in tests.
package metrics

import (
	"context"

	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Scope is the instrumentation scope name.
const Scope = "github.com/go-tangra/go-tangra-teleport/v4"

// Results (closed set: the teleportapi reasons plus ok).
const (
	ResultOK                = "ok"
	ResultNotFound          = "not_found"
	ResultConflict          = "conflict"
	ResultRejected          = "teleport_rejected"
	ResultUnreachable       = "cluster_unreachable"
	ResultCredentialInvalid = "credential_invalid" // #nosec G101 -- a name, not a credential
	ResultBlockedTarget     = "blocked_target"
	ResultError             = "error"
)

// Watcher states.
const (
	WatcherRunning = "running"
	WatcherBackoff = "backoff"
	WatcherStopped = "stopped"
)

// Provisioning actions.
const (
	ProvisionCreate = "create"
	ProvisionUpdate = "update"
	ProvisionLock   = "lock"
	ProvisionDelete = "delete"
)

// Metrics are the module instruments.
type Metrics struct {
	calls     metric.Int64Counter
	callTime  metric.Float64Histogram
	watchers  metric.Int64Gauge
	pollLag   metric.Float64Histogram
	provision metric.Int64Counter
	credDays  metric.Float64Gauge
}

// New creates the instruments on meter.
func New(meter metric.Meter) (*Metrics, error) {
	m := &Metrics{}
	var err error
	if m.calls, err = meter.Int64Counter("teleport.api.calls", metric.WithDescription("Teleport API calls by operation and result")); err != nil {
		return nil, err
	}
	if m.callTime, err = meter.Float64Histogram("teleport.api.call", metric.WithUnit("s"), metric.WithDescription("Teleport API call latency"),
		metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)); err != nil {
		return nil, err
	}
	if m.watchers, err = meter.Int64Gauge("teleport.watchers", metric.WithDescription("Teleport resource watchers by state")); err != nil {
		return nil, err
	}
	if m.pollLag, err = meter.Float64Histogram("teleport.alert.poll.lag", metric.WithUnit("s"), metric.WithDescription("Audit event poll lag behind now"),
		metric.WithExplicitBucketBoundaries(1, 5, 15, 30, 60, 120, 300, 900)); err != nil {
		return nil, err
	}
	if m.provision, err = meter.Int64Counter("teleport.provisioning", metric.WithDescription("Provisioning outcomes by action and result")); err != nil {
		return nil, err
	}
	if m.credDays, err = meter.Float64Gauge("teleport.credential.days_to_expiry.min", metric.WithDescription("Days until the soonest management credential expiry")); err != nil {
		return nil, err
	}
	return m, nil
}

// Call records one Teleport API call.
func (m *Metrics) Call(op, result string, d time.Duration) {
	if m == nil {
		return
	}
	m.calls.Add(context.Background(), 1, metric.WithAttributes(attribute.String("op", op), attribute.String("result", result)))
	m.callTime.Record(context.Background(), d.Seconds(), metric.WithAttributes(attribute.String("op", op)))
}

// SetWatchers sets the number of watchers in state.
func (m *Metrics) SetWatchers(state string, n int64) {
	if m != nil {
		m.watchers.Record(context.Background(), n, metric.WithAttributes(attribute.String("state", state)))
	}
}

// PollLag records how far an audit poll trails now.
func (m *Metrics) PollLag(d time.Duration) {
	if m != nil {
		m.pollLag.Record(context.Background(), d.Seconds())
	}
}

// Provision records one provisioning outcome.
func (m *Metrics) Provision(action, result string) {
	if m != nil {
		m.provision.Add(context.Background(), 1, metric.WithAttributes(attribute.String("action", action), attribute.String("result", result)))
	}
}

// SetCredentialDaysToExpiry sets the soonest credential expiry, in days.
func (m *Metrics) SetCredentialDaysToExpiry(days float64) {
	if m != nil {
		m.credDays.Record(context.Background(), days)
	}
}
