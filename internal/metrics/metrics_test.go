package metrics

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/go-tangra/go-tangra/v4/observe"
)

func TestInstrumentsRenderOnAdminHandler(t *testing.T) {
	fm, err := observe.NewMetrics()
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(fm.Meter(Scope))
	if err != nil {
		t.Fatal(err)
	}
	m.Call("ListUsers", ResultOK, 20*time.Millisecond)
	m.Call("ListUsers", ResultOK, 30*time.Millisecond)
	m.Call("Ping", ResultUnreachable, time.Second)
	m.SetWatchers(WatcherRunning, 3)
	m.SetWatchers(WatcherBackoff, 1)
	m.PollLag(12 * time.Second)
	m.Provision(ProvisionCreate, ResultOK)
	m.Provision(ProvisionLock, ResultRejected)
	m.SetCredentialDaysToExpiry(6.5)
	rec := httptest.NewRecorder()
	fm.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`teleport_api_calls_total{op="ListUsers",result="ok"} 2`,
		`teleport_api_calls_total{op="Ping",result="cluster_unreachable"} 1`,
		`teleport_api_call_seconds_count{op="ListUsers"} 2`,
		`teleport_watchers{state="running"} 3`,
		`teleport_watchers{state="backoff"} 1`,
		`teleport_alert_poll_lag_seconds_count 1`,
		`teleport_provisioning_total{action="create",result="ok"} 1`,
		`teleport_provisioning_total{action="lock",result="teleport_rejected"} 1`,
		`teleport_credential_days_to_expiry_min 6.5`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s in:\n%s", want, body)
		}
	}
}

func TestNilSafe(t *testing.T) {
	var m *Metrics
	m.Call("x", ResultError, time.Second)
	m.SetWatchers(WatcherStopped, 0)
	m.PollLag(time.Second)
	m.Provision(ProvisionDelete, ResultError)
	m.SetCredentialDaysToExpiry(1)
	if _, err := New(noop.NewMeterProvider().Meter("x")); err != nil {
		t.Fatal(err)
	}
}

type failingMeter struct {
	noop.Meter
	failAt int
	n      *int
}

func (f failingMeter) step(name string) error {
	*f.n++
	if *f.n == f.failAt {
		return errors.New("boom " + name)
	}
	return nil
}

func (f failingMeter) Int64Counter(name string, _ ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	return noop.Int64Counter{}, f.step(name)
}

func (f failingMeter) Float64Histogram(name string, _ ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	return noop.Float64Histogram{}, f.step(name)
}

func (f failingMeter) Int64Gauge(name string, _ ...metric.Int64GaugeOption) (metric.Int64Gauge, error) {
	return noop.Int64Gauge{}, f.step(name)
}

func (f failingMeter) Float64Gauge(name string, _ ...metric.Float64GaugeOption) (metric.Float64Gauge, error) {
	return noop.Float64Gauge{}, f.step(name)
}

func TestNewPropagatesErrors(t *testing.T) {
	for i := 1; i <= 6; i++ {
		n := 0
		if _, err := New(failingMeter{failAt: i, n: &n}); err == nil {
			t.Errorf("instrument %d error swallowed", i)
		}
	}
}
