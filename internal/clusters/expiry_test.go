package clusters_test

import (
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
)

const day = 24 * time.Hour

func TestEvaluateExpiry(t *testing.T) {
	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	long := issued.Add(30 * day)       // 30-day identity: 7-day threshold
	short := issued.Add(8 * time.Hour) // 8-hour identity: 25% = 2 h
	week := issued.Add(10 * day)       // 10 days: 25% = 2.5 d < 7 d
	for _, c := range []struct {
		name            string
		issued, expires time.Time
		now             time.Time
		stage           clusters.Stage
		threshold       time.Duration
	}{
		{"long, fresh", issued, long, issued.Add(day), clusters.StageNone, 7 * day},
		{"long, 8 days left", issued, long, long.Add(-8 * day), clusters.StageNone, 7 * day},
		{"long, 7 days left", issued, long, long.Add(-7 * day), clusters.StageWarn, 7 * day},
		{"long, 2 days left", issued, long, long.Add(-2 * day), clusters.StageWarn, 7 * day},
		{"long, 1 day left", issued, long, long.Add(-day), clusters.StageDay, 7 * day},
		{"long, 1 hour left", issued, long, long.Add(-time.Hour), clusters.StageDay, 7 * day},
		{"long, expired", issued, long, long, clusters.StageExpired, 7 * day},
		{"short, 3 h left", issued, short, short.Add(-3 * time.Hour), clusters.StageNone, 2 * time.Hour},
		{"short, 2 h left", issued, short, short.Add(-2 * time.Hour), clusters.StageWarn, 2 * time.Hour},
		{"short, 1 h left (no 1-day stage below the threshold)", issued, short, short.Add(-time.Hour), clusters.StageWarn, 2 * time.Hour},
		{"short, expired", issued, short, short.Add(time.Minute), clusters.StageExpired, 2 * time.Hour},
		{"10 days, 3 days left", issued, week, week.Add(-3 * day), clusters.StageNone, 60 * time.Hour},
		{"10 days, 2 days left", issued, week, week.Add(-2 * day), clusters.StageWarn, 60 * time.Hour},
		{"10 days, 20 h left", issued, week, week.Add(-20 * time.Hour), clusters.StageDay, 60 * time.Hour},
		{"unknown issue time: long-lived rules", time.Time{}, long, long.Add(-6 * day), clusters.StageWarn, 7 * day},
		{"no expiry", issued, time.Time{}, issued, clusters.StageNone, 0},
	} {
		e := clusters.EvaluateExpiry(c.issued, c.expires, c.now, 7*day)
		if e.Stage != c.stage || e.Threshold != c.threshold {
			t.Errorf("%s: stage %q threshold %v, want %q %v", c.name, e.Stage, e.Threshold, c.stage, c.threshold)
		}
		if !c.expires.IsZero() && e.Remaining != c.expires.Sub(c.now) {
			t.Errorf("%s: remaining %v", c.name, e.Remaining)
		}
	}
	if !clusters.StageWarn.Expiring() || !clusters.StageDay.Expiring() || clusters.StageExpired.Expiring() || clusters.StageNone.Expiring() {
		t.Fatal("Expiring")
	}
	// A zero warn threshold falls back to the 7-day default.
	if e := clusters.EvaluateExpiry(issued, long, long.Add(-6*day), 0); e.Stage != clusters.StageWarn {
		t.Fatalf("default threshold: %+v", e)
	}
}
