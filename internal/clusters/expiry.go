package clusters

import "time"

// DefaultWarnBefore is the long-lived credential threshold (FR-004).
const DefaultWarnBefore = 7 * 24 * time.Hour

// lastDay is the second warning stage of a long-lived credential.
const lastDay = 24 * time.Hour

// Stage is how close a credential is to expiry. Each stage is announced
// once (teleport.credential.expiring and the teleport.credential_expiring
// notification).
type Stage string

// Stages, in order.
const (
	StageNone    Stage = ""
	StageWarn    Stage = "warn"    // within the threshold
	StageDay     Stage = "day"     // within one day (long-lived credentials only)
	StageExpired Stage = "expired" // past NotAfter
)

// Expiring reports a warning stage (the cluster shows credential_expiring).
func (s Stage) Expiring() bool { return s == StageWarn || s == StageDay }

// Expiry is the evaluation of one credential.
type Expiry struct {
	Stage     Stage
	Threshold time.Duration // when the first warning starts, before expiry
	Remaining time.Duration
}

// EvaluateExpiry applies the FR-004 thresholds: warn at warn (default 7
// days) before expiry, or at 25% of the lifetime when that is shorter
// (short-lived identities); warn again with one day left when the threshold
// is longer than a day; then expired. An unknown issue time uses the
// long-lived rule; no expiry means nothing to warn about. Bot renewal is
// deferred (research D2), so evaluation is all this does.
func EvaluateExpiry(issued, expires, now time.Time, warn time.Duration) Expiry {
	if expires.IsZero() {
		return Expiry{}
	}
	if warn <= 0 {
		warn = DefaultWarnBefore
	}
	threshold := warn
	if !issued.IsZero() && expires.After(issued) {
		if quarter := expires.Sub(issued) / 4; quarter < threshold {
			threshold = quarter
		}
	}
	e := Expiry{Threshold: threshold, Remaining: expires.Sub(now)}
	switch {
	case !now.Before(expires):
		e.Stage = StageExpired
	case e.Remaining <= lastDay && threshold > lastDay:
		e.Stage = StageDay
	case e.Remaining <= threshold:
		e.Stage = StageWarn
	}
	return e
}
