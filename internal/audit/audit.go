// Package audit records every Teleport-module operation in a closed
// `teleport.*` vocabulary (FR-024, SR-007): cluster, credential, user, role,
// lock, token, link, mapping, provisioning, alert and deployment changes plus
// backups and refusals. Adapted from dns-v4 internal/audit.
//
// The framework audit package is not used for these rows: its vocabulary is
// closed to framework security events, so (like dns-v4) the module keeps its
// own vocabulary and writes the audit_event hypertable itself (plan.md
// deviation).
//
// A detail guard keeps identity files, credentials, tokens, invite and reset
// URLs, install commands and other secret-bearing keys out of the log at any
// depth; role changes record before/after SHA-256 hashes, never YAML. Events
// are buffered and written by a background goroutine so recording never
// blocks the caller.
package audit

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
)

// Action is the closed audit vocabulary.
type Action string

// Actions.
const (
	ClusterRegister  Action = "teleport.cluster.register"
	ClusterUpdate    Action = "teleport.cluster.update"
	ClusterRemove    Action = "teleport.cluster.remove"
	ClusterCheck     Action = "teleport.cluster.check"
	CredentialRotate Action = "teleport.credential.rotate" // #nosec G101 -- a name, not a credential

	UserCreate Action = "teleport.user.create"
	UserUpdate Action = "teleport.user.update"
	UserReset  Action = "teleport.user.reset"
	UserDelete Action = "teleport.user.delete"

	RoleCreate Action = "teleport.role.create"
	RoleUpdate Action = "teleport.role.update"
	RoleDelete Action = "teleport.role.delete"

	LockCreate Action = "teleport.lock.create"
	LockDelete Action = "teleport.lock.delete"

	TokenCreate Action = "teleport.token.create"
	TokenRevoke Action = "teleport.token.revoke"

	EnrollmentCreate Action = "teleport.enrollment.create"
	EnrollmentRender Action = "teleport.enrollment.render"
	EnrollmentReport Action = "teleport.enrollment.report"
	EnrollmentCancel Action = "teleport.enrollment.cancel"
	EnrollmentRetry  Action = "teleport.enrollment.retry"

	LinkConfirm Action = "teleport.link.confirm"
	LinkRemove  Action = "teleport.link.remove"

	MappingCreate Action = "teleport.mapping.create"
	MappingUpdate Action = "teleport.mapping.update"
	MappingDelete Action = "teleport.mapping.delete"

	ProvisionCreate Action = "teleport.provision.create"
	ProvisionSync   Action = "teleport.provision.sync"
	ProvisionLock   Action = "teleport.provision.lock"
	ProvisionDelete Action = "teleport.provision.delete"

	AlertRuleCreate Action = "teleport.alert_rule.create"
	AlertRuleUpdate Action = "teleport.alert_rule.update"
	AlertRuleDelete Action = "teleport.alert_rule.delete"
	AlertDeliver    Action = "teleport.alert.deliver"

	DeploymentCreate   Action = "teleport.deployment.create"
	DeploymentUpdate   Action = "teleport.deployment.update"
	DeploymentDelete   Action = "teleport.deployment.delete"
	DeploymentCheck    Action = "teleport.deployment.check"
	DeploymentArtifact Action = "teleport.deployment.artifact"

	// SessionPlayed is the start of an in-portal playback of a recorded
	// session (spec 003); the row names the session, never its content.
	SessionPlayed Action = "teleport.session.played"

	BackupExport Action = "teleport.backup.export"
	BackupImport Action = "teleport.backup.import"

	AccessRefused Action = "teleport.access.refused"

	// Brokered access (spec 004): a downloaded identity, a terminal's start
	// and end. Rows name the Teleport user, node and login, never a key, a
	// certificate or terminal content.
	AccessIssued    Action = "teleport.access.issued"
	TerminalStarted Action = "teleport.terminal.started"
	TerminalEnded   Action = "teleport.terminal.ended"
)

// Vocabulary lists every action.
var Vocabulary = []Action{
	ClusterRegister, ClusterUpdate, ClusterRemove, ClusterCheck, CredentialRotate,
	UserCreate, UserUpdate, UserReset, UserDelete,
	RoleCreate, RoleUpdate, RoleDelete,
	LockCreate, LockDelete,
	TokenCreate, TokenRevoke,
	EnrollmentCreate, EnrollmentRender, EnrollmentReport, EnrollmentCancel, EnrollmentRetry,
	LinkConfirm, LinkRemove,
	MappingCreate, MappingUpdate, MappingDelete,
	ProvisionCreate, ProvisionSync, ProvisionLock, ProvisionDelete,
	AlertRuleCreate, AlertRuleUpdate, AlertRuleDelete, AlertDeliver,
	DeploymentCreate, DeploymentUpdate, DeploymentDelete, DeploymentCheck, DeploymentArtifact,
	SessionPlayed,
	BackupExport, BackupImport,
	AccessRefused,
	AccessIssued, TerminalStarted, TerminalEnded,
}

// Target kinds (closed set).
const (
	TargetCluster     = "cluster"
	TargetCredential  = "credential"
	TargetUser        = "user"
	TargetRole        = "role"
	TargetLock        = "lock"
	TargetToken       = "token"
	TargetEnrollment  = "enrollment"
	TargetResource    = "resource"
	TargetLink        = "link"
	TargetMapping     = "mapping"
	TargetManagedUser = "managed_user"
	TargetAlertRule   = "alert_rule"
	TargetDeployment  = "deployment"
	TargetBackup      = "backup"
	TargetSession     = "session"
	TargetSystem      = "system"
)

// TargetKinds lists every target kind.
var TargetKinds = []string{
	TargetCluster, TargetCredential, TargetUser, TargetRole, TargetLock, TargetToken, TargetEnrollment, TargetResource, TargetLink,
	TargetMapping, TargetManagedUser, TargetAlertRule, TargetDeployment, TargetBackup, TargetSession, TargetSystem,
}

// Outcomes (closed set, data-model audit_event). unknown is for a Teleport
// write whose result could not be confirmed (a timeout after sending).
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeUnknown = "unknown"
)

// Actor kinds (closed set; mirrors authz).
const (
	ActorUser   = authz.ActorUser
	ActorModule = authz.ActorModule
	ActorWorker = authz.ActorWorker
	ActorSystem = authz.ActorSystem
)

// Known reports whether a is in the vocabulary.
func Known(a string) bool { return slices.Contains(Vocabulary, Action(a)) }

// Event is one record before persistence. Time is filled by Record.
type Event struct {
	TenantID      string
	ClusterID     string // "" when the action concerns no cluster
	Action        Action
	ActorKind     string
	ActorID       string
	TargetKind    string
	TargetName    string
	Outcome       string // success | failure | unknown
	Reason        string
	CorrelationID string
	Details       map[string]any
}

// FromSubjects starts an event for the caller s.
func FromSubjects(s authz.Subjects, a Action, targetKind, targetName, outcome string) Event {
	return Event{TenantID: s.TenantID, Action: a, ActorKind: ActorOf(s.ActorKind), ActorID: s.ActorID(),
		TargetKind: targetKind, TargetName: targetName, Outcome: outcome}
}

// Store persists audit rows. repo.Store satisfies it, as does any test double.
type Store interface {
	AppendAudit(ctx context.Context, row repo.AuditRow) error
}

// Validate checks the closed vocabulary and required fields. An unknown action
// is a programming error and is surfaced to the caller.
func Validate(e Event) error {
	if !Known(string(e.Action)) {
		return fmt.Errorf("audit: unknown action %q", e.Action)
	}
	if e.TenantID == "" {
		return errors.New("audit: tenant_id is required")
	}
	switch e.ActorKind {
	case ActorUser, ActorModule, ActorWorker, ActorSystem:
	default:
		return fmt.Errorf("audit: actor_kind %q", e.ActorKind)
	}
	if !slices.Contains(TargetKinds, e.TargetKind) {
		return fmt.Errorf("audit: target_kind %q", e.TargetKind)
	}
	switch e.Outcome {
	case OutcomeSuccess, OutcomeFailure, OutcomeUnknown:
	default:
		return fmt.Errorf("audit: outcome %q", e.Outcome)
	}
	return nil
}

// forbidden detail-key substrings (case-insensitive): identity files,
// credentials, tokens, passwords, private keys, one-time invite and reset
// URLs, install commands and config snippets (both embed a join token), and
// raw role YAML (role changes record hashes).
var forbidden = []string{"identity", "credential", "token", "password", "secret", "private", "api_key", "apikey",
	"authorization", "invite", "reset_url", "install_command", "config_snippet", "yaml", "cert", "body"}

func forbiddenKey(k string) bool {
	lk := strings.ToLower(k)
	for _, f := range forbidden {
		if strings.Contains(lk, f) {
			return true
		}
	}
	return false
}

func guardValue(v any) any {
	switch x := v.(type) {
	case string:
		return truncate(x)
	case map[string]any:
		return guardMap(x)
	case []any:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = guardValue(vv)
		}
		return out
	default:
		return v
	}
}

// Redact returns a copy of m with every forbidden key dropped (at any depth)
// and string values truncated to 256 bytes. It is what Record applies.
func Redact(m map[string]any) map[string]any { return guardMap(m) }

func guardMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if forbiddenKey(k) {
			continue
		}
		out[k] = guardValue(v)
	}
	return out
}

// Writer buffers events and writes them one row at a time; Record never blocks.
type Writer struct {
	st      Store
	ch      chan repo.AuditRow
	wg      sync.WaitGroup
	mu      sync.Mutex
	closed  bool
	dropped int64
	onError func(error)
	flushCh chan chan struct{}
}

// NewWriter starts the writer (queue 10k).
func NewWriter(st Store, onError func(error)) *Writer {
	w := newWriter(st, onError, 10000)
	w.start()
	return w
}

func newWriter(st Store, onError func(error), queue int) *Writer {
	w := &Writer{st: st, ch: make(chan repo.AuditRow, queue), onError: onError, flushCh: make(chan chan struct{})}
	if w.onError == nil {
		w.onError = func(error) {}
	}
	return w
}

func (w *Writer) start() {
	w.wg.Add(1)
	go w.run()
}

// Record validates the event, fills Time=now, guards the details and enqueues
// the row. An invalid event returns an error and is not queued.
func (w *Writer) Record(_ context.Context, e Event) error {
	if err := Validate(e); err != nil {
		return err
	}
	row := repo.AuditRow{
		ID:            store.NewID(),
		Time:          time.Now().UTC(),
		TenantID:      e.TenantID,
		ActorKind:     e.ActorKind,
		ActorID:       truncate(e.ActorID),
		ClusterID:     e.ClusterID,
		Action:        string(e.Action),
		TargetKind:    e.TargetKind,
		TargetName:    truncate(e.TargetName),
		Outcome:       e.Outcome,
		Reason:        truncate(e.Reason),
		CorrelationID: truncate(e.CorrelationID),
		Detail:        guardMap(e.Details),
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		w.dropped++
		return errors.New("audit: writer closed")
	}
	select {
	case w.ch <- row:
	default:
		w.dropped++
		w.onError(errors.New("audit: queue full, event dropped"))
	}
	return nil
}

// Flush writes everything queued so far and returns when it is stored or ctx is done.
func (w *Writer) Flush(ctx context.Context) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.mu.Unlock()
	done := make(chan struct{})
	select {
	case w.flushCh <- done:
	case <-ctx.Done():
		return
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// Dropped returns the number of dropped events.
func (w *Writer) Dropped() int64 { w.mu.Lock(); defer w.mu.Unlock(); return w.dropped }

func (w *Writer) writeRow(r repo.AuditRow) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := w.st.AppendAudit(ctx, r); err != nil {
		w.onError(err)
	}
}

func (w *Writer) run() {
	defer w.wg.Done()
	for {
		select {
		case r, ok := <-w.ch:
			if !ok {
				return
			}
			w.writeRow(r)
		case done := <-w.flushCh:
			for drained := false; !drained; {
				select {
				case r := <-w.ch:
					w.writeRow(r)
				default:
					drained = true
				}
			}
			close(done)
		}
	}
}

// Close drains and stops the writer.
func (w *Writer) Close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	close(w.ch)
	w.mu.Unlock()
	w.wg.Wait()
}

// Recorder is what domain services record through (the Writer, or a test double).
type Recorder interface {
	Record(ctx context.Context, e Event) error
}

// Emit records e on r when r is non-nil. Validation errors are programming
// errors and are ignored here (Record surfaces them to callers that care).
func Emit(ctx context.Context, r Recorder, e Event) {
	if r == nil {
		return
	}
	_ = r.Record(ctx, e)
}

func truncate(s string) string {
	if len(s) > 256 {
		return s[:256]
	}
	return s
}

// ActorOf maps an authz actor kind to the audit vocabulary (identical sets;
// anything else is recorded as a user).
func ActorOf(kind string) string {
	switch kind {
	case ActorModule, ActorWorker, ActorSystem:
		return kind
	}
	return ActorUser
}
