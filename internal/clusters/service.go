// Package clusters is US1: registering Teleport clusters, verifying them,
// watching their health and rotating or removing their management
// credential (FR-001…006, data-model cluster).
//
// Registration verifies before anything is saved: the proxy address passes
// netguard (research D12), the identity file parses and is unexpired, the
// cluster answers a ping with that identity, and the D3 probe lists the
// read grants the identity lacks. Only then is the identity written to the
// secret store and the registration stored with the reference. In
// production the store is warden, which cannot write yet (research D11), so
// registration fails with secrets.ErrWriteUnsupported (dependency_unavailable)
// and nothing is stored anywhere — there is no fallback.
//
// Health checks (Check, and the leased Monitor every minute) drive the
// data-model state machine: consecutive failures mark a cluster unreachable
// (default 3), an authentication rejection or an expired certificate marks
// it credential_invalid, a credential inside its expiry threshold marks it
// credential_expiring, and a server older than N-1 marks it
// unsupported_version, which blocks writes (Writable). Status changes are
// published as teleport.cluster.status_changed; an outage and each credential
// expiry stage are notified once.
//
// The identity never leaves secrets.Secret: it is not logged, returned,
// published or audited. Later stories reach a cluster through Client, which
// checks the caller's permission and tenant ownership first.
package clusters

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-tangra/go-tangra/v4/listquery"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/netguard"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/roleyaml"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// Errors.
var (
	// ErrInvalid is the input-validation error (every FieldError is one).
	ErrInvalid = errors.New("clusters: invalid input")
	// ErrUnsupportedVersion refuses writes to a cluster older than N-1.
	ErrUnsupportedVersion = errors.New("clusters: the cluster's Teleport version is unsupported; writes are blocked")
)

// FieldError is a validation refusal about one input field. Msg is written
// by this package about the caller's input and never quotes a credential.
type FieldError struct{ Field, Msg string }

func (e *FieldError) Error() string { return "clusters: " + e.Field + ": " + e.Msg }

// Is makes every FieldError an ErrInvalid.
func (e *FieldError) Is(target error) bool { return target == ErrInvalid }

// Defaults.
const (
	// SupportedMajor is the Teleport major the pinned API module targets
	// (research D1); N-1 is still supported, older blocks writes (D13).
	SupportedMajor                 = 19
	DefaultUnreachableAfter        = 3
	DefaultOfflineThresholdMinutes = 15
	minOfflineThreshold            = 5
	maxOfflineThreshold            = 1440
	maxDisplayName                 = 64
	maxReason                      = 512

	countPage = 1000  // page size when counting objects
	maxCount  = 10000 // counting stops here (plan Scale: 10k resources per cluster)
)

// Credential is an uploaded identity file: decoded from a JSON string, and
// redacted in every printing, JSON and log path (secrets.Secret).
type Credential struct{ secrets.Secret }

// NewCredential wraps a copy of b.
func NewCredential(b []byte) Credential { return Credential{secrets.NewSecret(b)} }

// UnmarshalJSON decodes a JSON string.
func (c *Credential) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("clusters: credential must be a string")
	}
	c.Secret = secrets.NewSecret([]byte(s))
	return nil
}

// RegisterInput is the POST /clusters body.
type RegisterInput struct {
	DisplayName    string     `json:"display_name"`
	ProxyAddr      string     `json:"proxy_addr"`
	CredentialKind string     `json:"credential_kind,omitempty"`
	Credential     Credential `json:"credential"`
}

// RotateInput is the POST /clusters/{id}/credential body.
type RotateInput struct {
	CredentialKind string     `json:"credential_kind,omitempty"`
	Credential     Credential `json:"credential"`
}

// SettingsInput are the editable settings (nil = unchanged).
type SettingsInput struct {
	OfflineThresholdMinutes *int  `json:"offline_threshold_minutes,omitempty"`
	AlertsEnabled           *bool `json:"alerts_enabled,omitempty"`
}

// UpdateInput is the PATCH /clusters/{id} body (nil = unchanged).
type UpdateInput struct {
	DisplayName *string        `json:"display_name,omitempty"`
	Settings    *SettingsInput `json:"settings,omitempty"`
}

// View is a cluster as the API returns it: never the credential reference.
type View struct {
	ID                  string               `json:"id"`
	DisplayName         string               `json:"display_name"`
	ProxyAddr           string               `json:"proxy_addr"`
	ClusterName         string               `json:"cluster_name"`
	Edition             string               `json:"edition"`
	ServerVersion       string               `json:"server_version"`
	CredentialKind      string               `json:"credential_kind"`
	CredentialIdentity  string               `json:"credential_identity"`
	CredentialExpiresAt *time.Time           `json:"credential_expires_at,omitempty"`
	Status              string               `json:"status"`
	StatusReason        string               `json:"status_reason"`
	MissingPermissions  []string             `json:"missing_permissions"`
	LastContactAt       *time.Time           `json:"last_contact_at,omitempty"`
	Counts              repo.Counts          `json:"counts"`
	Settings            repo.ClusterSettings `json:"settings"`
	WritesBlocked       bool                 `json:"writes_blocked"`
	CreatedBy           string               `json:"created_by"`
	CreatedAt           time.Time            `json:"created_at"`
	UpdatedAt           time.Time            `json:"updated_at"`
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// ViewOf renders a stored cluster.
func ViewOf(c repo.Cluster) View {
	missing := c.MissingPermissions
	if missing == nil {
		missing = []string{}
	}
	return View{ID: c.ID, DisplayName: c.DisplayName, ProxyAddr: c.ProxyAddr, ClusterName: c.ClusterName, Edition: c.Edition,
		ServerVersion: c.ServerVersion, CredentialKind: c.CredentialKind, CredentialIdentity: c.CredentialIdentity,
		CredentialExpiresAt: timePtr(c.CredentialExpiresAt), Status: c.Status, StatusReason: c.StatusReason,
		MissingPermissions: missing, LastContactAt: timePtr(c.LastContactAt), Counts: c.Counts, Settings: c.Settings,
		WritesBlocked: Writable(c) != nil, CreatedBy: c.CreatedBy, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt}
}

// ClusterList is the GET /clusters list contract (sorted in memory: at most
// 50 clusters per tenant).
var ClusterList = listquery.Spec{
	Fields: map[string]listquery.Field{
		"display_name": {Expr: "display_name", Text: true, NotNull: true},
		"status":       {Expr: "status", NotNull: true},
		"created_at":   {Expr: "created_at", DefaultDir: listquery.Desc, NotNull: true},
	},
	Default: "display_name", TieBreak: "id",
}

// RecipientsFunc names who is notified about a cluster condition
// (repo.ConditionClusterUnreachable, repo.ConditionCredentialExpiring).
type RecipientsFunc func(ctx context.Context, tenantID, clusterID, condition string) []string

// RuleLister lists a tenant's alert rules (repo.Store satisfies it).
type RuleLister interface {
	ListAlertRules(ctx context.Context, tenantID string) ([]repo.AlertRule, error)
}

// RuleRecipients notifies the recipients of the tenant's enabled alert rules
// for the condition (all clusters, or this one). The module-administrator
// fallback of contracts/events-and-tasks.md needs an auth lookup that does
// not exist yet; without a rule nobody is notified (the status, the event
// and the log still say so).
func RuleRecipients(rules RuleLister) RecipientsFunc {
	return func(ctx context.Context, tenantID, clusterID, condition string) []string {
		rs, err := rules.ListAlertRules(ctx, tenantID)
		if err != nil {
			return nil
		}
		var out []string
		seen := map[string]bool{}
		for _, r := range rs {
			if !r.Enabled || r.ConditionKind != condition || (r.ClusterID != "" && r.ClusterID != clusterID) {
				continue
			}
			for _, to := range r.Recipients.UserIDs {
				if !seen[to] {
					seen[to] = true
					out = append(out, to)
				}
			}
		}
		return out
	}
}

// Service is the cluster domain service. Every field but the policy knobs
// is required (Notify and Recipients may be nil: nothing is notified).
type Service struct {
	Repo    repo.Store
	Secrets secrets.Store
	Pool    *teleportapi.Pool
	// Dial opens the one-off verification connection with an identity that is
	// not stored yet (default teleportapi.Dial).
	Dial       func(ctx context.Context, p teleportapi.DialParams) (teleportapi.Client, error)
	Guard      *netguard.Guard
	Limits     teleportapi.Limits
	Authz      *authz.Authorizer
	Audit      audit.Recorder
	Events     events.Publisher
	Notify     notify.Notifier
	Recipients RecipientsFunc
	Log        *slog.Logger
	Now        func() time.Time

	// Policy (zero = default).
	WarnBefore              time.Duration // credential threshold (7 days)
	UnreachableAfter        int           // consecutive failed checks (3)
	OfflineThresholdMinutes int           // default cluster setting (15)
	SupportedMajor          int           // N (19)

	mu        sync.Mutex
	failures  map[string]int    // consecutive failed checks per cluster (this replica)
	announced map[string]string // last announced expiry stage per cluster
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Log
}

func (s *Service) unreachableAfter() int {
	if s.UnreachableAfter <= 0 {
		return DefaultUnreachableAfter
	}
	return s.UnreachableAfter
}

func (s *Service) offlineDefault() int {
	if s.OfflineThresholdMinutes <= 0 {
		return DefaultOfflineThresholdMinutes
	}
	return s.OfflineThresholdMinutes
}

func (s *Service) supportedMajor() int {
	if s.SupportedMajor <= 0 {
		return SupportedMajor
	}
	return s.SupportedMajor
}

func (s *Service) dial(ctx context.Context, p teleportapi.DialParams) (teleportapi.Client, error) {
	if s.Dial != nil {
		return s.Dial(ctx, p)
	}
	return teleportapi.Dial(ctx, p)
}

// KeyFor is the pool key of a cluster.
func KeyFor(c repo.Cluster) teleportapi.Key {
	return teleportapi.Key{ClusterID: c.ID, CredentialRef: c.CredentialRef, TenantID: c.TenantID, ProxyAddr: c.ProxyAddr}
}

// Writable refuses writes to a cluster whose version is unsupported (D13).
func Writable(c repo.Cluster) error {
	if c.Status == repo.StatusUnsupportedVersion {
		return ErrUnsupportedVersion
	}
	return nil
}

// Client checks perm and the cluster's ownership for the caller in ctx and
// returns the cluster with its pooled connection (the entry point of the
// later stories; writes also call Writable).
func (s *Service) Client(ctx context.Context, id, perm string) (repo.Cluster, teleportapi.Client, error) {
	c, err := s.Authz.RequireCluster(ctx, id, perm)
	if err != nil {
		return repo.Cluster{}, nil, err
	}
	cl, err := s.Pool.Get(ctx, KeyFor(c))
	if err != nil {
		return repo.Cluster{}, nil, err
	}
	return c, cl, nil
}

// ---- input validation

func displayName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len([]rune(s)) > maxDisplayName {
		return "", &FieldError{Field: "display_name", Msg: "must be 1 to 64 characters"}
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", &FieldError{Field: "display_name", Msg: "must not contain control characters"}
		}
	}
	return s, nil
}

func credentialKind(k string) error {
	if k != "" && k != repo.CredentialIdentityFile {
		return &FieldError{Field: "credential_kind", Msg: "only identity_file is supported"}
	}
	return nil
}

// proxyAddr canonicalises host[:port] (port 443 by default).
func proxyAddr(s string) (string, error) {
	host, port, err := netguard.ParseHostPort(strings.TrimSpace(s), 443)
	if err != nil {
		return "", &FieldError{Field: "proxy_addr", Msg: "must be host or host:port, without a scheme or path"}
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// guardErr maps a netguard refusal to a module reason.
func guardErr(err error) error {
	switch {
	case errors.Is(err, netguard.ErrInvalidAddress):
		return &FieldError{Field: "proxy_addr", Msg: "must be host or host:port, without a scheme or path"}
	case errors.Is(err, netguard.ErrBlocked), errors.Is(err, netguard.ErrPort):
		return teleportapi.ErrBlockedTarget
	}
	return teleportapi.ErrUnreachable
}

// ---- verification and probing

// result is what one successful health probe learned.
type result struct {
	info    teleportapi.Info
	counts  repo.Counts
	missing []string
}

// fatal reports a probe error that fails the whole check.
func fatal(err error) bool {
	return errors.Is(err, teleportapi.ErrUnreachable) || errors.Is(err, teleportapi.ErrCredentialInvalid)
}

// verify dials addr with an identity that is not stored yet and probes it.
func (s *Service) verify(ctx context.Context, addr string, cred secrets.Secret) (result, error) {
	if _, err := s.Guard.Resolve(ctx, addr); err != nil {
		return result{}, guardErr(err)
	}
	cl, err := s.dial(ctx, teleportapi.DialParams{ProxyAddr: addr, Identity: cred, Guard: s.Guard, Limits: s.Limits})
	if err != nil {
		return result{}, teleportapi.MapError(err)
	}
	defer func() { _ = cl.Close() }()
	return s.probe(ctx, cl)
}

// probe pings the cluster, runs the D3 read probe and counts objects of the
// kinds the identity may read.
func (s *Service) probe(ctx context.Context, cl teleportapi.Client) (result, error) {
	info, err := cl.Ping(ctx)
	if err != nil {
		return result{}, err
	}
	r := result{info: info, missing: []string{}}
	denied := map[string]bool{}
	for _, k := range teleportapi.ProbeKinds {
		err := cl.ProbeRead(ctx, k)
		switch {
		case err == nil:
		case errors.Is(err, teleportapi.ErrAccessDenied):
			denied[k] = true
			r.missing = append(r.missing, k+":read")
		case fatal(err):
			return result{}, err
		}
	}
	counters := []struct {
		kind string
		dst  *int
		list func(o teleportapi.ListOptions) (int, string, error)
	}{
		{teleportapi.ProbeUser, &r.counts.Users, func(o teleportapi.ListOptions) (int, string, error) {
			p, err := cl.ListUsers(ctx, o)
			return len(p.Items), p.Next, err
		}},
		{teleportapi.ProbeRole, &r.counts.Roles, func(o teleportapi.ListOptions) (int, string, error) {
			p, err := cl.ListRoles(ctx, o)
			return len(p.Items), p.Next, err
		}},
	}
	for _, rk := range []struct {
		kind string
		dst  *int
	}{
		{teleportapi.KindNode, &r.counts.Nodes}, {teleportapi.KindApp, &r.counts.Apps}, {teleportapi.KindDB, &r.counts.DBs},
		{teleportapi.KindKube, &r.counts.Kube}, {teleportapi.KindDesktop, &r.counts.Desktops},
	} {
		kind := rk.kind
		counters = append(counters, struct {
			kind string
			dst  *int
			list func(o teleportapi.ListOptions) (int, string, error)
		}{kind, rk.dst, func(o teleportapi.ListOptions) (int, string, error) {
			p, err := cl.ListResources(ctx, kind, o)
			return len(p.Items), p.Next, err
		}})
	}
	for _, c := range counters {
		if denied[c.kind] {
			continue
		}
		n, err := count(c.list)
		if fatal(err) {
			return result{}, err
		}
		*c.dst = n
	}
	return r, nil
}

// count pages through a list up to maxCount.
func count(list func(o teleportapi.ListOptions) (int, string, error)) (int, error) {
	total, next := 0, ""
	for total < maxCount {
		n, nx, err := list(teleportapi.ListOptions{Limit: countPage, Next: next})
		if err != nil {
			return total, err
		}
		total += n
		if nx == "" {
			break
		}
		next = nx
	}
	return min(total, maxCount), nil
}

// ---- status

func edition(e string) string {
	switch e {
	case teleportapi.EditionCommunity:
		return repo.EditionCommunity
	case teleportapi.EditionEnterprise:
		return repo.EditionEnterprise
	}
	return repo.EditionUnknown
}

// versionMajor reads the major of "19.0.1", "v19.0.1" or "19.0.0-alpha.1".
func versionMajor(v string) (int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	head, _, _ := strings.Cut(v, ".")
	n, err := strconv.Atoi(head)
	return n, err == nil && n > 0
}

func bounded(s string) string {
	if len(s) > maxReason {
		return s[:maxReason]
	}
	return s
}

// statusFor derives the status of a reachable cluster: an expired
// credential, then an unsupported version, then an expiring credential.
func (s *Service) statusFor(c repo.Cluster, now time.Time) (string, string) {
	exp := EvaluateExpiry(c.CredentialIssuedAt, c.CredentialExpiresAt, now, s.WarnBefore)
	if exp.Stage == StageExpired {
		return repo.StatusCredentialInvalid, "The management credential expired at " + c.CredentialExpiresAt.Format(time.RFC3339) + "; rotate it."
	}
	n := s.supportedMajor()
	major, ok := versionMajor(c.ServerVersion)
	if ok && major < n-1 {
		return repo.StatusUnsupportedVersion, bounded(fmt.Sprintf("Teleport %s is older than the supported %d.x and %d.x; writes are blocked until the cluster is upgraded.",
			c.ServerVersion, n-1, n))
	}
	if exp.Stage.Expiring() {
		return repo.StatusCredentialExpiring, "The management credential expires at " + c.CredentialExpiresAt.Format(time.RFC3339) + "; rotate it."
	}
	if ok && major > n {
		return repo.StatusConnected, bounded(fmt.Sprintf("Teleport %s is newer than the tested %d.x.", c.ServerVersion, n))
	}
	return repo.StatusConnected, ""
}

// apply records a successful probe.
func (s *Service) apply(c *repo.Cluster, r result, now time.Time) {
	c.ClusterName, c.ServerVersion, c.Edition = r.info.ClusterName, r.info.ServerVersion, edition(r.info.Edition)
	c.Counts, c.MissingPermissions, c.LastContactAt = r.counts, r.missing, now
	c.Status, c.StatusReason = s.statusFor(*c, now)
}

func (s *Service) failure(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failures == nil {
		s.failures = map[string]int{}
	}
	s.failures[id]++
	return s.failures[id]
}

func (s *Service) resetFailures(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, id)
}

// forget drops the in-memory state of a cluster.
func (s *Service) forget(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, id)
	delete(s.announced, id)
}

// markAnnounced records key as the cluster's announced stage; false when it
// already was.
func (s *Service) markAnnounced(id, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.announced == nil {
		s.announced = map[string]string{}
	}
	if s.announced[id] == key {
		return false
	}
	s.announced[id] = key
	return true
}

// announce publishes a status change and notifies an outage and each new
// credential expiry stage (once per stage and credential, per replica).
func (s *Service) announce(ctx context.Context, prev string, c repo.Cluster, now time.Time) {
	if prev != "" && c.Status != prev {
		events.Emit(ctx, s.Events, c.TenantID, events.ClusterStatusChanged, events.ClusterStatus{ClusterID: c.ID, Status: c.Status})
		if c.Status == repo.StatusUnreachable {
			s.notify(ctx, c, notify.TemplateClusterUnreachable, repo.ConditionClusterUnreachable)
		}
	}
	exp := EvaluateExpiry(c.CredentialIssuedAt, c.CredentialExpiresAt, now, s.WarnBefore)
	if exp.Stage == StageNone {
		return
	}
	if s.markAnnounced(c.ID, string(exp.Stage)+"@"+c.CredentialExpiresAt.Format(time.RFC3339)) {
		events.Emit(ctx, s.Events, c.TenantID, events.CredentialExpiring, events.Credential{ClusterID: c.ID, ExpiresAt: c.CredentialExpiresAt})
		s.notify(ctx, c, notify.TemplateCredentialExpiring, repo.ConditionCredentialExpiring)
	}
}

// notify sends template about c to the condition's recipients when the
// cluster's alerts are enabled. Variables are identifiers and status text only.
func (s *Service) notify(ctx context.Context, c repo.Cluster, template, condition string) {
	if s.Notify == nil || !c.Settings.AlertsEnabled {
		return
	}
	var to []string
	if s.Recipients != nil {
		to = s.Recipients(ctx, c.TenantID, c.ID, condition)
	}
	if len(to) == 0 {
		s.log().InfoContext(ctx, "cluster notification has no recipients", "cluster_id", c.ID, "template", template)
		return
	}
	vars := map[string]string{"cluster_id": c.ID, "display_name": c.DisplayName, "cluster_name": c.ClusterName,
		"status": c.Status, "status_reason": c.StatusReason}
	if !c.LastContactAt.IsZero() {
		vars["last_contact_at"] = c.LastContactAt.Format(time.RFC3339)
	}
	if !c.CredentialExpiresAt.IsZero() {
		vars["expires_at"] = c.CredentialExpiresAt.Format(time.RFC3339)
	}
	for _, r := range to {
		if err := s.Notify.Send(ctx, notify.Message{TenantID: c.TenantID, Template: template, To: r, Vars: vars, CorrelationID: c.ID}); err != nil {
			s.log().WarnContext(ctx, "cluster notification failed", "cluster_id", c.ID, "template", template, "err", err)
		}
	}
}

// ---- audit

// ReasonOf is the audit reason of a failure (a closed vocabulary, never a
// Teleport message).
func ReasonOf(err error) string {
	var g *GuardError
	switch {
	case errors.As(err, &g):
		return g.Guard
	case teleportapi.Reason(err) != "":
		return teleportapi.Reason(err)
	case errors.Is(err, ErrInvalid), errors.Is(err, roleyaml.ErrInvalid):
		return "validation_failed"
	case errors.Is(err, ErrUnsupportedVersion):
		return "unsupported_version"
	case errors.Is(err, authz.ErrForbidden):
		return "forbidden"
	case errors.Is(err, secrets.ErrWriteUnsupported), errors.Is(err, secrets.ErrUnavailable):
		return "dependency_unavailable"
	case errors.Is(err, repo.ErrConflict):
		return "conflict"
	case errors.Is(err, repo.ErrNotFound):
		return "not_found"
	}
	return "error"
}

func (s *Service) record(ctx context.Context, a audit.Action, kind, clusterID, target string, err error, details map[string]any) {
	Audit(ctx, s.Audit, a, kind, clusterID, target, err, details)
}

// ---- operations

// List returns the caller's tenant clusters (clusters:read).
func (s *Service) List(ctx context.Context, req listquery.Request) (listquery.Page[View], error) {
	if err := s.Authz.Require(ctx, authz.ClustersRead); err != nil {
		return listquery.Page[View]{}, err
	}
	subj, _ := authz.FromContext(ctx)
	cs, err := s.Repo.ListClusters(ctx, subj.TenantID)
	if err != nil {
		return listquery.Page[View]{}, err
	}
	views := make([]View, 0, len(cs))
	for _, c := range cs {
		views = append(views, ViewOf(c))
	}
	listquery.SortSlice(views, req, func(v View, field string) any {
		switch field {
		case "status":
			return v.Status
		case "created_at":
			return v.CreatedAt
		}
		return v.DisplayName
	}, func(v View) string { return v.ID })
	items, total, applied := listquery.Window(views, req)
	return listquery.NewPage(items, total, applied), nil
}

// Get returns one cluster of the caller's tenant (clusters:read).
func (s *Service) Get(ctx context.Context, id string) (View, error) {
	c, err := s.Authz.RequireCluster(ctx, id, authz.ClustersRead)
	if err != nil {
		return View{}, err
	}
	return ViewOf(c), nil
}

// Register verifies a cluster and only then stores its credential and
// registration (clusters:manage).
func (s *Service) Register(ctx context.Context, in RegisterInput) (View, error) {
	if err := s.Authz.Require(ctx, authz.ClustersManage); err != nil {
		return View{}, err
	}
	subj, _ := authz.FromContext(ctx)
	name, err := displayName(in.DisplayName)
	if err != nil {
		return View{}, err
	}
	if err := credentialKind(in.CredentialKind); err != nil {
		return View{}, err
	}
	addr, err := proxyAddr(in.ProxyAddr)
	if err != nil {
		return View{}, err
	}
	now := s.now()
	ident, err := ParseIdentity(in.Credential.Reveal(), now)
	if err != nil {
		s.record(ctx, audit.ClusterRegister, audit.TargetCluster, "", name, err, nil)
		return View{}, err
	}
	existing, err := s.Repo.ListClusters(ctx, subj.TenantID)
	if err != nil {
		return View{}, err
	}
	for _, o := range existing {
		if o.DisplayName == name {
			return View{}, repo.ErrConflict
		}
	}
	res, err := s.verify(ctx, addr, in.Credential.Secret)
	if err != nil {
		s.record(ctx, audit.ClusterRegister, audit.TargetCluster, "", name, err, nil)
		return View{}, err
	}
	c := repo.Cluster{ID: store.NewID(), TenantID: subj.TenantID, DisplayName: name, ProxyAddr: addr,
		CredentialKind: repo.CredentialIdentityFile, CredentialIdentity: ident.Username,
		CredentialIssuedAt: ident.IssuedAt, CredentialExpiresAt: ident.ExpiresAt,
		Settings:  repo.ClusterSettings{OfflineThresholdMinutes: s.offlineDefault(), AlertsEnabled: true},
		CreatedBy: subj.ActorID(), CreatedAt: now, UpdatedAt: now}
	s.apply(&c, res, now)
	ref, err := s.Secrets.Put(ctx, secretName(c.ID), in.Credential.Secret)
	if err != nil {
		s.record(ctx, audit.ClusterRegister, audit.TargetCluster, "", name, err, nil)
		return View{}, err
	}
	c.CredentialRef = ref.String()
	if err := s.Repo.CreateCluster(ctx, c); err != nil {
		if derr := s.Secrets.Delete(ctx, ref); derr != nil {
			s.log().WarnContext(ctx, "orphaned credential after a failed registration", "cluster_id", c.ID, "err", derr)
		}
		s.record(ctx, audit.ClusterRegister, audit.TargetCluster, "", name, err, nil)
		return View{}, err
	}
	s.record(ctx, audit.ClusterRegister, audit.TargetCluster, c.ID, name, nil,
		map[string]any{"cluster_name": c.ClusterName, "server_version": c.ServerVersion, "status": c.Status})
	events.Emit(ctx, s.Events, c.TenantID, events.ClusterRegistered, events.Cluster{ClusterID: c.ID})
	s.announce(ctx, "", c, now)
	return ViewOf(c), nil
}

// secretName is the secret-store name of a cluster's credential.
func secretName(clusterID string) string { return "teleport-" + clusterID }

// Update edits the display name and settings (clusters:manage).
func (s *Service) Update(ctx context.Context, id string, in UpdateInput) (View, error) {
	c, err := s.Authz.RequireCluster(ctx, id, authz.ClustersManage)
	if err != nil {
		return View{}, err
	}
	if in.DisplayName == nil && in.Settings == nil {
		return View{}, &FieldError{Field: "body", Msg: "nothing to update"}
	}
	if in.DisplayName != nil {
		if c.DisplayName, err = displayName(*in.DisplayName); err != nil {
			return View{}, err
		}
	}
	if st := in.Settings; st != nil {
		if m := st.OfflineThresholdMinutes; m != nil {
			if *m < minOfflineThreshold || *m > maxOfflineThreshold {
				return View{}, &FieldError{Field: "settings.offline_threshold_minutes", Msg: "must be 5 to 1440"}
			}
			c.Settings.OfflineThresholdMinutes = *m
		}
		if st.AlertsEnabled != nil {
			c.Settings.AlertsEnabled = *st.AlertsEnabled
		}
	}
	updated, err := s.Repo.UpdateCluster(ctx, c)
	s.record(ctx, audit.ClusterUpdate, audit.TargetCluster, c.ID, c.DisplayName, err, nil)
	if err != nil {
		return View{}, err
	}
	events.Emit(ctx, s.Events, c.TenantID, events.ClusterUpdated, events.Cluster{ClusterID: c.ID})
	return ViewOf(updated), nil
}

// RotateCredential verifies a new identity against the registered cluster
// and only then stores it as the cluster's credential (clusters:manage).
func (s *Service) RotateCredential(ctx context.Context, id string, in RotateInput) (v View, err error) {
	c, err := s.Authz.RequireCluster(ctx, id, authz.ClustersManage)
	if err != nil {
		return View{}, err
	}
	defer func() {
		s.record(ctx, audit.CredentialRotate, audit.TargetCredential, c.ID, c.DisplayName, err, nil)
	}()
	if err := credentialKind(in.CredentialKind); err != nil {
		return View{}, err
	}
	now := s.now()
	ident, err := ParseIdentity(in.Credential.Reveal(), now)
	if err != nil {
		return View{}, err
	}
	res, err := s.verify(ctx, c.ProxyAddr, in.Credential.Secret)
	if err != nil {
		return View{}, err
	}
	if c.ClusterName != "" && res.info.ClusterName != c.ClusterName {
		return View{}, &FieldError{Field: "credential", Msg: "the identity signs in to a different Teleport cluster"}
	}
	ref, err := s.Secrets.Put(ctx, secretName(c.ID), in.Credential.Secret)
	if err != nil {
		return View{}, err
	}
	prev, oldRef := c.Status, c.CredentialRef
	c.CredentialRef, c.CredentialIdentity = ref.String(), ident.Username
	c.CredentialIssuedAt, c.CredentialExpiresAt = ident.IssuedAt, ident.ExpiresAt
	s.apply(&c, res, now)
	updated, err := s.Repo.UpdateCluster(ctx, c)
	if err != nil {
		return View{}, err
	}
	if oldRef != c.CredentialRef {
		if old, perr := secrets.ParseRef(oldRef); perr == nil {
			if derr := s.Secrets.Delete(ctx, old); derr != nil && !errors.Is(derr, secrets.ErrNotFound) {
				s.log().WarnContext(ctx, "previous credential not deleted", "cluster_id", c.ID, "err", derr)
			}
		}
	}
	s.Pool.Invalidate(c.ID)
	s.forget(c.ID)
	events.Emit(ctx, s.Events, c.TenantID, events.CredentialRotated, events.Credential{ClusterID: c.ID, ExpiresAt: c.CredentialExpiresAt})
	s.announce(ctx, prev, updated, now)
	return ViewOf(updated), nil
}

// Check runs a health check now (clusters:read).
func (s *Service) Check(ctx context.Context, id string) (View, error) {
	c, err := s.Authz.RequireCluster(ctx, id, authz.ClustersRead)
	if err != nil {
		return View{}, err
	}
	updated, err := s.CheckCluster(ctx, c)
	s.record(ctx, audit.ClusterCheck, audit.TargetCluster, c.ID, c.DisplayName, err, map[string]any{"status": updated.Status})
	if err != nil {
		return View{}, err
	}
	return ViewOf(updated), nil
}

// errExpired is the local "credential expired" outcome (no dial).
var errExpired = errors.New("clusters: credential expired")

// CheckCluster runs one health check of c and records the outcome (the
// monitor's entry point; the caller has already authorised it). A failed
// probe is not an error: it moves the status. Errors are store or secret
// store failures, which leave the status unchanged.
func (s *Service) CheckCluster(ctx context.Context, c repo.Cluster) (repo.Cluster, error) {
	now := s.now()
	var res result
	var err error
	if EvaluateExpiry(c.CredentialIssuedAt, c.CredentialExpiresAt, now, s.WarnBefore).Stage == StageExpired {
		err = errExpired
	} else {
		var cl teleportapi.Client
		if cl, err = s.Pool.Get(ctx, KeyFor(c)); err == nil {
			res, err = s.probe(ctx, cl)
		}
	}
	if errors.Is(err, secrets.ErrUnavailable) {
		return c, err
	}
	// Re-read so a concurrent edit (display name, settings) is not overwritten.
	fresh, gerr := s.Repo.GetCluster(ctx, c.TenantID, c.ID)
	if gerr != nil {
		return c, gerr
	}
	prev := fresh.Status
	c = fresh
	switch {
	case err == nil:
		s.resetFailures(c.ID)
		s.apply(&c, res, now)
	case errors.Is(err, errExpired):
		s.resetFailures(c.ID)
		s.Pool.Invalidate(c.ID)
		c.Status, c.StatusReason = s.statusFor(c, now)
	case errors.Is(err, teleportapi.ErrCredentialInvalid):
		s.resetFailures(c.ID)
		s.Pool.Invalidate(c.ID)
		c.Status, c.StatusReason = repo.StatusCredentialInvalid, "The cluster rejected the management credential; rotate it."
	default:
		if s.failure(c.ID) >= s.unreachableAfter() {
			if c.Status != repo.StatusUnreachable {
				s.Pool.Invalidate(c.ID)
			}
			c.Status, c.StatusReason = repo.StatusUnreachable, unreachableReason(c.LastContactAt)
		}
	}
	updated, err := s.Repo.UpdateCluster(ctx, c)
	if err != nil {
		return c, err
	}
	s.announce(ctx, prev, updated, now)
	return updated, nil
}

// CheckCredential evaluates c's credential expiry without contacting the
// cluster (the teleport:credential-expiry task; the caller has already
// authorised it): an expired credential moves the cluster to
// credential_invalid, one within the threshold moves a connected cluster to
// credential_expiring, and each new stage is announced once. A cluster whose
// stage leaves its status unchanged is not written. Bot renewal is deferred
// (research D2). Errors are store failures.
func (s *Service) CheckCredential(ctx context.Context, c repo.Cluster) (repo.Cluster, error) {
	now := s.now()
	fresh, err := s.Repo.GetCluster(ctx, c.TenantID, c.ID)
	if err != nil {
		return c, err
	}
	c = fresh
	prev := c.Status
	exp := EvaluateExpiry(c.CredentialIssuedAt, c.CredentialExpiresAt, now, s.WarnBefore)
	switch {
	case exp.Stage == StageExpired && c.Status != repo.StatusCredentialInvalid:
		s.Pool.Invalidate(c.ID)
		c.Status, c.StatusReason = s.statusFor(c, now)
	case exp.Stage.Expiring() && c.Status == repo.StatusConnected:
		c.Status, c.StatusReason = s.statusFor(c, now)
	}
	if c.Status != prev {
		if c, err = s.Repo.UpdateCluster(ctx, c); err != nil {
			return fresh, err
		}
	}
	s.announce(ctx, prev, c, now)
	return c, nil
}

func unreachableReason(last time.Time) string {
	if last.IsZero() {
		return "The cluster has not answered health checks."
	}
	return "No successful contact since " + last.Format(time.RFC3339) + "."
}

// Remove deletes the registration and its credential. Teleport itself is
// not contacted (clusters:manage). A secret store failure keeps the
// registration so the removal can be retried without orphaning the secret.
func (s *Service) Remove(ctx context.Context, id string) error {
	c, err := s.Authz.RequireCluster(ctx, id, authz.ClustersManage)
	if err != nil {
		return err
	}
	if ref, perr := secrets.ParseRef(c.CredentialRef); perr == nil {
		if err := s.Secrets.Delete(ctx, ref); err != nil && !errors.Is(err, secrets.ErrNotFound) {
			s.record(ctx, audit.ClusterRemove, audit.TargetCluster, c.ID, c.DisplayName, err, nil)
			return err
		}
	}
	if err := s.Repo.DeleteCluster(ctx, c.TenantID, c.ID); err != nil {
		s.record(ctx, audit.ClusterRemove, audit.TargetCluster, c.ID, c.DisplayName, err, nil)
		return err
	}
	s.Pool.Invalidate(c.ID)
	s.forget(c.ID)
	s.record(ctx, audit.ClusterRemove, audit.TargetCluster, c.ID, c.DisplayName, nil, nil)
	events.Emit(ctx, s.Events, c.TenantID, events.ClusterRemoved, events.Cluster{ClusterID: c.ID})
	return nil
}

// PurgeTenant removes every registration of a deleted tenant and its
// credential (contracts/events-and-tasks.md, "Tenant deleted"). Teleport is
// not contacted. The cluster rows cascade to tokens, snapshots, links,
// mappings, managed users, cursors and deliveries; the tenant's alert rules
// and deployment drafts are deleted too. It runs as the system subject of
// tenantID. A secret store failure keeps that registration (so a retry does
// not orphan the secret) and is returned after the other clusters are
// removed; the call is idempotent.
func (s *Service) PurgeTenant(ctx context.Context, tenantID string) (removed int, err error) {
	if tenantID == "" {
		return 0, fmt.Errorf("%w: tenant required", authz.ErrForbidden)
	}
	ctx = authz.WithSubjects(ctx, authz.System(tenantID))
	cs, err := s.Repo.ListClusters(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	var errs []error
	for _, c := range cs {
		if ref, perr := secrets.ParseRef(c.CredentialRef); perr == nil {
			if derr := s.Secrets.Delete(ctx, ref); derr != nil && !errors.Is(derr, secrets.ErrNotFound) {
				s.record(ctx, audit.ClusterRemove, audit.TargetCluster, c.ID, c.DisplayName, derr, map[string]any{"reason": "tenant_deleted"})
				errs = append(errs, derr)
				continue
			}
		}
		if derr := s.Repo.DeleteCluster(ctx, tenantID, c.ID); derr != nil && !errors.Is(derr, repo.ErrNotFound) {
			errs = append(errs, derr)
			continue
		}
		s.Pool.Invalidate(c.ID)
		s.forget(c.ID)
		removed++
		s.record(ctx, audit.ClusterRemove, audit.TargetCluster, c.ID, c.DisplayName, nil, map[string]any{"reason": "tenant_deleted"})
		events.Emit(ctx, s.Events, tenantID, events.ClusterRemoved, events.Cluster{ClusterID: c.ID})
	}
	if rules, lerr := s.Repo.ListAlertRules(ctx, tenantID); lerr != nil {
		errs = append(errs, lerr)
	} else {
		for _, r := range rules {
			if derr := s.Repo.DeleteAlertRule(ctx, tenantID, r.ID); derr != nil && !errors.Is(derr, repo.ErrNotFound) {
				errs = append(errs, derr)
			}
		}
	}
	if drafts, lerr := s.Repo.ListDrafts(ctx, tenantID); lerr != nil {
		errs = append(errs, lerr)
	} else {
		for _, d := range drafts {
			if derr := s.Repo.DeleteDraft(ctx, tenantID, d.ID); derr != nil && !errors.Is(derr, repo.ErrNotFound) {
				errs = append(errs, derr)
			}
		}
	}
	return removed, errors.Join(errs...)
}
