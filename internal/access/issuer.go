// Package access is brokered Teleport access (spec 004): a provisioned
// portal user gets short-lived Teleport certificates without a Teleport
// sign-in. The module's management identity asks Teleport for them as the
// caller's own managed Teleport user (impersonation, research R1); Teleport
// allows that only for users labelled tangra.io/managed=true, and this
// package additionally checks, before every issuance, that the user is the
// caller's: the managed-user row of (tenant, portal user, cluster), active,
// and a Teleport user whose tenant and portal-user labels name the caller
// (R2). The request never names a Teleport user.
//
// Issuance needs a portal session established with MFA (amr otp or hwk,
// R3); roles that need Teleport's own per-session MFA are refused (R9).
// Lifetimes come from the cluster's access settings (R4). Nothing issued is
// stored: certificates live for the request (download, node listing) or
// the terminal (internal/terminal) and are dropped. Every download and
// refusal is audited (R12) without any key or certificate.
package access

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/users"
)

// Kinds of issued access (audit detail "kind").
const (
	KindDownload = "download"
	KindTerminal = "terminal"
)

// Service issues brokered access. Clusters and Repo are required; Audit and
// Log may be nil (tests).
type Service struct {
	Clusters *clusters.Service
	Repo     repo.Store
	Audit    audit.Recorder
	Log      *slog.Logger
	Now      func() time.Time

	nodes nodeCache
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Grant is a caller resolved to their own managed Teleport user on one
// cluster. It holds no credential.
type Grant struct {
	Subject  authz.Subjects
	Cluster  repo.Cluster
	Client   teleportapi.Client
	Managed  repo.ManagedUser
	User     teleportapi.User // the Teleport user as read now
	Settings repo.AccessSettings
}

// Owned reports whether u is the managed Teleport user of tangra user
// tangraID in tenantID (the provisioning labels).
func Owned(u teleportapi.User, tenantID, tangraID string) bool {
	return u.Labels[users.LabelManaged] == "true" && u.Labels[users.LabelTenant] == tenantID && u.Labels[users.LabelUser] == tangraID
}

// Resolve checks perm and the cluster for the caller in ctx and finds the
// caller's own managed user. needMFA refuses a portal session without MFA.
// Order: permission and cluster (forbidden, not_found), a human caller,
// MFA, the managed-user row, the Teleport user and its labels, locks.
func (s *Service) Resolve(ctx context.Context, clusterID, perm string, needMFA bool) (Grant, error) {
	c, cl, err := s.Clusters.Client(ctx, clusterID, perm)
	if err != nil {
		return Grant{}, err
	}
	subj, _ := authz.FromContext(ctx)
	if !subj.IsHuman() || subj.UserID == "" {
		return Grant{}, authz.ErrForbidden
	}
	g := Grant{Subject: subj, Cluster: c, Client: cl}
	if needMFA && !subj.MFA() {
		return g, ErrMFARequired
	}
	rows, err := s.Repo.ListManagedUsers(ctx, subj.TenantID, c.ID)
	if err != nil {
		return g, err
	}
	mine := func(m repo.ManagedUser) bool {
		return m.TenantID == subj.TenantID && m.ClusterID == c.ID && m.TangraUserID == subj.UserID
	}
	i := slices.IndexFunc(rows, func(m repo.ManagedUser) bool { return mine(m) && m.State == repo.UserActive })
	if i < 0 || rows[i].TeleportUsername == "" {
		return g, ErrNotProvisioned
	}
	g.Managed = rows[i]
	u, err := cl.GetUser(ctx, g.Managed.TeleportUsername)
	if teleportapi.Reason(err) == "not_found" {
		return g, ErrNotProvisioned
	}
	if err != nil {
		return g, err
	}
	if u.Name != g.Managed.TeleportUsername || !Owned(u, subj.TenantID, subj.UserID) {
		return g, errLabelMismatch
	}
	g.User = u
	locks, err := cl.ListLocks(ctx)
	if err != nil {
		return g, err
	}
	for _, l := range locks {
		if l.TargetKind == "user" && l.Target == u.Name {
			return g, ErrLocked
		}
	}
	if g.Settings, err = s.Repo.GetAccessSettings(ctx, subj.TenantID, c.ID); err != nil {
		return g, err
	}
	return g, nil
}

// TTL is the lifetime of an issuance: the cluster setting, shortened (never
// lengthened) by a requested minutes > 0; outside 15..720 is ErrInvalid.
func TTL(settings repo.AccessSettings, minutes int) (time.Duration, error) {
	max := settings.AccessTTLMinutes
	if max < MinTTLMinutes || max > MaxTTLMinutes {
		max = repo.DefaultAccessTTLMinutes
	}
	if minutes == 0 {
		return time.Duration(max) * time.Minute, nil
	}
	if minutes < MinTTLMinutes || minutes > MaxTTLMinutes {
		return 0, ErrInvalid
	}
	return time.Duration(min(minutes, max)) * time.Minute, nil
}

// Issue asks Teleport for certificates as g's user for ttl. Roles needing
// per-session MFA are refused first; a refused impersonation names the
// management role (or identity) to fix. The caller drops the certificates.
func (s *Service) Issue(ctx context.Context, g Grant, ttl time.Duration) (*teleportapi.UserCerts, error) {
	if g.Client == nil || g.User.Name == "" {
		return nil, ErrNotProvisioned
	}
	if err := sessionMFA(ctx, g); err != nil {
		return nil, err
	}
	certs, err := g.Client.IssueUserCerts(ctx, g.User.Name, ttl)
	if err != nil {
		if errors.Is(err, teleportapi.ErrAccessDenied) {
			if strings.Contains(teleportapi.Detail(err), "impersonated user") {
				return nil, ErrIdentityUnsuitable
			}
			return nil, ErrRoleOutdated
		}
		return nil, err
	}
	if certs.User != g.User.Name {
		certs.Drop()
		return nil, teleportapi.ErrRejected
	}
	return certs, nil
}

// sessionMFA refuses when the cluster or any role of the user requires
// Teleport's per-session MFA (FR-014).
func sessionMFA(ctx context.Context, g Grant) error {
	on, err := g.Client.SessionMFARequired(ctx)
	if err != nil {
		return err
	}
	if on {
		return ErrSessionMFARequired
	}
	for _, r := range g.User.Roles {
		def, err := g.Client.GetRoleDefinition(ctx, r)
		if teleportapi.Reason(err) == "not_found" {
			continue
		}
		if err != nil {
			return err
		}
		if def.GetOptions().RequireMFAType.IsSessionMFARequired() {
			return ErrSessionMFARequired
		}
	}
	return nil
}

// Mine is the caller's own access on a cluster (GET access): no MFA needed,
// nothing issued.
type Mine struct {
	TeleportUser string       `json:"teleport_user"`
	Roles        []string     `json:"roles"`
	Logins       []string     `json:"logins"`
	MFA          bool         `json:"mfa"`
	CanTerminal  bool         `json:"can_terminal"`
	CanDownload  bool         `json:"can_download"`
	ProxyAddr    string       `json:"proxy_addr"`
	ClusterName  string       `json:"cluster_name"`
	Settings     SettingsView `json:"settings"`
}

// Mine returns the caller's own access (access:terminal).
func (s *Service) Mine(ctx context.Context, clusterID string) (Mine, error) {
	g, err := s.Resolve(ctx, clusterID, authz.AccessTerminal, false)
	if err != nil {
		return Mine{}, err
	}
	return Mine{TeleportUser: g.User.Name, Roles: nonNil(g.User.Roles), Logins: nonNil(g.User.Logins), MFA: g.Subject.MFA(),
		CanTerminal: true, CanDownload: s.Clusters.Authz.Require(ctx, authz.AccessDownload) == nil,
		ProxyAddr: g.Cluster.ProxyAddr, ClusterName: g.Cluster.ClusterName, Settings: viewOf(g.Settings)}, nil
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return slices.Clone(v)
}

// ---- audit

// Record writes one audit row of a brokered-access action for g's caller:
// target the Teleport user (or nothing yet), outcome by err, details
// without any key, certificate or terminal content.
func (s *Service) Record(ctx context.Context, a audit.Action, g Grant, err error, details map[string]any) {
	subj := g.Subject
	if subj.TenantID == "" {
		subj, _ = authz.FromContext(ctx)
	}
	if subj.TenantID == "" {
		return
	}
	target := g.User.Name
	if target == "" {
		target = g.Managed.TeleportUsername
	}
	e := audit.FromSubjects(subj, a, audit.TargetManagedUser, target, audit.OutcomeSuccess)
	// Only a cluster resolved for the caller: never another tenant's id.
	e.ClusterID = g.Cluster.ID
	e.Details = map[string]any{}
	for k, v := range details {
		e.Details[k] = v
	}
	if target != "" {
		e.Details["teleport_user"] = target
	}
	if err != nil {
		e.Outcome, e.Reason = audit.OutcomeFailure, AuditReason(err)
	}
	audit.Emit(ctx, s.Audit, e)
}
