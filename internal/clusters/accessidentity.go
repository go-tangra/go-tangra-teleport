package clusters

// The access identity (spec 005): an optional, per-cluster sign-in identity
// (tsh login as tangra-access) that brokered access issues certificates
// with. Teleport refuses impersonation from an impersonated certificate,
// which every tctl auth sign identity — the management credential — is.
// The access identity is checked before it is stored (it parses and is
// unexpired, signs in, is not impersonated, belongs to the registered
// cluster and, when a managed user exists, may impersonate it), kept in the
// same secret store as the management credential and reached through its
// own pool (AccessPool). Its expiry is announced like the management
// credential's; upload, replace and remove are audited. It never leaves
// secrets.Secret.

import (
	"context"
	"errors"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// Access identity refusals (closed-vocabulary reasons, ReasonOf).
var (
	// ErrAccessIdentityMissing: the cluster has no access identity.
	ErrAccessIdentityMissing = errors.New("clusters: no access identity")
	// ErrAccessIdentityExpired: the stored access identity has expired.
	ErrAccessIdentityExpired = errors.New("clusters: the access identity has expired")
	// ErrNotSignIn: an uploaded identity is impersonated (tctl auth sign),
	// so Teleport would never let it impersonate.
	ErrNotSignIn = errors.New("clusters: the identity is not a sign-in identity")
	// ErrCannotImpersonate: Teleport refused the dry issuance for a
	// managed user with the uploaded identity.
	ErrCannotImpersonate = errors.New("clusters: the identity cannot impersonate managed users")
)

// Access identity states (the status view).
const (
	AccessStateMissing  = "missing"
	AccessStateOK       = "ok"
	AccessStateExpiring = "expiring"
	AccessStateExpired  = "expired"
)

// CredentialAccessIdentity names the access identity in the
// teleport.credential.expiring event and notification.
const CredentialAccessIdentity = "access_identity"

// dryRunTTL is the lifetime of the impersonation check on upload.
const dryRunTTL = time.Minute

// AccessIdentityInput is the PUT access-identity body.
type AccessIdentityInput struct {
	Credential Credential `json:"credential"`
}

// AccessIdentityView is the access identity as the API shows it: never the
// identity or its reference.
type AccessIdentityView struct {
	Configured   bool       `json:"configured"`
	TeleportUser string     `json:"teleport_user,omitempty"`
	IssuedAt     *time.Time `json:"issued_at,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	State        string     `json:"state"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
	UpdatedBy    string     `json:"updated_by,omitempty"`
	// ImpersonationChecked is set on upload: a managed user existed and
	// Teleport issued certificates for it with the identity.
	ImpersonationChecked *bool `json:"impersonation_checked,omitempty"`
}

// AccessState is the state of a stored access identity at now (the same
// thresholds as the management credential).
func (s *Service) AccessState(a repo.AccessIdentity, now time.Time) string {
	switch exp := EvaluateExpiry(a.IssuedAt, a.ExpiresAt, now, s.WarnBefore); {
	case exp.Stage == StageExpired:
		return AccessStateExpired
	case exp.Stage.Expiring():
		return AccessStateExpiring
	}
	return AccessStateOK
}

func (s *Service) accessView(a repo.AccessIdentity, now time.Time) AccessIdentityView {
	return AccessIdentityView{Configured: true, TeleportUser: a.TeleportUser, IssuedAt: timePtr(a.IssuedAt), ExpiresAt: timePtr(a.ExpiresAt),
		State: s.AccessState(a, now), UpdatedAt: timePtr(a.UpdatedAt), UpdatedBy: a.UpdatedBy}
}

// accessSecretName is the secret-store name of a cluster's access identity.
func accessSecretName(clusterID string) string { return "teleport-access-" + clusterID }

// accessKey is the access pool key of a cluster's access identity.
func accessKey(c repo.Cluster, a repo.AccessIdentity) teleportapi.Key {
	return teleportapi.Key{ClusterID: c.ID, CredentialRef: a.CredentialRef, TenantID: c.TenantID, ProxyAddr: c.ProxyAddr}
}

// AccessIdentity returns a cluster's access identity status (clusters:read).
func (s *Service) AccessIdentity(ctx context.Context, id string) (AccessIdentityView, error) {
	c, err := s.Authz.RequireCluster(ctx, id, authz.ClustersRead)
	if err != nil {
		return AccessIdentityView{}, err
	}
	return s.AccessIdentityOf(ctx, c)
}

// AccessIdentityOf is the access identity status of an authorised cluster.
func (s *Service) AccessIdentityOf(ctx context.Context, c repo.Cluster) (AccessIdentityView, error) {
	a, err := s.Repo.GetAccessIdentity(ctx, c.TenantID, c.ID)
	if errors.Is(err, repo.ErrNotFound) {
		return AccessIdentityView{State: AccessStateMissing}, nil
	}
	if err != nil {
		return AccessIdentityView{}, err
	}
	return s.accessView(a, s.now()), nil
}

// PutAccessIdentity verifies an uploaded sign-in identity against the
// registered cluster and only then stores it as the cluster's access
// identity, replacing any previous one (clusters:manage).
func (s *Service) PutAccessIdentity(ctx context.Context, id string, in AccessIdentityInput) (v AccessIdentityView, err error) {
	c, err := s.Authz.RequireCluster(ctx, id, authz.ClustersManage)
	if err != nil {
		return AccessIdentityView{}, err
	}
	prev, gerr := s.Repo.GetAccessIdentity(ctx, c.TenantID, c.ID)
	replacing := gerr == nil
	if gerr != nil && !errors.Is(gerr, repo.ErrNotFound) {
		return AccessIdentityView{}, gerr
	}
	action := audit.AccessIdentityUpload
	if replacing {
		action = audit.AccessIdentityReplace
	}
	details := map[string]any{}
	defer func() { s.record(ctx, action, audit.TargetCredential, c.ID, c.DisplayName, err, details) }()

	now := s.now()
	ident, err := ParseIdentity(in.Credential.Reveal(), now)
	if err != nil {
		return AccessIdentityView{}, err
	}
	details["teleport_user"] = ident.Username
	if ident.Impersonator != "" {
		return AccessIdentityView{}, ErrNotSignIn
	}
	if c.ClusterName != "" && ident.ClusterName != c.ClusterName {
		return AccessIdentityView{}, &FieldError{Field: "credential", Msg: "the identity signs in to a different Teleport cluster"}
	}
	checked, err := s.verifyAccess(ctx, c, in.Credential.Secret)
	if err != nil {
		return AccessIdentityView{}, err
	}
	details["impersonation_checked"] = checked
	ref, err := s.Secrets.Put(ctx, accessSecretName(c.ID), in.Credential.Secret)
	if err != nil {
		return AccessIdentityView{}, err
	}
	subj, _ := authz.FromContext(ctx)
	a := repo.AccessIdentity{ClusterID: c.ID, TenantID: c.TenantID, CredentialRef: ref.String(), TeleportUser: ident.Username,
		IssuedAt: ident.IssuedAt, ExpiresAt: ident.ExpiresAt, UpdatedAt: now, UpdatedBy: subj.ActorID()}
	if err = s.Repo.PutAccessIdentity(ctx, a); err != nil {
		if !replacing || prev.CredentialRef != a.CredentialRef {
			s.dropSecret(ctx, c.ID, a.CredentialRef)
		}
		return AccessIdentityView{}, err
	}
	if replacing && prev.CredentialRef != a.CredentialRef {
		s.dropSecret(ctx, c.ID, prev.CredentialRef)
	}
	s.invalidateAccess(c.ID)
	details["expires_at"] = a.ExpiresAt.Format(time.RFC3339)
	events.Emit(ctx, s.Events, c.TenantID, events.ClusterUpdated, events.Cluster{ClusterID: c.ID})
	s.announceAccess(ctx, c, now)
	v = s.accessView(a, now)
	v.ImpersonationChecked = &checked
	return v, nil
}

// verifyAccess dials the cluster with an identity that is not stored yet:
// it must sign in to the registered cluster and, when the cluster has an
// active managed user, Teleport must issue 1-minute certificates for it
// (they are dropped at once). checked reports whether that dry issuance ran.
func (s *Service) verifyAccess(ctx context.Context, c repo.Cluster, cred secrets.Secret) (checked bool, err error) {
	if _, err := s.Guard.Resolve(ctx, c.ProxyAddr); err != nil {
		return false, guardErr(err)
	}
	cl, err := s.dial(ctx, teleportapi.DialParams{ProxyAddr: c.ProxyAddr, Identity: cred, Guard: s.Guard, Limits: s.Limits})
	if err != nil {
		return false, teleportapi.MapError(err)
	}
	defer func() { _ = cl.Close() }()
	info, err := cl.Ping(ctx)
	if err != nil {
		return false, err
	}
	if c.ClusterName != "" && info.ClusterName != c.ClusterName {
		return false, &FieldError{Field: "credential", Msg: "the identity signs in to a different Teleport cluster"}
	}
	user, err := s.managedUser(ctx, c)
	if err != nil || user == "" {
		return false, err
	}
	certs, err := cl.IssueUserCerts(ctx, user, dryRunTTL)
	if errors.Is(err, teleportapi.ErrAccessDenied) {
		return true, ErrCannotImpersonate
	}
	if err != nil {
		return true, err
	}
	certs.Drop()
	return true, nil
}

// managedUser names one active managed Teleport user of c ("" when none).
func (s *Service) managedUser(ctx context.Context, c repo.Cluster) (string, error) {
	rows, err := s.Repo.ListManagedUsers(ctx, c.TenantID, c.ID)
	if err != nil {
		return "", err
	}
	for _, m := range rows {
		if m.TenantID == c.TenantID && m.ClusterID == c.ID && m.State == repo.UserActive && m.TeleportUsername != "" {
			return m.TeleportUsername, nil
		}
	}
	return "", nil
}

// DeleteAccessIdentity removes a cluster's access identity and its secret
// (clusters:manage; not_found when none). A secret store failure keeps it
// so the removal can be retried.
func (s *Service) DeleteAccessIdentity(ctx context.Context, id string) (err error) {
	c, err := s.Authz.RequireCluster(ctx, id, authz.ClustersManage)
	if err != nil {
		return err
	}
	defer func() {
		s.record(ctx, audit.AccessIdentityDelete, audit.TargetCredential, c.ID, c.DisplayName, err, nil)
	}()
	a, err := s.Repo.GetAccessIdentity(ctx, c.TenantID, c.ID)
	if err != nil {
		return err
	}
	if err := s.deleteAccessSecret(ctx, a.CredentialRef); err != nil {
		return err
	}
	if err := s.Repo.DeleteAccessIdentity(ctx, c.TenantID, c.ID); err != nil {
		return err
	}
	s.invalidateAccess(c.ID)
	events.Emit(ctx, s.Events, c.TenantID, events.ClusterUpdated, events.Cluster{ClusterID: c.ID})
	return nil
}

// AccessClient is the pooled connection of an authorised cluster's access
// identity: ErrAccessIdentityMissing when none is configured,
// ErrAccessIdentityExpired (without dialling) when it has expired.
func (s *Service) AccessClient(ctx context.Context, c repo.Cluster) (teleportapi.Client, error) {
	a, err := s.Repo.GetAccessIdentity(ctx, c.TenantID, c.ID)
	if errors.Is(err, repo.ErrNotFound) {
		return nil, ErrAccessIdentityMissing
	}
	if err != nil {
		return nil, err
	}
	if !s.now().Before(a.ExpiresAt) {
		s.invalidateAccess(c.ID)
		return nil, ErrAccessIdentityExpired
	}
	if s.AccessPool == nil {
		return nil, ErrAccessIdentityMissing
	}
	return s.AccessPool.Get(ctx, accessKey(c, a))
}

// InvalidateAccess drops the pooled access connection of a cluster (a
// rejected access identity).
func (s *Service) InvalidateAccess(clusterID string) { s.invalidateAccess(clusterID) }

func (s *Service) invalidateAccess(clusterID string) {
	if s.AccessPool != nil {
		s.AccessPool.Invalidate(clusterID)
	}
}

// deleteAccessSecret deletes an access identity's secret (a missing one is
// already gone).
func (s *Service) deleteAccessSecret(ctx context.Context, ref string) error {
	r, err := secrets.ParseRef(ref)
	if err != nil {
		return nil
	}
	if err := s.Secrets.Delete(ctx, r); err != nil && !errors.Is(err, secrets.ErrNotFound) {
		return err
	}
	return nil
}

// dropSecret deletes a secret that is no longer referenced, logging (never
// failing) when it cannot.
func (s *Service) dropSecret(ctx context.Context, clusterID, ref string) {
	if err := s.deleteAccessSecret(ctx, ref); err != nil {
		s.log().WarnContext(ctx, "access identity secret not deleted", "cluster_id", clusterID, "err", err)
	}
}

// removeAccessIdentity deletes a cluster's access identity secret before
// the cluster itself is removed (the row cascades).
func (s *Service) removeAccessIdentity(ctx context.Context, c repo.Cluster) error {
	a, err := s.Repo.GetAccessIdentity(ctx, c.TenantID, c.ID)
	if errors.Is(err, repo.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.deleteAccessSecret(ctx, a.CredentialRef); err != nil {
		return err
	}
	s.invalidateAccess(c.ID)
	return nil
}

// announceAccess publishes and notifies each new expiry stage of c's
// access identity once (the management credential's thresholds). It never
// changes the cluster status, which describes the management credential.
func (s *Service) announceAccess(ctx context.Context, c repo.Cluster, now time.Time) {
	a, err := s.Repo.GetAccessIdentity(ctx, c.TenantID, c.ID)
	if err != nil {
		if !errors.Is(err, repo.ErrNotFound) {
			s.log().WarnContext(ctx, "access identity not readable for its expiry", "cluster_id", c.ID, "err", err)
		}
		return
	}
	exp := EvaluateExpiry(a.IssuedAt, a.ExpiresAt, now, s.WarnBefore)
	if exp.Stage == StageNone {
		return
	}
	if !s.markAnnounced(accessAnnounceKey(c.ID), string(exp.Stage)+"@"+a.ExpiresAt.Format(time.RFC3339)) {
		return
	}
	events.Emit(ctx, s.Events, c.TenantID, events.CredentialExpiring,
		events.Credential{ClusterID: c.ID, ExpiresAt: a.ExpiresAt, Kind: CredentialAccessIdentity})
	reason := "The access identity for portal terminals expires at " + a.ExpiresAt.Format(time.RFC3339) + "; sign in as " + a.TeleportUser + " again and replace it."
	if exp.Stage == StageExpired {
		reason = "The access identity for portal terminals expired at " + a.ExpiresAt.Format(time.RFC3339) + "; portal terminals are unavailable until it is replaced."
	}
	s.notifyWith(ctx, c, notify.TemplateCredentialExpiring, repo.ConditionCredentialExpiring, map[string]string{
		"credential": CredentialAccessIdentity, "status_reason": reason, "expires_at": a.ExpiresAt.Format(time.RFC3339)})
}

// accessAnnounceKey is the announced-stage key of a cluster's access identity.
func accessAnnounceKey(clusterID string) string { return clusterID + "/access" }
