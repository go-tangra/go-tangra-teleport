package clusters

import (
	"context"
	"errors"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/audit"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// Safety guards of the later stories (FR-011, FR-013): a refusal that no
// permission overrides. The API answers 403 forbidden with detail.guard.
const (
	// GuardSelfIdentity: the action would delete, change or lock out the
	// cluster's management identity.
	GuardSelfIdentity = "self_identity"
	// GuardPresetRole: Teleport built-in roles cannot be deleted.
	GuardPresetRole = "preset_role"
	// GuardManagementRole: the role is held by the management identity.
	GuardManagementRole = "management_role"
)

// ErrRefused marks every guard refusal.
var ErrRefused = errors.New("clusters: refused by a safety guard")

// GuardError is a guard refusal. Msg is written by the module and explains
// the refusal; it never quotes a Teleport message.
type GuardError struct{ Guard, Msg string }

func (e *GuardError) Error() string { return "clusters: " + e.Guard + ": " + e.Msg }

// Is makes every GuardError an ErrRefused.
func (e *GuardError) Is(target error) bool { return target == ErrRefused }

// IsManagementIdentity reports whether user is the cluster's management identity.
func IsManagementIdentity(c repo.Cluster, user string) bool {
	return c.CredentialIdentity != "" && user == c.CredentialIdentity
}

// ManagementIdentity reads the cluster's management identity (its roles feed
// the self-lockout guards). An unknown identity refuses: the guard fails
// closed.
func ManagementIdentity(ctx context.Context, c repo.Cluster, cl teleportapi.Client) (teleportapi.User, error) {
	if c.CredentialIdentity == "" {
		return teleportapi.User{}, &GuardError{Guard: GuardSelfIdentity,
			Msg: "the cluster's management identity is unknown; run a health check or rotate the credential first"}
	}
	return cl.GetUser(ctx, c.CredentialIdentity)
}

// Audit records one action of a domain service for the caller in ctx: the
// outcome is failure with a closed-vocabulary reason when err is set
// (never a Teleport message). Details pass the audit detail guard.
func Audit(ctx context.Context, r audit.Recorder, a audit.Action, kind, clusterID, target string, err error, details map[string]any) {
	subj, _ := authz.FromContext(ctx)
	e := audit.FromSubjects(subj, a, kind, target, audit.OutcomeSuccess)
	e.ClusterID, e.Details = clusterID, details
	if err != nil {
		e.Outcome, e.Reason = audit.OutcomeFailure, ReasonOf(err)
	}
	audit.Emit(ctx, r, e)
}
