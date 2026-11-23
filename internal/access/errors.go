package access

import (
	"errors"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
)

// Refusals (plan.md Contract). Each has a closed-vocabulary reason (Reason).
var (
	// ErrMFARequired: the portal session was not established with MFA (R3).
	ErrMFARequired = &refusal{"mfa_required", "access: the portal session did not use MFA"}
	// ErrNotProvisioned: the caller has no active managed user on the
	// cluster, or its Teleport user is missing or not labelled for the
	// caller (R2).
	ErrNotProvisioned = &refusal{"not_provisioned", "access: not provisioned on this cluster"}
	// ErrLocked: a Teleport lock targets the caller's Teleport user.
	ErrLocked = &refusal{"user_locked", "access: the Teleport user is locked"}
	// ErrSessionMFARequired: a role of the user (or the cluster) requires
	// Teleport's own per-session MFA, which brokered access cannot satisfy (R9).
	ErrSessionMFARequired = &refusal{"session_mfa_required", "access: per-session MFA required"}
	// ErrRoleOutdated: Teleport refused the impersonation: the management
	// role lacks the impersonate rule (FR-019).
	ErrRoleOutdated = &refusal{"management_role_outdated", "access: the management role cannot impersonate managed users"}
	// ErrIdentityUnsuitable: the management identity is itself an
	// impersonated certificate (a tctl auth sign identity), which Teleport
	// never lets impersonate (plan.md Deviations D1).
	ErrIdentityUnsuitable = &refusal{"management_identity_unsuitable", "access: the management identity cannot impersonate"}
	// ErrInvalid: a lifetime outside 15..720 minutes.
	ErrInvalid = &refusal{"validation_failed", "access: invalid request"}
)

// errLabelMismatch is ErrNotProvisioned for a Teleport user whose labels do
// not name the caller; the audit row says so.
var errLabelMismatch = &refusal{"label_mismatch", "access: the Teleport user is not the caller's"}

type refusal struct{ reason, msg string }

func (e *refusal) Error() string { return e.msg }

// Is makes errLabelMismatch an ErrNotProvisioned.
func (e *refusal) Is(target error) bool { return e == errLabelMismatch && target == ErrNotProvisioned }

// Reason is the closed-vocabulary reason of an access refusal (the API's).
func Reason(err error) string {
	var r *refusal
	if errors.As(err, &r) {
		if r == errLabelMismatch {
			return ErrNotProvisioned.reason
		}
		return r.reason
	}
	return clusters.ReasonOf(err)
}

// AuditReason is Reason with the finer audit-only reasons (label_mismatch).
func AuditReason(err error) string {
	var r *refusal
	if errors.As(err, &r) {
		return r.reason
	}
	return clusters.ReasonOf(err)
}
