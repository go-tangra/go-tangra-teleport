package teleportapi

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"

	"github.com/gravitational/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Module error reasons (contracts/http-api.md). Every error a Client returns
// wraps exactly one of these.
var (
	ErrNotFound          = &reasonError{reason: "not_found", msg: "teleport: not found"}
	ErrConflict          = &reasonError{reason: "conflict", msg: "teleport: conflict"}
	ErrRejected          = &reasonError{reason: "teleport_rejected", msg: "teleport: request rejected"}
	ErrUnreachable       = &reasonError{reason: "cluster_unreachable", msg: "teleport: cluster unreachable"}
	ErrCredentialInvalid = &reasonError{reason: "credential_invalid", msg: "teleport: credential invalid"}
	ErrBlockedTarget     = &reasonError{reason: "blocked_target", msg: "teleport: address not allowed"}
)

// ErrAccessDenied marks a Teleport access denial. It is not a reason of its
// own: a denied call still answers teleport_rejected (errors.Is(err,
// ErrRejected) holds too), but the permission probe (research D3) can tell a
// missing grant apart from any other refusal.
var ErrAccessDenied = errors.New("teleport: access denied")

type reasonError struct{ reason, msg string }

func (e *reasonError) Error() string { return e.msg }

// mapped is a reason error with a sanitized detail.
type mapped struct {
	base   *reasonError
	detail string
	denied bool // a Teleport access denial (ErrAccessDenied)
}

func (e *mapped) Error() string {
	if e.detail == "" {
		return e.base.msg
	}
	return e.base.msg + ": " + e.detail
}

func (e *mapped) Unwrap() error { return e.base }

// Is reports ErrAccessDenied for access denials.
func (e *mapped) Is(target error) bool { return e.denied && target == ErrAccessDenied }

// Reason returns the module reason of a mapped error ("" otherwise).
func Reason(err error) string {
	var r *reasonError
	if errors.As(err, &r) {
		return r.reason
	}
	return ""
}

// Detail returns the sanitized first line of Teleport's message kept in a
// mapped error ("" otherwise): bounded, single-line, no stack trace. The API
// shows it for teleport_rejected so an administrator can read why Teleport
// refused their own input (a role definition).
func Detail(err error) string {
	var m *mapped
	if errors.As(err, &m) {
		return m.detail
	}
	return ""
}

// maxDetail bounds the Teleport message kept in a mapped error.
const maxDetail = 200

// sanitize keeps the first line of the user-facing message, bounded. trace
// errors carry no stack in UserMessage; nothing multi-line survives.
func sanitize(err error) string {
	msg := trace.UserMessage(err)
	if i := strings.IndexAny(msg, "\r\n"); i >= 0 {
		msg = msg[:i]
	}
	if len(msg) > maxDetail {
		msg = msg[:maxDetail]
	}
	return strings.TrimSpace(msg)
}

// MapError maps a teleport/api, gRPC or transport error to a module reason.
func MapError(err error) error {
	if err == nil {
		return nil
	}
	if Reason(err) != "" {
		return err
	}
	base := classify(err)
	return &mapped{base: base, detail: sanitize(err), denied: base == ErrRejected && trace.IsAccessDenied(err)}
}

func classify(err error) *reasonError {
	var certErr x509.CertificateInvalidError
	var unknownAuth x509.UnknownAuthorityError
	switch {
	case trace.IsNotFound(err):
		return ErrNotFound
	case trace.IsCompareFailed(err), trace.IsAlreadyExists(err):
		return ErrConflict
	case errors.As(err, &certErr), errors.As(err, &unknownAuth),
		strings.Contains(err.Error(), "expired certificate"), strings.Contains(err.Error(), "bad certificate"):
		return ErrCredentialInvalid
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), trace.IsConnectionProblem(err):
		return ErrUnreachable
	case trace.IsAccessDenied(err), trace.IsBadParameter(err), trace.IsLimitExceeded(err):
		return ErrRejected
	}
	switch status.Code(err) {
	case codes.DeadlineExceeded, codes.Unavailable, codes.Canceled:
		return ErrUnreachable
	case codes.Unauthenticated:
		return ErrCredentialInvalid
	}
	return ErrRejected
}
