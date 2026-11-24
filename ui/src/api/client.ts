// The Teleport API through the gateway: the kit client bound to this module's base.
import { createApi, ApiError, csrfToken, describe, type Method, type RequestOptions } from '@go-tangra/ui/api'
import { registerReasons } from '@go-tangra/ui/forms'

export { ApiError, csrfToken, describe }
export type { Method, RequestOptions }

export const BASE = '/api/teleport/v1'

// Teleport-specific refusal reasons (closed vocabulary, api/openapi/teleport.yaml).
const REASONS: Record<string, string> = {
  cluster_unreachable: 'The Teleport cluster did not answer. Check its proxy address and that it is running.',
  credential_invalid: 'The identity file is malformed, expired or was rejected by the cluster.',
  unsupported_version: 'This cluster runs an unsupported Teleport version; changes are blocked until it is upgraded.',
  enterprise_only: 'That feature needs Teleport Enterprise.',
  teleport_rejected: 'The Teleport cluster refused the request.',
  dependency_unavailable: 'A platform service the module needs is unavailable.',
  blocked_target: 'That address is not allowed: loopback, link-local, metadata and private networks are refused.',
  // Session playback (spec 003).
  recording_not_found: 'Teleport has no recording of this session (not recorded, still in progress, or deleted).',
  recording_access_denied: "The cluster's management role cannot read session recordings.",
  playback_expired: 'This playback has expired; start it again.',
  recording_too_large: 'This recording is too large to play here.',
  not_playable: 'Only SSH terminal sessions can be played here.',
  // Brokered access (spec 004).
  mfa_required: 'Sign in to the portal with a second factor (MFA) to get Teleport access.',
  not_provisioned: 'You have no Teleport user on this cluster. Ask an administrator to provision you.',
  user_locked: 'Your Teleport user on this cluster is locked.',
  session_mfa_required: "A role of your Teleport user requires Teleport's per-session MFA; use tsh login on this cluster.",
  // Access identity (spec 005).
  access_identity_missing: 'This cluster has no access identity for portal terminals. An administrator must upload one on the cluster page.',
  access_identity_expired: "This cluster's access identity has expired. An administrator must sign in as tangra-access again and replace it.",
  access_identity_invalid: "Teleport rejected this cluster's access identity. An administrator must check the tangra-access role and replace it.",
  access_identity_not_sign_in: 'That identity was made with tctl auth sign, which Teleport never lets impersonate. Upload the file written by tsh login.',
  access_identity_cannot_impersonate: 'Teleport refused certificates for a provisioned user with that identity: its user needs the tangra-access role.',
  too_many: 'Too many terminals are open. End one first.',
  terminal_ended: 'This terminal has ended.',
}
registerReasons(REASONS)

/**
 * Reasons whose text above already says everything the server's message
 * does (it restates the same refusal for API clients): explain shows them
 * once, without the detail.
 */
const SELF_EXPLAINED = new Set(
  Object.keys(REASONS).filter((r) => !['cluster_unreachable', 'credential_invalid', 'teleport_rejected', 'dependency_unavailable', 'blocked_target', 'recording_access_denied'].includes(r)),
)

export const api = createApi({ base: BASE })

/** A server message as a sentence: capitalised and ending in a full stop. */
export function sentence(msg: string): string {
  const t = msg.trim()
  if (!t) return ''
  const s = t.charAt(0).toUpperCase() + t.slice(1)
  return /[.!?]$/.test(s) ? s : `${s}.`
}

const norm = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim()

/**
 * describe() plus the module's own explanation of a refusal (detail.message
 * is written by the module about the caller's input; it never quotes a
 * credential or a Teleport message). A field refusal is its message alone;
 * a reason the module explains itself is shown once, without the message
 * that restates it; any other reason gets the message as a second sentence.
 */
export function explain(err: unknown): string {
  const base = describe(err)
  if (!(err instanceof ApiError)) return base
  const msg = typeof err.detail?.message === 'string' ? err.detail.message : ''
  if (!msg || SELF_EXPLAINED.has(err.reason)) return base
  if (err.reason === 'validation_failed') return sentence(msg)
  if (norm(msg) === norm(base) || norm(base).includes(norm(msg))) return base
  return `${base} ${sentence(msg)}`
}

/**
 * Wraps a form's onSubmit so the module's field refusal
 * ({reason: validation_failed, detail: {field, message}}) reaches the form
 * kit in its per-field shape ({detail: {fields: {[field]: message}}}): the
 * field is highlighted with the server's own message, and no generic
 * "check the highlighted fields" alert is shown. Every other error is
 * rethrown as is.
 */
export function formErrors<A extends unknown[], R>(fn: (...args: A) => Promise<R>): (...args: A) => Promise<R> {
  return async (...args: A) => {
    try {
      return await fn(...args)
    } catch (e) {
      const field = e instanceof ApiError ? e.detail?.field : undefined
      const message = e instanceof ApiError ? e.detail?.message : undefined
      if (e instanceof ApiError && e.reason === 'validation_failed' && typeof field === 'string' && field && typeof message === 'string' && message) {
        throw new ApiError(e.status, e.reason, { fields: { [field]: sentence(message) } })
      }
      throw e
    }
  }
}
