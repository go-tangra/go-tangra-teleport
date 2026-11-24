import { describe, expect, it } from 'vitest'
import { ApiError, explain, formErrors } from '@/api/client'

describe('explain', () => {
  it('shows a self-explanatory refusal once, without the server restating it', () => {
    const e = new ApiError(409, 'not_provisioned', {
      message: 'you have no Teleport user on this cluster; ask an administrator to provision you',
    })
    expect(explain(e)).toBe('You have no Teleport user on this cluster. Ask an administrator to provision you.')
  })

  it.each([
    'mfa_required', 'user_locked', 'session_mfa_required', 'access_identity_missing', 'access_identity_expired',
    'access_identity_invalid', 'access_identity_not_sign_in', 'access_identity_cannot_impersonate', 'too_many',
    'terminal_ended', 'recording_not_found', 'playback_expired', 'recording_too_large', 'not_playable',
  ])('does not append the server message to %s', (reason) => {
    const plain = explain(new ApiError(422, reason))
    expect(explain(new ApiError(422, reason, { message: 'the server says the same thing' }))).toBe(plain)
  })

  it('adds the server detail to a generic refusal, as a sentence', () => {
    const e = new ApiError(503, 'dependency_unavailable', { message: "the tenant's membership cannot be read from auth; nothing was changed" })
    expect(explain(e)).toBe("A platform service the module needs is unavailable. The tenant's membership cannot be read from auth; nothing was changed.")
  })

  it('keeps the remedy the server adds to a recording access refusal', () => {
    const e = new ApiError(403, 'recording_access_denied', { message: 'give it session: [list, read]' })
    expect(explain(e)).toMatch(/cannot read session recordings\. Give it session: \[list, read\]\.$/)
  })

  it('states a field refusal by its own message only', () => {
    const e = new ApiError(422, 'validation_failed', { field: 'tangra_user_id', message: 'this member holds no mapped tangra role or group' })
    expect(explain(e)).toBe('This member holds no mapped tangra role or group.')
    expect(explain(new ApiError(422, 'validation_failed'))).toBe('Please check the highlighted fields.')
  })

  it('never repeats a detail that equals the reason text', () => {
    const e = new ApiError(503, 'dependency_unavailable', { message: 'a platform service the module needs is unavailable' })
    expect(explain(e)).toBe('A platform service the module needs is unavailable.')
  })
})

describe('formErrors', () => {
  it("turns the module's field refusal into the form kit's per-field shape", async () => {
    const submit = formErrors(() => Promise.reject(new ApiError(422, 'validation_failed', { field: 'tangra_user_id', message: 'this member holds no mapped tangra role or group' })))
    const err = await submit().catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).reason).toBe('validation_failed')
    expect((err as ApiError).detail).toEqual({ fields: { tangra_user_id: 'This member holds no mapped tangra role or group.' } })
  })

  it('passes results and every other error through', async () => {
    expect(await formErrors((a: number) => Promise.resolve(a + 1))(1)).toBe(2)
    const other = new ApiError(503, 'dependency_unavailable')
    expect(await formErrors(() => Promise.reject(other))().catch((e: unknown) => e)).toBe(other)
    const fields = new ApiError(422, 'validation_failed', { fields: { a: 'x' } })
    expect(await formErrors(() => Promise.reject(fields))().catch((e: unknown) => e)).toBe(fields)
  })
})
