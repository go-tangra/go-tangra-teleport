import { z } from 'zod'

/** Teleport object names the module accepts (server: clusters.ValidName). */
export const TELEPORT_NAME = /^[A-Za-z0-9][A-Za-z0-9._@+:-]{0,127}$/
export const MAX_ROLE_YAML_BYTES = 64 * 1024

const name = z.string().trim().regex(TELEPORT_NAME, 'Use letters, digits and . _ @ + - : (start with a letter or digit).')

/** "a, b c" → ["a", "b", "c"]. */
export const splitList = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)

const nameList = (min: number) =>
  z.string().transform(splitList).pipe(z.array(name).min(min, 'Enter at least one.').max(32, 'At most 32.'))

/** POST /clusters/{id}/users. */
export const userSchema = z.object({ name, roles: nameList(1), logins: nameList(0) })
export type UserForm = z.input<typeof userSchema>

/** PUT /clusters/{id}/users/{name}. */
export const userEditSchema = z.object({ roles: nameList(1), logins: nameList(0) })
export type UserEditForm = z.input<typeof userEditSchema>

/** POST /clusters/{id}/locks. */
export const lockSchema = z.object({
  target_kind: z.enum(['user', 'role', 'server_id']),
  target: name,
  reason: z.string().trim().min(1, 'A reason is required.').max(256),
  expires_at: z
    .string()
    .optional()
    .refine((s) => !s || new Date(s).getTime() > Date.now(), 'The expiry must be in the future.'),
})
export type LockForm = z.input<typeof lockSchema>
