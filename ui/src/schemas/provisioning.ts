import { z } from 'zod'
import { TELEPORT_NAME, splitList } from './identity'

/** POSIX-style logins the module accepts (server: provisioning loginPattern). */
export const LOGIN = /^[A-Za-z_][A-Za-z0-9._-]{0,31}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const roles = z
  .string()
  .transform(splitList)
  .pipe(z.array(z.string().regex(TELEPORT_NAME, 'Use Teleport role names.')).min(1, 'Enter at least one role.').max(16, 'At most 16.'))
const logins = z
  .string()
  .transform(splitList)
  .pipe(z.array(z.string().regex(LOGIN, 'Logins are letters, digits, . _ - and start with a letter or _.')).max(32, 'At most 32.'))

/**
 * The module's own role slugs (pkg/teleportmanifest Roles). Auth reports only
 * these to provisioning, so a module_role mapping can only match one of them.
 */
export const MODULE_ROLES = [
  { slug: 'administrator', title: 'Administrator' },
  { slug: 'operator', title: 'Operator' },
  { slug: 'auditor', title: 'Auditor' },
  { slug: 'viewer', title: 'Viewer' },
] as const

/** POST /clusters/{id}/mappings. */
export const mappingSchema = z.object({
  subject_kind: z.enum(['module_role', 'group']),
  subject_ref: z.string().trim().regex(TELEPORT_NAME, 'Enter the tangra role slug or group id.'),
  teleport_roles: roles,
  logins,
})
export type MappingForm = z.input<typeof mappingSchema>

/** PUT /clusters/{id}/mappings/{mid}: the subject cannot change. */
export const mappingEditSchema = z.object({ teleport_roles: roles, logins })
export type MappingEditForm = z.input<typeof mappingEditSchema>

/** POST /clusters/{id}/managed-users. */
export const provisionSchema = z.object({ tangra_user_id: z.string().trim().regex(UUID, 'Enter a tangra user id.') })
export type ProvisionForm = z.input<typeof provisionSchema>
