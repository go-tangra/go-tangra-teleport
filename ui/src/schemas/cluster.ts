import { z } from 'zod'

/** The identity-file cap (server: 64 KiB). */
export const MAX_IDENTITY_BYTES = 64 * 1024

const HOSTPORT = /^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)(:\d{1,5})?$/

/** Light client-side checks; the server (netguard) is authoritative. */
export const proxyAddr = z
  .string()
  .trim()
  .min(1, 'Enter the proxy address.')
  .max(300)
  .refine((s) => HOSTPORT.test(s), 'Use host or host:port, without https:// or a path.')

const identityFile = z.string().min(1, 'Choose the identity file.').max(MAX_IDENTITY_BYTES, 'The identity file is larger than 64 KiB.')

/** POST /clusters. */
export const registerSchema = z.object({
  display_name: z.string().trim().min(1, 'Enter a name.').max(64),
  proxy_addr: proxyAddr,
  credential: identityFile,
})
export type RegisterForm = z.infer<typeof registerSchema>

/** POST /clusters/{id}/credential. */
export const rotateSchema = z.object({ credential: identityFile })
export type RotateForm = z.infer<typeof rotateSchema>

/** PATCH /clusters/{id}. */
export const updateSchema = z.object({
  display_name: z.string().trim().min(1).max(64),
  offline_threshold_minutes: z.coerce.number().int().min(5).max(1440),
  alerts_enabled: z.boolean(),
})
export type UpdateForm = z.infer<typeof updateSchema>
