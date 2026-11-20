import { z } from 'zod'
import { splitList } from './identity'
import { LOGIN } from './provisioning'

// Mirrors the server's strict wizard validation (internal/deploy Validate);
// the server remains authoritative.
const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/
const isDomain = (d: string) => {
  const labels = d.split('.')
  return d.length <= 253 && labels.length >= 2 && !/^[0-9]+$/.test(labels[labels.length - 1]) && labels.every((l) => LABEL.test(l))
}
const EMAIL = /^[A-Za-z0-9]([A-Za-z0-9._-]{0,62}[A-Za-z0-9])?@[A-Za-z0-9.-]+$/

export const draftSchema = z
  .object({
    domain: z.string().trim().toLowerCase().refine(isDomain, 'Enter a domain such as teleport.example.com.'),
    cert_mode: z.enum(['acme', 'own_cert']),
    acme_email: z.string().trim().optional(),
    teleport_version: z.string().trim().regex(/^\d{1,4}\.\d{1,4}\.\d{1,4}$/, 'Enter a release version such as 19.1.2.'),
    admin_username: z.string().trim().regex(/^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$/, 'Letters, digits and . _ @ -.'),
    admin_logins: z
      .string()
      .transform(splitList)
      .pipe(z.array(z.string().regex(LOGIN, 'Logins are letters, digits, . _ - and start with a letter or _.')).min(1, 'Enter at least one login.').max(32)),
  })
  .superRefine((v, ctx) => {
    if (v.cert_mode === 'acme' && !(v.acme_email && EMAIL.test(v.acme_email))) {
      ctx.addIssue({ code: 'custom', path: ['acme_email'], message: 'Enter the e-mail address Let’s Encrypt notices go to.' })
    }
  })
  .transform((v) => ({ ...v, acme_email: v.cert_mode === 'acme' ? v.acme_email : undefined }))
export type DraftForm = z.input<typeof draftSchema>
