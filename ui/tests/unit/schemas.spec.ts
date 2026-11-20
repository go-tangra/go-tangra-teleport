import { describe, expect, it } from 'vitest'
import { draftSchema, mappingSchema, provisionSchema, splitList, userSchema } from '@/schemas'

// The schemas mirror the server's validation; the server stays authoritative.
describe('identity and provisioning schemas', () => {
  it('splits comma and space separated lists', () => {
    expect(splitList(' access, editor  auditor,,')).toEqual(['access', 'editor', 'auditor'])
  })

  it('parses a user into role and login arrays', () => {
    const u = userSchema.parse({ name: 'alice', roles: 'access, editor', logins: 'root' })
    expect(u).toEqual({ name: 'alice', roles: ['access', 'editor'], logins: ['root'] })
    expect(userSchema.safeParse({ name: 'alice', roles: '', logins: '' }).success).toBe(false)
  })

  it('validates mappings and provisioning ids', () => {
    expect(mappingSchema.parse({ subject_kind: 'group', subject_ref: 'ops', teleport_roles: 'access', logins: 'ubuntu' }).teleport_roles).toEqual(['access'])
    expect(mappingSchema.safeParse({ subject_kind: 'group', subject_ref: 'ops', teleport_roles: 'access', logins: '-oProxy' }).success).toBe(false)
    expect(provisionSchema.safeParse({ tangra_user_id: 'not-a-uuid' }).success).toBe(false)
  })
})

describe('deployment draft schema', () => {
  const ok = { domain: 'TP.Example.Test', cert_mode: 'acme', acme_email: 'ops@example.test', teleport_version: '19.1.2', admin_username: 'admin', admin_logins: 'root, ubuntu' }

  it('normalizes a valid draft', () => {
    const d = draftSchema.parse(ok)
    expect(d.domain).toBe('tp.example.test')
    expect(d.admin_logins).toEqual(['root', 'ubuntu'])
  })

  it('drops the e-mail for an own certificate', () => {
    expect(draftSchema.parse({ ...ok, cert_mode: 'own_cert' }).acme_email).toBeUndefined()
  })

  it('refuses shell syntax and malformed values', () => {
    for (const bad of [{ domain: 'x$(id).example.test' }, { domain: 'localhost' }, { domain: 'example.123' }, { teleport_version: 'latest' },
      { admin_username: 'a;rm' }, { admin_logins: 'root;id' }, { acme_email: '' }]) {
      expect(draftSchema.safeParse({ ...ok, ...bad }).success, JSON.stringify(bad)).toBe(false)
    }
  })
})
