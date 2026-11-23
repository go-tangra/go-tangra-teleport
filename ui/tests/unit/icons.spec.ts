// Every icon the module names must be in @go-tangra/ui's bundled set: an
// unknown name renders as a blank/generic glyph, both in the module pages and
// in the portal nav (which draws the manifest's nav icons with the same set).
import { describe, expect, it } from 'vitest'
import { ICONS } from '@go-tangra/ui'

const sources: Record<string, string> = {
  ...import.meta.glob<string>('../../src/**/*.{vue,ts}', { query: '?raw', import: 'default', eager: true }),
  ...import.meta.glob<string>(['../../../pkg/teleportmanifest/*.go', '!../../../pkg/teleportmanifest/*_test.go'], {
    query: '?raw',
    import: 'default',
    eager: true,
  }),
}

describe('icons', () => {
  it('reads the module sources and the manifest', () => {
    const paths = Object.keys(sources)
    expect(paths.some((p) => p.endsWith('manifest.go'))).toBe(true)
    expect(paths.some((p) => p.endsWith('.vue'))).toBe(true)
  })

  it('uses only icons from the bundled set', () => {
    const known = new Set<string>(ICONS)
    const missing: string[] = []
    for (const [path, text] of Object.entries(sources)) {
      for (const name of text.match(/mdi-[a-z0-9-]+/g) ?? []) {
        if (!known.has(name)) missing.push(`${name} (${path})`)
      }
    }
    expect(missing).toEqual([])
  })
})
