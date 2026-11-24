import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { MODULE_ROLES } from '@/schemas'
import { memberTitle, membersApi } from '@/stores/provisioning'
import { ApiError } from '@/api/client'
import type { MemberCandidate } from '@/api/types'

const { default: MemberPicker } = await import('@/components/MemberPicker.vue')

const alice: MemberCandidate = { user_id: 'u-alice', display_name: 'Alice Smith', login: 'alice@example.com' }
const bob: MemberCandidate = { user_id: 'u-bob', display_name: 'Bob Jones', login: 'bob@example.com' }

afterEach(() => {
  vi.restoreAllMocks()
  vi.useRealTimers()
})

function render(modelValue = '') {
  return mount(MemberPicker, { props: { id: 'member', clusterId: 'c1', label: 'Tangra member', modelValue } })
}
const combo = (w: ReturnType<typeof render>) => w.findComponent({ name: 'UiCombobox' })
const titles = (w: ReturnType<typeof render>) => (combo(w).props('options') as { title: string; value: string }[]).map((o) => o.title)

describe('MemberPicker', () => {
  it('lists members on open with display name and login', async () => {
    const search = vi.spyOn(membersApi, 'search').mockResolvedValue({ items: [alice, bob] })
    const w = render()
    await flushPromises()
    expect(search).toHaveBeenCalledWith('c1', '')
    expect(titles(w)).toEqual(['Alice Smith (alice@example.com)', 'Bob Jones (bob@example.com)'])
  })

  it('searches 250 ms after the last keystroke and ignores stale answers', async () => {
    vi.useFakeTimers()
    const search = vi.spyOn(membersApi, 'search').mockResolvedValue({ items: [alice, bob] })
    const w = render()
    await flushPromises()
    combo(w).vm.$emit('search', 'b')
    combo(w).vm.$emit('search', 'bo')
    vi.advanceTimersByTime(249)
    expect(search).toHaveBeenCalledTimes(1)
    search.mockResolvedValue({ items: [bob] })
    vi.advanceTimersByTime(1)
    await flushPromises()
    expect(search).toHaveBeenCalledTimes(2)
    expect(search).toHaveBeenLastCalledWith('c1', 'bo')
    expect(titles(w)).toEqual(['Bob Jones (bob@example.com)'])
  })

  it('emits the user id and keeps the chosen member shown', async () => {
    vi.useFakeTimers()
    const search = vi.spyOn(membersApi, 'search').mockResolvedValue({ items: [alice, bob] })
    const w = render()
    await flushPromises()
    combo(w).vm.$emit('update:modelValue', 'u-alice')
    expect(w.emitted('update:modelValue')?.[0]).toEqual(['u-alice'])
    await w.setProps({ modelValue: 'u-alice' })
    search.mockResolvedValue({ items: [bob] })
    combo(w).vm.$emit('search', 'bob')
    vi.advanceTimersByTime(250)
    await flushPromises()
    expect(titles(w)).toEqual(['Alice Smith (alice@example.com)', 'Bob Jones (bob@example.com)'])
    combo(w).vm.$emit('update:modelValue', null)
    expect(w.emitted('update:modelValue')?.[1]).toEqual([''])
  })

  it('shows why the search failed', async () => {
    vi.spyOn(membersApi, 'search').mockRejectedValue(new ApiError(503, 'dependency_unavailable', { dependency: 'auth' }))
    const w = render()
    await flushPromises()
    expect(combo(w).props('error')).toBeTruthy()
  })

  it('titles a member by whatever is known', () => {
    expect(memberTitle({ user_id: 'u', display_name: '', login: 'a@example.com' })).toBe('a@example.com')
    expect(memberTitle({ user_id: 'u', display_name: 'a@example.com', login: 'a@example.com' })).toBe('a@example.com')
    expect(memberTitle({ user_id: 'u', display_name: '', login: '' })).toBe('u')
  })
})

// The mapping editor offers the module's own role slugs: they must be the
// manifest's (auth reports only those to provisioning).
const manifest = Object.values(
  import.meta.glob<string>('../../../pkg/teleportmanifest/manifest.go', { query: '?raw', import: 'default', eager: true }),
)[0]!

describe('MODULE_ROLES', () => {
  it('matches the manifest role slugs', () => {
    const block = manifest.slice(manifest.indexOf('var Roles = '), manifest.indexOf('var Grants'))
    const slugs = [...block.matchAll(/Slug: "([a-z0-9-]+)"/g)].map((m) => m[1])
    expect(slugs.length).toBeGreaterThan(0)
    expect(MODULE_ROLES.map((r) => r.slug)).toEqual(slugs)
  })

  it("shows the form's field error", async () => {
    vi.spyOn(membersApi, 'search').mockResolvedValue({ items: [alice] })
    const w = mount(MemberPicker, { props: { id: 'member', clusterId: 'c1', label: 'Tangra member', modelValue: alice.user_id, error: 'This member holds no mapped tangra role or group.' } })
    await flushPromises()
    expect(combo(w).props('error')).toBe('This member holds no mapped tangra role or group.')
    expect(w.text()).toContain('This member holds no mapped tangra role or group.')
  })
})
