import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { ApiError } from '@/api/client'
import { accessApi, accessLoginCommand } from '@/stores/access'
import type { AccessIdentity, Cluster } from '@/api/types'

vi.mock('@go-tangra/ui', async (orig) => ({
  ...(await orig<typeof import('@go-tangra/ui')>()),
  useConfirm: () => ({ ask: async () => true }),
}))

const { default: AccessIdentityCard } = await import('@/pages/clusters/AccessIdentityCard.vue')

const cluster = { id: 'c1', proxy_addr: 'tp.example.com:443', cluster_name: 'prod.example.com' } as Cluster
const ok: AccessIdentity = { configured: true, teleport_user: 'tangra-access', expires_at: '2027-11-23T10:00:00Z', state: 'ok' }
const missing: AccessIdentity = { configured: false, state: 'missing' }

afterEach(() => vi.restoreAllMocks())

async function pick(w: ReturnType<typeof mount>, text: string): Promise<void> {
  // jsdom's File has no text(): a stand-in with the one method the card reads.
  const f = { name: 'tangra-access.identity', size: text.length, text: async () => text } as unknown as File
  w.findComponent({ name: 'UiFilePicker' }).vm.$emit('update:modelValue', f)
  await flushPromises()
}

describe('AccessIdentityCard', () => {
  it('shows the exact tsh login command', () => {
    expect(accessLoginCommand('tp.example.com:443')).toBe(
      'tsh login --proxy=tp.example.com:443 --user=tangra-access --ttl=525600 --format=file --out=tangra-access.identity',
    )
  })

  it('explains a missing identity and uploads one', async () => {
    vi.spyOn(accessApi, 'accessIdentity').mockResolvedValue(missing)
    const put = vi.spyOn(accessApi, 'putAccessIdentity').mockResolvedValue({ ...ok, impersonation_checked: true })
    const w = mount(AccessIdentityCard, { props: { cluster } })
    await flushPromises()
    expect(w.find('[data-test="access-identity-state"]').text()).toBe('not set up')
    expect(w.find('[data-test="access-identity-missing"]').exists()).toBe(true)
    expect(w.find('[data-test="access-identity-command"]').text()).toBe(accessLoginCommand('tp.example.com:443'))
    expect(w.find('[data-test="access-identity-remove"]').exists()).toBe(false)
    await pick(w, 'IDENTITY')
    expect(put).toHaveBeenCalledWith('c1', 'IDENTITY')
    expect(w.find('[data-test="access-identity-state"]').text()).toBe('valid')
    expect(w.find('[data-test="access-identity-user"]').text()).toBe('tangra-access')
    expect(w.find('[data-test="access-identity-notice"]').text()).toMatch(/saved/)
  })

  it('explains a refused upload', async () => {
    vi.spyOn(accessApi, 'accessIdentity').mockResolvedValue(missing)
    vi.spyOn(accessApi, 'putAccessIdentity').mockRejectedValue(new ApiError(422, 'access_identity_not_sign_in'))
    const w = mount(AccessIdentityCard, { props: { cluster } })
    await flushPromises()
    await pick(w, 'SIGNED')
    expect(w.find('[data-test="access-identity-error"]').text()).toMatch(/tctl auth sign/)
  })

  it('shows an expired identity and removes it', async () => {
    const get = vi.spyOn(accessApi, 'accessIdentity').mockResolvedValue({ ...ok, state: 'expired' })
    const del = vi.spyOn(accessApi, 'deleteAccessIdentity').mockResolvedValue(undefined)
    const w = mount(AccessIdentityCard, { props: { cluster } })
    await flushPromises()
    expect(w.find('[data-test="access-identity-state"]').text()).toBe('expired')
    expect(w.find('[data-test="access-identity-expired"]').exists()).toBe(true)
    get.mockResolvedValue(missing)
    await w.find('[data-test="access-identity-remove"]').trigger('click')
    await flushPromises()
    expect(del).toHaveBeenCalledWith('c1')
    expect(w.find('[data-test="access-identity-state"]').text()).toBe('not set up')
  })
})
