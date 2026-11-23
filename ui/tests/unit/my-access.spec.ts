import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { ApiError } from '@/api/client'
import { accessApi } from '@/stores/access'
import type { Cluster, MyAccess } from '@/api/types'
import MyAccessCard from '@/pages/clusters/MyAccessCard.vue'

const cluster = { id: 'c1', proxy_addr: 'tp.example.com:443', cluster_name: 'prod.example.com' } as Cluster
const mine: MyAccess = {
  teleport_user: 'tangra-alice', roles: ['access'], logins: ['deploy'], mfa: true, can_terminal: true, can_download: true,
  proxy_addr: 'tp.example.com:443', cluster_name: 'prod.example.com', settings: { access_ttl_minutes: 480 },
}

afterEach(() => vi.restoreAllMocks())

describe('MyAccessCard', () => {
  it('shows the user, logins and downloads access for tsh', async () => {
    vi.spyOn(accessApi, 'mine').mockResolvedValue(mine)
    const dl = vi.spyOn(accessApi, 'download').mockResolvedValue({ user: 'tangra-alice', expires_at: '2026-01-01T08:00:00Z', filename: 'tangra-alice-prod.identity' })
    const w = mount(MyAccessCard, { props: { cluster } })
    await flushPromises()
    expect(w.find('[data-test="my-access-user"]').text()).toBe('tangra-alice')
    expect(w.find('[data-test="my-access-logins"]').text()).toContain('deploy')
    expect(w.find('[data-test="my-access-mfa"]').exists()).toBe(false)
    await w.find('[data-test="my-access-download"]').trigger('click')
    await flushPromises()
    expect(dl).toHaveBeenCalledWith('c1')
    expect(w.find('[data-test="my-access-command"]').text()).toBe('tsh -i tangra-alice-prod.identity --proxy=tp.example.com:443 ssh deploy@<node>')
  })

  it('explains a session without MFA and disables the download', async () => {
    vi.spyOn(accessApi, 'mine').mockResolvedValue({ ...mine, mfa: false })
    const w = mount(MyAccessCard, { props: { cluster } })
    await flushPromises()
    expect(w.find('[data-test="my-access-mfa"]').exists()).toBe(true)
    expect(w.find('[data-test="my-access-download"]').attributes('disabled')).toBeDefined()
  })

  it('explains not being provisioned', async () => {
    vi.spyOn(accessApi, 'mine').mockRejectedValue(new ApiError(409, 'not_provisioned'))
    const w = mount(MyAccessCard, { props: { cluster } })
    await flushPromises()
    expect(w.find('[data-test="my-access-not-provisioned"]').exists()).toBe(true)
    expect(w.find('[data-test="my-access-download"]').exists()).toBe(false)
  })

  it('saves the access lifetime', async () => {
    vi.spyOn(accessApi, 'mine').mockResolvedValue(mine)
    const put = vi.spyOn(accessApi, 'putSettings').mockResolvedValue({ access_ttl_minutes: 60 })
    const w = mount(MyAccessCard, { props: { cluster } })
    await flushPromises()
    await w.find('#access-ttl').setValue('60')
    await w.find('[data-test="access-ttl-save"]').trigger('click')
    await flushPromises()
    expect(put).toHaveBeenCalledWith('c1', { access_ttl_minutes: 60 })
  })
})
