import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { managedApi, mappingsApi, membersApi } from '@/stores/provisioning'
import { ApiError } from '@/api/client'
import type { Cluster, ManagedUser } from '@/api/types'

const { default: ProvisioningTab } = await import('@/pages/clusters/tabs/ProvisioningTab.vue')

const cluster = { id: 'c1', display_name: 'prod', writes_blocked: false } as Cluster
const bob = { user_id: '018f3a2b-0000-7000-8000-0000000000b1', display_name: 'Bob Jones', login: 'bob@example.com' }

afterEach(() => vi.restoreAllMocks())

async function render() {
  vi.spyOn(mappingsApi, 'list').mockResolvedValue({ items: [] })
  vi.spyOn(managedApi, 'list').mockResolvedValue({ items: [] })
  const search = vi.spyOn(membersApi, 'search').mockResolvedValue({ items: [bob] })
  const w = mount(ProvisioningTab, { props: { cluster }, attachTo: document.body })
  await flushPromises()
  return { w, search }
}

describe('ProvisioningTab', () => {
  it('provisions the member picked by name and sends the user id', async () => {
    const { w, search } = await render()
    expect(search).not.toHaveBeenCalled() // only once the dialog opens
    const provision = vi.spyOn(managedApi, 'provision').mockResolvedValue({} as ManagedUser)
    await w.find('[data-test="provision-new"]').trigger('click')
    await flushPromises()
    expect(search).toHaveBeenCalledWith('c1', '')
    const picker = w.findComponent({ name: 'MemberPicker' })
    expect(picker.exists()).toBe(true)
    const combo = picker.findComponent({ name: 'UiCombobox' })
    expect(combo.props('options')).toEqual([{ title: 'Bob Jones (bob@example.com)', value: bob.user_id }])
    combo.vm.$emit('update:modelValue', bob.user_id)
    await flushPromises()
    const save = w.findAllComponents({ name: 'UiButton' }).find((b) => b.attributes('data-test') === 'provision-save')
    expect(save).toBeTruthy()
    await save!.trigger('click')
    await flushPromises()
    expect(provision).toHaveBeenCalledWith('c1', bob.user_id)
    w.unmount()
  })

  it('offers the module role slugs when mapping a module role', async () => {
    const { w } = await render()
    await w.find('[data-test="mapping-new"]').trigger('click')
    await flushPromises()
    const sel = w.findAllComponents({ name: 'UiSelect' }).find((c) => c.attributes('data-test') === 'mapping-ref')
    expect(sel).toBeTruthy()
    expect((sel!.props('options') as { value: string }[]).map((o) => o.value)).toEqual(['administrator', 'operator', 'auditor', 'viewer'])
    // A group is typed in, starting empty.
    const kind = w.findAllComponents({ name: 'UiSelect' }).find((c) => c.attributes('data-test') === 'mapping-kind')!
    kind.vm.$emit('update:modelValue', 'group')
    await flushPromises()
    const ref = w.findAllComponents({ name: 'UiInput' }).find((c) => c.attributes('data-test') === 'mapping-ref')
    expect(ref).toBeTruthy()
    expect(ref!.props('modelValue')).toBe('')
    w.unmount()
  })

  it("shows the server's refusal once, on the member field", async () => {
    const { w } = await render()
    vi.spyOn(managedApi, 'provision').mockRejectedValue(new ApiError(422, 'validation_failed', {
      field: 'tangra_user_id', message: 'this member holds no mapped tangra role or group',
    }))
    await w.find('[data-test="provision-new"]').trigger('click')
    await flushPromises()
    const picker = w.findComponent({ name: 'MemberPicker' })
    picker.findComponent({ name: 'UiCombobox' }).vm.$emit('update:modelValue', bob.user_id)
    await flushPromises()
    await w.findAllComponents({ name: 'UiButton' }).find((b) => b.attributes('data-test') === 'provision-save')!.trigger('click')
    await flushPromises()
    const dialog = document.body.querySelector('[data-test="provision-dialog"]')?.closest('dialog, [role="dialog"]') ?? document.body
    const text = dialog.textContent ?? ''
    expect(text).not.toContain('Please check the highlighted fields.')
    expect(text.split('This member holds no mapped tangra role or group.').length - 1).toBe(1)
    expect(picker.findComponent({ name: 'UiCombobox' }).props('error')).toBe('This member holds no mapped tangra role or group.')
    w.unmount()
  })

  it('shows any other refusal of the provision dialog once', async () => {
    const { w } = await render()
    vi.spyOn(managedApi, 'provision').mockRejectedValue(new ApiError(503, 'dependency_unavailable', { message: 'the invite could not be delivered' }))
    await w.find('[data-test="provision-new"]').trigger('click')
    await flushPromises()
    w.findComponent({ name: 'MemberPicker' }).findComponent({ name: 'UiCombobox' }).vm.$emit('update:modelValue', bob.user_id)
    await flushPromises()
    await w.findAllComponents({ name: 'UiButton' }).find((b) => b.attributes('data-test') === 'provision-save')!.trigger('click')
    await flushPromises()
    const text = document.body.textContent ?? ''
    expect(text.split('A platform service the module needs is unavailable.').length - 1).toBe(1)
    w.unmount()
  })
})
