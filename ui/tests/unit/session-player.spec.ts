import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { createPinia, setActivePinia } from 'pinia'
import { ApiError } from '@/api/client'
import { recordingApi } from '@/stores/audit'
import { useClusters } from '@/stores/clusters'
import type { RecordingPage } from '@/player/model'

// xterm needs a real layout engine; the player is tested against a stand-in
// that records what it is told (FR-006: output arrives as bytes only).
const { terms, FakeTerminal } = vi.hoisted(() => {
  class FakeTerminal {
    writes: unknown[] = []
    sizes: [number, number][] = []
    resets = 0
    disposed = false
    constructor(readonly opts: Record<string, unknown>) {
      terms.push(this)
    }
    open() {}
    onResize() {
      return { dispose() {} }
    }
    write(d: unknown) {
      this.writes.push(d)
    }
    resize(c: number, r: number) {
      this.sizes.push([c, r])
    }
    reset() {
      this.resets++
    }
    dispose() {
      this.disposed = true
    }
  }
  const terms: FakeTerminal[] = []
  return { terms, FakeTerminal }
})
vi.mock('@xterm/xterm', () => ({ Terminal: FakeTerminal }))
vi.mock('@xterm/xterm/css/xterm.css', () => ({}))

import SessionPlayer from '@/pages/clusters/SessionPlayer.vue'

async function open(pages: Array<RecordingPage | Error | Promise<never>>) {
  const calls: Array<{ cursor: string | undefined; signal: AbortSignal | undefined }> = []
  vi.spyOn(recordingApi, 'page').mockImplementation(async (_id, _sid, cursor, signal) => {
    calls.push({ cursor, signal })
    const next = pages.shift()
    if (!next) return new Promise<never>(() => {})
    if (next instanceof Error) throw next
    return next
  })
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/teleport/clusters/:id/sessions/:sid/play', component: SessionPlayer }],
  })
  await router.push('/teleport/clusters/c1/sessions/ssh-1/play?d=5')
  const pinia = createPinia()
  setActivePinia(pinia)
  vi.spyOn(useClusters(), 'get').mockResolvedValue({ id: 'c1', display_name: 'prod', proxy_addr: 'tp.example.com:443', cluster_name: 'prod' } as never)
  const w = mount(SessionPlayer, { global: { plugins: [router, pinia] } })
  await flushPromises()
  await flushPromises()
  return { w, calls }
}

afterEach(() => {
  vi.restoreAllMocks()
  terms.length = 0
})

describe('SessionPlayer', () => {
  it('starts a playback, prefetches with the cursor and writes bytes only', async () => {
    const { w, calls } = await open([
      { width: 100, height: 30, events: [[0, 'o', btoa('$ ls\r\n')]], next: 'cur-1', done: false, bytes: 6 },
      { events: [[1000, 'o', btoa('\xff')]], done: true, bytes: 7 },
    ])
    expect(calls.map((c) => c.cursor)).toEqual([undefined, 'cur-1'])
    const t = terms[0]!
    expect(t.opts.disableStdin).toBe(true)
    expect(t.opts.allowProposedApi).toBe(false)
    expect(typeof (t.opts.linkHandler as { activate: unknown }).activate).toBe('function')
    expect(t.sizes[0]).toEqual([100, 30])
    expect(t.writes.length).toBeGreaterThan(0)
    for (const d of t.writes) expect(d).toBeInstanceOf(Uint8Array)
    expect(w.find('[data-test="player-teleport-link"]').attributes('href')).toBe('https://tp.example.com/web/cluster/prod/session/ssh-1')
    w.unmount()
    expect(t.disposed).toBe(true)
  })

  it('aborts loading when closed (FR-005)', async () => {
    const { w, calls } = await open([{ width: 80, height: 24, events: [], next: 'cur-1', done: false, bytes: 0 }])
    expect(calls).toHaveLength(2) // the second read is still in flight
    const signal = calls[1]!.signal!
    expect(signal.aborted).toBe(false)
    w.unmount()
    expect(signal.aborted).toBe(true)
  })

  it('explains a refused playback and keeps the Teleport link', async () => {
    const { w } = await open([new ApiError(422, 'not_playable', { message: 'only SSH terminal sessions can be played here' })])
    expect(w.find('[data-test="player-error"]').text()).toContain('Only SSH terminal sessions')
    expect(w.find('[data-test="player-teleport-link"]').exists()).toBe(true)
    expect(w.find('[data-test="player-toggle"]').exists()).toBe(false)
  })

  it('keeps what loaded when the rest fails and offers a retry', async () => {
    const { w, calls } = await open([
      { width: 80, height: 24, events: [[0, 'o', btoa('a')]], next: 'cur-1', done: false, bytes: 1 },
      new ApiError(502, 'cluster_unreachable'),
      { events: [], done: true, bytes: 1 },
    ])
    expect(w.find('[data-test="player-partial"]').exists()).toBe(true)
    expect(w.find('[data-test="player-error"]').exists()).toBe(false)
    await w.find('[data-test="player-retry"]').trigger('click')
    await flushPromises()
    expect(calls.map((c) => c.cursor)).toEqual([undefined, 'cur-1', 'cur-1'])
    expect(w.find('[data-test="player-partial"]').exists()).toBe(false)
  })
})
