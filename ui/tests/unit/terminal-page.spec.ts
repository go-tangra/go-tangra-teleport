import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { ApiError } from '@/api/client'
import { accessApi, fromBase64, toBase64 } from '@/stores/access'

// xterm needs a real layout engine: a stand-in records what it is told.
const { terms, FakeTerminal } = vi.hoisted(() => {
  class FakeTerminal {
    writes: unknown[] = []
    cols: number
    rows: number
    dataHandler: ((d: string) => void) | null = null
    disposed = false
    constructor(readonly opts: { cols: number; rows: number }) {
      this.cols = opts.cols
      this.rows = opts.rows
      terms.push(this)
    }
    open() {}
    focus() {}
    onData(h: (d: string) => void) {
      this.dataHandler = h
      return { dispose() {} }
    }
    onResize() {
      return { dispose() {} }
    }
    write(d: unknown) {
      this.writes.push(d)
    }
    resize(c: number, r: number) {
      this.cols = c
      this.rows = r
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

class FakeSource {
  static CLOSED = 2
  static all: FakeSource[] = []
  readyState = 1
  closed = false
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  listeners: Record<string, Array<(ev: MessageEvent) => void>> = {}
  constructor(readonly url: string) {
    FakeSource.all.push(this)
  }
  addEventListener(type: string, h: (ev: MessageEvent) => void) {
    ;(this.listeners[type] ??= []).push(h)
  }
  emit(type: string, data: string, lastEventId = '') {
    for (const h of this.listeners[type] ?? []) h(new MessageEvent(type, { data, lastEventId }))
  }
  close() {
    this.closed = true
    this.readyState = 2
  }
}

import TerminalPage from '@/pages/clusters/TerminalPage.vue'

const view = { terminal_id: 'a'.repeat(32), node: 'node-1', login: 'deploy', teleport_user: 'tangra-alice', started_at: '2026-01-01T00:00:00Z', expires_at: '2026-01-01T08:00:00Z' }

async function open(query = '?node=node-1&login=deploy&host=web-1') {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/teleport/clusters/:id/terminal', component: TerminalPage },
      { path: '/teleport/clusters/:id', name: 'teleport-cluster', component: { template: '<div />' } },
    ],
  })
  await router.push('/teleport/clusters/c1/terminal' + query)
  const w = mount(TerminalPage, { global: { plugins: [router] } })
  await flushPromises()
  return w
}

beforeEach(() => {
  vi.stubGlobal('EventSource', FakeSource)
  FakeSource.all = []
})
afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  vi.useRealTimers()
  terms.length = 0
})

describe('TerminalPage', () => {
  it('creates the terminal, writes output bytes, resumes from the last offset and sends keystrokes', async () => {
    const create = vi.spyOn(accessApi, 'create').mockResolvedValue(view)
    const input = vi.spyOn(accessApi, 'input').mockResolvedValue(undefined)
    const w = await open()
    expect(create).toHaveBeenCalledWith('c1', expect.objectContaining({ node: 'node-1', login: 'deploy' }))
    expect(w.find('[data-test="terminal-info"]').text()).toContain('tangra-alice')
    const src = FakeSource.all[0]!
    expect(src.url).toBe('/api/teleport/v1/clusters/c1/terminals/' + view.terminal_id + '/output')
    src.emit('output', toBase64(new TextEncoder().encode('$ ')), '2')
    expect(terms[0]!.writes[0]).toEqual(new Uint8Array([36, 32]))
    // The stream's maximum age: reconnect from offset 2.
    src.emit('bye', '{}')
    expect(src.closed).toBe(true)
    expect(FakeSource.all[1]!.url).toContain('?from=2')
    terms[0]!.dataHandler!('ls\r')
    await flushPromises()
    expect(input).toHaveBeenCalledWith('c1', view.terminal_id, new TextEncoder().encode('ls\r'))
  })

  it('shows why the terminal ended and stops reading', async () => {
    vi.spyOn(accessApi, 'create').mockResolvedValue(view)
    const w = await open()
    const src = FakeSource.all[0]!
    src.emit('end', '{"reason":"revoked"}')
    await flushPromises()
    expect(src.closed).toBe(true)
    expect(w.find('[data-test="terminal-ended"]').text()).toContain('revoked')
    expect(w.find('[data-test="terminal-end"]').exists()).toBe(false)
  })

  it('sends a keepalive every minute and ends the terminal on leaving', async () => {
    vi.useFakeTimers()
    vi.spyOn(accessApi, 'create').mockResolvedValue(view)
    const keep = vi.spyOn(accessApi, 'keepalive').mockResolvedValue(undefined)
    const close = vi.spyOn(accessApi, 'close').mockResolvedValue(undefined)
    const w = await open()
    vi.advanceTimersByTime(60_000)
    expect(keep).toHaveBeenCalledTimes(1)
    w.unmount()
    expect(close).toHaveBeenCalledWith('c1', view.terminal_id)
    expect(FakeSource.all[0]!.closed).toBe(true)
    expect(terms[0]!.disposed).toBe(true)
  })

  it('explains a refusal', async () => {
    vi.spyOn(accessApi, 'create').mockRejectedValue(new ApiError(403, 'mfa_required'))
    const w = await open()
    expect(w.find('[data-test="terminal-error"]').text()).toMatch(/second factor/)
    expect(FakeSource.all).toHaveLength(0)
  })

  it('needs a node and a login', async () => {
    const create = vi.spyOn(accessApi, 'create')
    const w = await open('')
    expect(create).not.toHaveBeenCalled()
    expect(w.find('[data-test="terminal-error"]').exists()).toBe(true)
  })

  it('round-trips base64', () => {
    const b = new Uint8Array([0, 255, 27, 91])
    expect(fromBase64(toBase64(b))).toEqual(b)
  })
})
