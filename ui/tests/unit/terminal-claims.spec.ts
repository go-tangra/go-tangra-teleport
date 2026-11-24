import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { claim, drop, release, RELEASE_GRACE_MS } from '@/stores/terminalClaims'

// The portal shell may mount the terminal page several times while it
// loads; each mount must not open (and immediately close) its own terminal.
describe('terminal claims', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => {
    vi.useRealTimers()
    drop('k')
  })

  it('opens one terminal for concurrent mounts of the same page', async () => {
    const create = vi.fn().mockResolvedValue({ terminal_id: 't1' })
    const [a, b, c] = await Promise.all([claim('k', create), claim('k', create), claim('k', create)])
    expect(create).toHaveBeenCalledTimes(1)
    expect([a, b, c].map((v) => v.terminal_id)).toEqual(['t1', 't1', 't1'])
  })

  it('a quick remount keeps the terminal; the last release closes it after the grace', async () => {
    const create = vi.fn().mockResolvedValue({ terminal_id: 't1' })
    const close = vi.fn()
    await claim('k', create)
    release('k', close) // unmount
    await claim('k', create) // remount within the grace
    vi.advanceTimersByTime(RELEASE_GRACE_MS + 10)
    expect(close).not.toHaveBeenCalled()
    expect(create).toHaveBeenCalledTimes(1)
    release('k', close)
    vi.advanceTimersByTime(RELEASE_GRACE_MS + 10)
    await Promise.resolve()
    expect(close).toHaveBeenCalledWith('t1')
    await claim('k', create) // a later open is a new terminal
    expect(create).toHaveBeenCalledTimes(2)
  })

  it('a failed open is not kept', async () => {
    const create = vi.fn().mockRejectedValueOnce(new Error('refused')).mockResolvedValue({ terminal_id: 't2' })
    await expect(claim('k', create)).rejects.toThrow('refused')
    expect((await claim('k', create)).terminal_id).toBe('t2')
  })

  it('an ended terminal is dropped without closing it again', async () => {
    const create = vi.fn().mockResolvedValue({ terminal_id: 't1' })
    const close = vi.fn()
    await claim('k', create)
    drop('k')
    release('k', close)
    vi.advanceTimersByTime(RELEASE_GRACE_MS + 10)
    await Promise.resolve()
    expect(close).not.toHaveBeenCalled()
  })
})
