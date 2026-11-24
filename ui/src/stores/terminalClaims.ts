// One terminal per page key (cluster, node, login) in this browser tab,
// shared by every mount of the terminal page. The portal shell can mount and
// unmount a module page several times while it loads; without this each
// mount opened a terminal and its unmount closed it at once, and a burst
// ran into the per-user limit ("Too many terminals are open").
import type { TerminalView } from '@/api/types'

/** How long an unmounted page's terminal waits for a remount before it closes. */
export const RELEASE_GRACE_MS = 2000

interface Entry {
  view: Promise<TerminalView>
  holders: number
  timer?: ReturnType<typeof setTimeout> | undefined
}

const entries = new Map<string, Entry>()

/** Returns the key's terminal, opening it with create only if none is held. */
export function claim(key: string, create: () => Promise<TerminalView>): Promise<TerminalView> {
  let e = entries.get(key)
  if (!e) {
    const view = create()
    const fresh: Entry = { view, holders: 0 }
    entries.set(key, fresh)
    view.catch(() => {
      if (entries.get(key) === fresh) entries.delete(key)
    })
    e = fresh
  }
  if (e.timer) {
    clearTimeout(e.timer)
    e.timer = undefined
  }
  e.holders++
  return e.view
}

/** A mount lets go; the last one closes the terminal after RELEASE_GRACE_MS. */
export function release(key: string, close: (terminalId: string) => void): void {
  const e = entries.get(key)
  if (!e) return
  e.holders = Math.max(0, e.holders - 1)
  if (e.holders > 0) return
  e.timer = setTimeout(() => {
    if (entries.get(key) !== e || e.holders > 0) return
    entries.delete(key)
    void e.view.then((v) => close(v.terminal_id), () => undefined)
  }, RELEASE_GRACE_MS)
}

/** The terminal ended (or the tab unloads): forget it without closing it here. */
export function drop(key: string): void {
  const e = entries.get(key)
  if (e?.timer) clearTimeout(e.timer)
  entries.delete(key)
}
