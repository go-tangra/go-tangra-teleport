// The pure part of the session player (spec 003, research R10-R12): the
// loaded events of one recording, the timeline, speed, idle skipping and
// seeking. It knows nothing of the DOM or the network: SessionPlayer.vue
// feeds it pages, drives tick() from animation frames and applies the
// returned operations to an xterm terminal. Output stays bytes
// (Uint8Array) from the page to term.write, so nothing in a recording is
// ever interpreted as HTML.

/** Playback speeds (FR-002). */
export const SPEEDS = [0.5, 1, 2, 4, 8] as const
export type Speed = (typeof SPEEDS)[number]

/** Gaps longer than this are shortened by "skip idle" (FR-002). */
export const IDLE_GAP_MS = 3000

/** The largest terminal dimension accepted (the module's bound). */
export const MAX_TERM = 4096

/** Bounds one merged write when replaying many events at once (a seek). */
const MAX_MERGE = 1 << 20

/** One page of GET .../sessions/{sid}/recording (RecordingPage). */
export interface RecordingPage {
  width?: number | undefined
  height?: number | undefined
  events: Array<[number, 'o' | 'r', string]>
  next?: string | undefined
  done: boolean
  bytes: number
}

export type ReplayEvent = { ms: number; kind: 'write'; data: Uint8Array } | { ms: number; kind: 'resize'; cols: number; rows: number }

/** What the terminal is told to do. */
export type Op = { kind: 'write'; data: Uint8Array } | { kind: 'resize'; cols: number; rows: number }

/** A seek: reset the terminal, then apply ops in order. */
export interface SeekResult {
  reset: true
  ops: Op[]
}

/** Decodes base64 to bytes (no text decoding: output need not be UTF-8). */
export function decodeBase64(s: string): Uint8Array {
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function termSize(s: string): { cols: number; rows: number } | null {
  const m = /^(\d{1,4})x(\d{1,4})$/.exec(s)
  if (!m) return null
  const cols = Number(m[1])
  const rows = Number(m[2])
  return cols >= 1 && rows >= 1 && cols <= MAX_TERM && rows <= MAX_TERM ? { cols, rows } : null
}

function dim(n: number | undefined, def: number): number {
  return n !== undefined && Number.isInteger(n) && n >= 1 && n <= MAX_TERM ? n : def
}

/** The loaded part of one recording; pages are appended in order. */
export class Recording {
  width = 80
  height = 24
  done = false
  bytes = 0
  readonly events: ReplayEvent[] = []
  private pages = 0

  /** knownSeconds is the session's duration from the list (R10), if known. */
  constructor(private readonly knownSeconds?: number) {}

  append(p: RecordingPage): void {
    if (this.pages++ === 0) {
      this.width = dim(p.width, 80)
      this.height = dim(p.height, 24)
    }
    let last = this.events.at(-1)?.ms ?? 0
    for (const [rawMs, kind, data] of p.events) {
      const ms = Math.max(Number.isFinite(rawMs) ? rawMs : 0, last)
      if (kind === 'o') {
        let bytes: Uint8Array
        try {
          bytes = decodeBase64(data)
        } catch {
          continue
        }
        if (bytes.length === 0) continue
        this.events.push({ ms, kind: 'write', data: bytes })
      } else if (kind === 'r') {
        const size = termSize(data)
        if (!size) continue
        this.events.push({ ms, kind: 'resize', ...size })
      } else {
        continue
      }
      last = ms
    }
    this.bytes = p.bytes
    if (p.done) this.done = true
  }

  /** The time up to which every event is known. */
  get loadedMs(): number {
    return this.events.at(-1)?.ms ?? 0
  }

  /** Total time: final once done; while loading, the known duration or what has loaded. */
  get duration(): number {
    return Math.max(this.loadedMs, (this.knownSeconds ?? 0) * 1000)
  }

  /** Index of the first event after t. */
  indexAfter(t: number): number {
    let lo = 0
    let hi = this.events.length
    while (lo < hi) {
      const mid = (lo + hi) >> 1
      if ((this.events[mid]?.ms ?? 0) <= t) lo = mid + 1
      else hi = mid
    }
    return lo
  }

  /** The ops of events [from, to), consecutive writes merged (bounded). */
  ops(from: number, to: number): Op[] {
    const out: Op[] = []
    let chunks: Uint8Array[] = []
    let size = 0
    const flush = () => {
      if (chunks.length === 1 && chunks[0]) out.push({ kind: 'write', data: chunks[0] })
      else if (chunks.length > 1) {
        const data = new Uint8Array(size)
        let off = 0
        for (const c of chunks) {
          data.set(c, off)
          off += c.length
        }
        out.push({ kind: 'write', data })
      }
      chunks = []
      size = 0
    }
    for (let i = from; i < to; i++) {
      const e = this.events[i]
      if (!e) break
      if (e.kind === 'write') {
        if (size + e.data.length > MAX_MERGE) flush()
        chunks.push(e.data)
        size += e.data.length
      } else {
        flush()
        out.push({ kind: 'resize', cols: e.cols, rows: e.rows })
      }
    }
    flush()
    return out
  }
}

/** Playback state over a Recording: position (ms), play/pause, speed, idle skipping, seeking. */
export class Player {
  position = 0
  playing = false
  skipIdle = false
  private speed: Speed = 1
  private cursor = 0 // next event to apply
  private pending: number | null = null // a seek waiting for data

  constructor(readonly rec: Recording) {}

  get currentSpeed(): Speed {
    return this.speed
  }

  setSpeed(s: number): void {
    const found = SPEEDS.find((v) => v === s)
    if (found === undefined) throw new Error('unsupported speed')
    this.speed = found
  }

  get ended(): boolean {
    return this.rec.done && this.position >= this.rec.duration
  }

  /** A seek or the playback is waiting for data that has not loaded yet. */
  get waiting(): boolean {
    return this.pending !== null || (this.playing && !this.rec.done && this.position >= this.rec.loadedMs)
  }

  /** Starts or resumes; from the end it starts over (apply the returned seek). */
  play(): SeekResult | null {
    const restart = this.ended ? this.seek(0) : null
    this.playing = true
    return restart
  }

  pause(): void {
    this.playing = false
  }

  /** Jumps to t: the terminal is reset and given all output up to t (R11). Null while t has not loaded. */
  seek(t: number): SeekResult | null {
    t = Math.max(0, t)
    if (this.rec.done) t = Math.min(t, this.rec.duration)
    else if (t > this.rec.loadedMs) {
      this.pending = t
      return null
    }
    this.pending = null
    this.position = t
    this.cursor = this.rec.indexAfter(t)
    return { reset: true, ops: [{ kind: 'resize', cols: this.rec.width, rows: this.rec.height }, ...this.rec.ops(0, this.cursor)] }
  }

  /** Retries a waiting seek once more has loaded. */
  retry(): SeekResult | null {
    if (this.pending === null || (!this.rec.done && this.rec.loadedMs < this.pending)) return null
    return this.seek(this.pending)
  }

  /** Advances by wallMs of real time and returns the ops to apply. */
  tick(wallMs: number): Op[] {
    if (!this.playing || this.pending !== null || wallMs <= 0) return []
    let t = this.advance(wallMs * this.speed)
    if (this.rec.done && t >= this.rec.duration) {
      t = this.rec.duration
      this.playing = false
    } else if (!this.rec.done && t > this.rec.loadedMs) {
      t = this.rec.loadedMs
    }
    t = Math.max(t, this.position)
    const end = this.rec.indexAfter(t)
    const ops = this.rec.ops(this.cursor, end)
    this.cursor = end
    this.position = t
    return ops
  }

  /** Recording time after `left` ms of playback, idle gaps shortened when skipping. */
  private advance(left: number): number {
    let t = this.position
    if (!this.skipIdle) return t + left
    const ev = this.rec.events
    for (let guard = 0; left > 0 && guard < 10_000; guard++) {
      const i = this.rec.indexAfter(t)
      const next = ev[i]
      if (!next) return t + left
      const prev = i > 0 ? (ev[i - 1]?.ms ?? 0) : 0
      const stop = next.ms - prev > IDLE_GAP_MS ? prev + IDLE_GAP_MS : next.ms
      if (t >= stop) {
        t = next.ms // past the shortened gap: on to the next event
        continue
      }
      const step = Math.min(left, stop - t)
      t += step
      left -= step
    }
    return t
  }
}

const SAFE_SID = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/

/** The Teleport web UI link for a session, as the module builds it ("" when unusable). */
export function teleportSessionUrl(proxyAddr: string, clusterName: string, sid: string): string {
  const m = /^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):(\d{1,5})$/.exec(proxyAddr)
  if (!m || !clusterName || !SAFE_SID.test(sid)) return ''
  const host = m[2] === '443' ? m[1] : `${m[1]}:${m[2]}`
  return `https://${host}/web/cluster/${encodeURIComponent(clusterName)}/session/${sid}`
}
