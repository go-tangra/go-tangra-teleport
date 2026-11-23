import { describe, expect, it } from 'vitest'
import { IDLE_GAP_MS, Player, Recording, SPEEDS, decodeBase64, teleportSessionUrl, type Op, type RecordingPage } from '@/player/model'

// The player model is the pure part of the session player (spec 003,
// research R10-R12): loaded events, the timeline, speed, idle skipping and
// seeking. Output stays bytes (Uint8Array) end to end.
const enc = (s: string) => btoa(s)
const text = (ops: Op[]) =>
  ops
    .filter((o) => o.kind === 'write')
    .map((o) => (o.kind === 'write' ? String.fromCharCode(...o.data) : ''))
    .join('')

function page(events: RecordingPage['events'], extra: Partial<RecordingPage> = {}): RecordingPage {
  return { events, done: false, bytes: 0, ...extra }
}

/** A recording: "a" at 1 s, resize at 1.5 s, "b" at 2 s, a 10 s idle gap, "c" at 12 s. */
function sample(done = true): Recording {
  const r = new Recording()
  r.append(page([[1000, 'o', enc('a')], [1500, 'r', '100x30'], [2000, 'o', enc('b')], [12000, 'o', enc('c')]], { width: 80, height: 24, done }))
  return r
}

describe('Recording', () => {
  it('keeps the size, decodes output as bytes and knows its duration', () => {
    const r = sample()
    expect([r.width, r.height]).toEqual([80, 24])
    expect(r.events).toHaveLength(4)
    expect(r.events[0]).toEqual({ ms: 1000, kind: 'write', data: new Uint8Array([97]) })
    expect(r.events[1]).toEqual({ ms: 1500, kind: 'resize', cols: 100, rows: 30 })
    expect(r.duration).toBe(12000)
    expect(r.loadedMs).toBe(12000)
  })

  it('uses the known duration (from the list) and grows while loading', () => {
    const r = new Recording(20)
    r.append(page([[1000, 'o', enc('a')]], { width: 80, height: 24 }))
    expect(r.duration).toBe(20000)
    expect(r.done).toBe(false)
    r.append(page([[25000, 'o', enc('z')]], { done: true }))
    expect(r.duration).toBe(25000)
  })

  it('keeps time from going backwards and drops unusable events', () => {
    const r = new Recording()
    r.append(page([[500, 'o', enc('x')], [400, 'o', enc('y')], [600, 'r', 'junk'], [700, 'r', '0x5'], [800, 'r', '5000x10'], [900, 'o', '']], { width: 80, height: 24 }))
    expect(r.events.map((e) => e.ms)).toEqual([500, 500])
    // Binary (non UTF-8) bytes survive.
    expect(decodeBase64(btoa('\xff\x1b['))).toEqual(new Uint8Array([0xff, 0x1b, 0x5b]))
  })

  it('falls back to 80x24 without a size', () => {
    const r = new Recording()
    r.append(page([], { done: true }))
    expect([r.width, r.height]).toEqual([80, 24])
  })
})

describe('Player', () => {
  it('plays at the original timing', () => {
    const p = new Player(sample())
    expect(p.seek(0)?.ops).toEqual([{ kind: 'resize', cols: 80, rows: 24 }])
    p.play()
    expect(p.tick(999)).toEqual([])
    expect(text(p.tick(1))).toBe('a')
    expect(p.position).toBe(1000)
    const ops = p.tick(1000)
    expect(ops).toEqual([{ kind: 'resize', cols: 100, rows: 30 }, { kind: 'write', data: new Uint8Array([98]) }])
  })

  it('pauses and resumes from the same point', () => {
    const p = new Player(sample())
    p.seek(0)
    p.play()
    p.tick(1500)
    p.pause()
    expect(p.tick(5000)).toEqual([])
    expect(p.position).toBe(1500)
    p.play()
    expect(text(p.tick(500))).toBe('b')
  })

  it('offers the spec speeds and applies them from the current point', () => {
    expect([...SPEEDS]).toEqual([0.5, 1, 2, 4, 8])
    const p = new Player(sample())
    p.seek(0)
    p.play()
    p.setSpeed(2)
    p.tick(500)
    expect(p.position).toBe(1000)
    p.setSpeed(0.5)
    p.tick(1000)
    expect(p.position).toBe(1500)
    expect(() => p.setSpeed(3)).toThrow()
  })

  it('shortens idle gaps over 3 s while the timeline keeps real time', () => {
    const p = new Player(sample())
    p.seek(2000)
    p.play()
    p.skipIdle = true
    p.tick(IDLE_GAP_MS) // the first 3 s of the 10 s gap play normally
    expect(p.position).toBe(5000)
    expect(text(p.tick(250))).toBe('c') // the rest is skipped
    expect(p.position).toBe(12000)
    // Without skipping the gap plays in full.
    const q = new Player(sample())
    q.seek(2000)
    q.play()
    q.tick(3250)
    expect(q.position).toBe(5250)
    // Seeking into a gap and skipping jumps on to the next event.
    const s = new Player(sample())
    s.seek(8000)
    s.play()
    s.skipIdle = true
    expect(text(s.tick(100))).toBe('c')
    expect(s.position).toBe(12000) // the end of the recording
    expect(s.ended).toBe(true)
  })

  it('seeks to exactly the output up to t, resizes included', () => {
    const p = new Player(sample())
    p.seek(0)
    p.play()
    p.tick(12000)
    const back = p.seek(1700)
    expect(back?.reset).toBe(true)
    expect(back?.ops).toEqual([{ kind: 'resize', cols: 80, rows: 24 }, { kind: 'write', data: new Uint8Array([97]) }, { kind: 'resize', cols: 100, rows: 30 }])
    // Nothing from the previous position bleeds in (the end paused it).
    expect(p.playing).toBe(false)
    expect(p.play()).toBeNull()
    expect(text(p.tick(300))).toBe('b')
    const end = p.seek(99999)
    expect(text(end?.ops ?? [])).toBe('abc')
    expect(p.position).toBe(12000)
    expect(p.seek(-5)?.ops).toEqual([{ kind: 'resize', cols: 80, rows: 24 }])
  })

  it('merges consecutive output into one write on seek', () => {
    const r = new Recording()
    r.append(page([[1, 'o', enc('he')], [2, 'o', enc('llo')]], { width: 10, height: 5, done: true }))
    const ops = new Player(r).seek(5)?.ops ?? []
    expect(ops).toHaveLength(2)
    expect(ops[0]).toEqual({ kind: 'resize', cols: 10, rows: 5 })
    expect(text(ops)).toBe('hello')
  })

  it('waits for data when seeking or playing past what has loaded', () => {
    const r = new Recording(30)
    r.append(page([[1000, 'o', enc('a')]], { width: 80, height: 24 }))
    const p = new Player(r)
    p.seek(0)
    p.play()
    p.tick(5000)
    expect(p.position).toBe(1000)
    expect(p.waiting).toBe(true)
    expect(p.seek(20000)).toBeNull() // not loaded yet
    expect(p.waiting).toBe(true)
    expect(p.retry()).toBeNull()
    r.append(page([[15000, 'o', enc('b')], [21000, 'o', enc('c')]]))
    const ops = p.retry()
    expect(text(ops?.ops ?? [])).toBe('ab')
    expect(p.position).toBe(20000)
    expect(p.waiting).toBe(false)
  })

  it('ends at the duration', () => {
    const p = new Player(sample())
    p.seek(0)
    p.play()
    p.tick(60000)
    expect(p.position).toBe(12000)
    expect(p.ended).toBe(true)
    expect(p.playing).toBe(false)
    p.play() // from the end: start over
    expect(p.position).toBe(0)
    expect(p.playing).toBe(true)
  })

  it('stays within 100 ms of the original over 10 minutes at 1x (SC-006)', () => {
    const r = new Recording()
    const evs: RecordingPage['events'] = []
    for (let ms = 0; ms <= 600_000; ms += 1000) evs.push([ms, 'o', enc('.')])
    r.append(page(evs, { width: 80, height: 24, done: true }))
    const p = new Player(r)
    p.seek(0)
    p.play()
    let wall = 0
    for (let i = 0; i < 36_000; i++) {
      p.tick(16.67)
      wall += 16.67
    }
    expect(Math.abs(p.position - Math.min(wall, 600_000))).toBeLessThan(100)
  })
})

describe('teleportSessionUrl', () => {
  it('mirrors the module link and refuses unsafe input', () => {
    expect(teleportSessionUrl('teleport.example.com:443', 'prod', 'abc-1')).toBe('https://teleport.example.com/web/cluster/prod/session/abc-1')
    expect(teleportSessionUrl('tp.example.com:3080', 'prod', 'abc-1')).toBe('https://tp.example.com:3080/web/cluster/prod/session/abc-1')
    expect(teleportSessionUrl('tp.example.com:443', 'prod', '../x')).toBe('')
    expect(teleportSessionUrl('', 'prod', 'abc')).toBe('')
    expect(teleportSessionUrl('tp.example.com:443', '', 'abc')).toBe('')
  })
})
