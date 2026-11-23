<script setup lang="ts">
// The portal player for one recorded SSH session (spec 003, sessions:play).
// Pages are read from the module (which reads them live from Teleport and
// keeps nothing) and kept in the browser for seeking (R11); the next page
// is fetched while playing, and closing the player aborts any read (FR-005).
// The recording is rendered only by xterm as terminal output, written as
// bytes: no add-ons, no proposed API, OSC 8 links inert (R12, FR-006).
// Opening the player starts one audited playback (the first page).
import { computed, markRaw, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { Terminal } from '@xterm/xterm'
import '@xterm/xterm/css/xterm.css'
import { UiAlert, UiButton, UiCard, UiPage, UiSelect, UiSkeleton, UiSwitch } from '@go-tangra/ui'
import { ApiError, explain } from '@/api/client'
import type { Cluster } from '@/api/types'
import { useClusters } from '@/stores/clusters'
import { recordingApi } from '@/stores/audit'
import { Player, Recording, SPEEDS, teleportSessionUrl, type Op, type SeekResult } from '@/player/model'
import { mirrorStyles, type StyleMirror } from '@/player/cspStyles'

const route = useRoute()
const clusters = useClusters()
const id = computed(() => String(route.params.id ?? ''))
const sid = computed(() => String(route.params.sid ?? ''))
const known = (() => {
  const d = Number(route.query.d)
  return Number.isFinite(d) && d > 0 ? d : undefined
})()

const cluster = ref<Cluster | null>(null)
const starting = ref(true)
const fatal = ref('') // nothing can be played
const partial = ref('') // what loaded plays; the rest failed
const position = ref(0)
const duration = ref(0)
const playing = ref(false)
const waiting = ref(false)
const speed = ref('1')
const skipIdle = ref(false)
const loadedMs = ref(0)
const done = ref(false)

const teleportLink = computed(() => (cluster.value ? teleportSessionUrl(cluster.value.proxy_addr, cluster.value.cluster_name, sid.value) : ''))
const speedOptions = SPEEDS.map((s) => ({ title: `${s}x`, value: String(s) }))

const host = ref<HTMLElement | null>(null)
const frame = ref<HTMLElement | null>(null)
let term: Terminal | null = null
let styles: StyleMirror | null = null
let rec = markRaw(new Recording(known))
let player = markRaw(new Player(rec))
let cursor: string | undefined
let fetching = false
let restarted = false
let aborter = new AbortController()
let raf = 0
let last = 0
let closed = false
let resizeObserver: ResizeObserver | null = null

function sync(): void {
  position.value = player.position
  duration.value = rec.duration
  playing.value = player.playing
  waiting.value = player.waiting
  loadedMs.value = rec.loadedMs
  done.value = rec.done
}

/** Scales the terminal down to the page width instead of cropping it. */
function fit(): void {
  const screen = host.value?.querySelector<HTMLElement>('.xterm-screen')
  if (!host.value || !frame.value || !screen) return
  const avail = frame.value.clientWidth
  const w = screen.offsetWidth
  const scale = w > 0 && avail > 0 ? Math.min(1, avail / w) : 1
  // CSSOM, not a style attribute: allowed by the CSP.
  host.value.style.transform = scale < 1 ? `scale(${scale})` : ''
  host.value.style.transformOrigin = 'top left'
  frame.value.style.height = `${Math.ceil(screen.offsetHeight * scale)}px`
}

function apply(ops: Op[]): void {
  if (!term) return
  for (const op of ops) {
    if (op.kind === 'write') term.write(op.data)
    else {
      term.resize(op.cols, op.rows)
      styles?.sync()
    }
  }
  if (ops.some((o) => o.kind === 'resize')) requestAnimationFrame(fit)
}

function applySeek(r: SeekResult | null): void {
  if (!r || !term) return
  term.reset()
  apply(r.ops)
}

function loop(now: number): void {
  raf = 0
  if (closed) return
  const dt = last ? now - last : 0
  last = now
  apply(player.tick(dt))
  sync()
  if (player.waiting) void fetchNext()
  if (player.playing) raf = requestAnimationFrame(loop)
}

function startLoop(): void {
  if (!raf) {
    last = 0
    raf = requestAnimationFrame(loop)
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/** Reads the next page; keeps reading while playing or waiting (prefetch). */
async function fetchNext(): Promise<void> {
  if (fetching || rec.done || closed) return
  fetching = true
  partial.value = ''
  try {
    for (let busy = 0; ; ) {
      try {
        const p = await recordingApi.page(id.value, sid.value, cursor, aborter.signal)
        if (closed) return
        rec.append(p)
        cursor = p.next
        break
      } catch (e) {
        // 429: another of this user's playbacks is reading; try again shortly.
        if (e instanceof ApiError && e.status === 429 && busy++ < 5 && !closed) {
          await sleep(2000)
          continue
        }
        throw e
      }
    }
    if (starting.value) {
      starting.value = false
      applySeek(player.seek(0))
      player.play()
      startLoop()
    }
    applySeek(player.retry())
    sync()
  } catch (e) {
    if (closed || aborter.signal.aborted) return
    onError(e)
  } finally {
    fetching = false
  }
  if (!rec.done && !closed && !fatal.value && !partial.value && (player.playing || player.waiting)) void fetchNext()
}

function onError(e: unknown): void {
  const reason = e instanceof ApiError ? e.reason : ''
  // R4: a cursor from before a restart or from another instance; start
  // again (a new, audited playback) and come back to the same point, once.
  if (reason === 'playback_expired' && !restarted) {
    restarted = true
    restart(player.position)
    return
  }
  if (starting.value || ['recording_not_found', 'recording_access_denied', 'recording_too_large', 'not_playable'].includes(reason)) {
    starting.value = false
    fatal.value = explain(e)
    player.pause()
    sync()
    return
  }
  partial.value = explain(e)
  sync()
}

function restart(at: number): void {
  rec = markRaw(new Recording(known))
  player = markRaw(new Player(rec))
  cursor = undefined
  term?.reset()
  if (at > 0) {
    player.seek(at) // waits for the data
    player.play()
    startLoop()
  } else {
    starting.value = true
  }
  sync()
  void fetchNext()
}

function retryLoad(): void {
  partial.value = ''
  void fetchNext()
}

function togglePlay(): void {
  if (player.playing) {
    player.pause()
    sync()
    return
  }
  applySeek(player.play())
  sync()
  startLoop()
  void fetchNext()
}

function onSeek(ev: Event): void {
  const t = Number((ev.target as HTMLInputElement).value)
  if (!Number.isFinite(t)) return
  const r = player.seek(t)
  applySeek(r)
  sync()
  if (!r) void fetchNext() // the loading state shows until it arrives
  if (player.playing) startLoop()
}

function onSpeed(v: unknown): void {
  player.setSpeed(Number(v))
  speed.value = String(v)
}

function onSkipIdle(v: boolean): void {
  player.skipIdle = v
  skipIdle.value = v
}

function clock(ms: number): string {
  const s = Math.floor(ms / 1000)
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const ss = String(s % 60).padStart(2, '0')
  return h > 0 ? `${h}:${String(m).padStart(2, '0')}:${ss}` : `${m}:${ss}`
}

onMounted(() => {
  if (host.value) {
    term = new Terminal({
      cols: 80,
      rows: 24,
      disableStdin: true,
      cursorBlink: false,
      scrollback: 1000,
      allowProposedApi: false,
      // OSC 8 hyperlinks in a recording do nothing (the default would offer to open them).
      linkHandler: { activate: () => {} },
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      fontSize: 14,
    })
    term.open(host.value)
    styles = mirrorStyles(host.value)
    styles.sync()
    term.onResize(() => {
      styles?.sync()
      requestAnimationFrame(fit)
    })
    if (typeof ResizeObserver !== 'undefined' && frame.value) {
      resizeObserver = new ResizeObserver(() => fit())
      resizeObserver.observe(frame.value)
    }
  }
  clusters.get(id.value).then((c) => (cluster.value = c), () => undefined)
  void fetchNext()
})

onBeforeUnmount(() => {
  closed = true
  aborter.abort()
  aborter = new AbortController()
  if (raf) cancelAnimationFrame(raf)
  resizeObserver?.disconnect()
  styles?.dispose()
  term?.dispose()
  term = null
})
</script>

<template>
  <UiPage title="Session playback" :subtitle="cluster ? cluster.display_name + ' · ' + sid : sid" data-test="session-player">
    <template #actions>
      <a v-if="teleportLink" :href="teleportLink" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-text" data-test="player-teleport-link">
        Open in Teleport
      </a>
    </template>
    <div class="flex flex-col gap-4">
      <UiAlert v-if="fatal" kind="error" data-test="player-error">
        {{ fatal }}
        <template v-if="teleportLink"> You can still open it in Teleport.</template>
      </UiAlert>
      <UiAlert v-if="partial" kind="warning" data-test="player-partial">
        {{ partial }} What has loaded keeps playing.
        <UiButton size="sm" variant="outline" data-test="player-retry" @click="retryLoad()">Retry</UiButton>
      </UiAlert>
      <UiCard>
        <UiSkeleton v-if="starting && !fatal" data-test="player-starting" />
        <div ref="frame" class="w-full overflow-hidden rounded bg-black" :class="{ hidden: fatal }">
          <div ref="host" class="inline-block" data-test="player-terminal" />
        </div>
        <div v-if="!fatal" class="mt-4 flex flex-col gap-3">
          <div class="flex items-center gap-3">
            <UiButton
              :icon="playing ? 'mdi-stop' : 'mdi-play'"
              icon-only
              :label="playing ? 'Pause' : 'Play'"
              :disabled="starting"
              data-test="player-toggle"
              @click="togglePlay()"
            />
            <span class="font-mono text-sm tabular-nums" data-test="player-time">{{ clock(position) }} / {{ clock(duration) }}</span>
            <span v-if="waiting && !fatal" class="text-sm text-base-content/70" role="status" data-test="player-loading">Loading…</span>
          </div>
          <input
            type="range"
            class="range range-sm w-full"
            min="0"
            :max="Math.max(duration, 1)"
            step="100"
            :value="position"
            :disabled="starting"
            aria-label="Timeline"
            data-test="player-timeline"
            @input="onSeek"
          >
          <div class="text-xs text-base-content/60" data-test="player-loaded">
            Loaded {{ done ? 'all' : 'up to ' + clock(loadedMs) }}
          </div>
          <div class="flex flex-wrap items-end gap-4">
            <UiSelect id="player-speed" :model-value="speed" label="Speed" :options="speedOptions" size="sm" class="w-28" data-test="player-speed" @update:model-value="onSpeed" />
            <UiSwitch id="player-skip-idle" :model-value="skipIdle" label="Skip idle (gaps over 3 s)" data-test="player-skip-idle" @update:model-value="onSkipIdle" />
          </div>
        </div>
      </UiCard>
    </div>
  </UiPage>
</template>
