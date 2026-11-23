<script setup lang="ts">
// A brokered SSH terminal (spec 004, US1): a shell on one node as the
// caller's own provisioned Teleport user, opened by the module through the
// cluster's proxy. Output arrives as server-sent events (byte offsets as
// event ids, so a reconnect resumes where it stopped); keystrokes, resizes
// and a keepalive every 60 s are POSTed. Leaving the page ends the
// terminal. Teleport records the session under the user. Output is written
// to xterm as bytes only; links are inert.
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Terminal } from '@xterm/xterm'
import '@xterm/xterm/css/xterm.css'
import { UiAlert, UiBadge, UiButton, UiCard, UiPage, UiSkeleton } from '@go-tangra/ui'
import { explain } from '@/api/client'
import type { TerminalView } from '@/api/types'
import { accessApi, fromBase64 } from '@/stores/access'
import { mirrorStyles, type StyleMirror } from '@/player/cspStyles'
import { formatTime } from './status'

/** Keepalive period; the module ends a terminal after 3 min without one. */
const KEEPALIVE_MS = 60_000

const END_TEXT: Record<string, string> = {
  closed: 'You ended this terminal.',
  exit: 'The shell exited.',
  reader_gone: 'The terminal ended because the page was not connected.',
  keepalive_lost: 'The terminal ended because your portal session was not seen for 3 minutes.',
  max_duration: 'The terminal reached its 8 hour maximum.',
  certificate_expired: 'Your Teleport access for this terminal expired.',
  revoked: 'Your access was revoked (de-provisioned, locked or permission removed).',
  shutdown: 'The Teleport module restarted.',
  error: 'The connection to the node failed.',
}

/** Refusals of the cluster's access identity (spec 005), with what to do. */
const IDENTITY_HINT: Record<string, string> = {
  access_identity_missing: 'An administrator can upload it on the cluster page under "Access identity for portal terminals".',
  access_identity_expired: 'An administrator can renew it: sign in again with the tsh login command shown on the cluster page and choose Replace.',
  access_identity_invalid: 'An administrator can check the tangra-access role on the cluster and replace the identity on the cluster page.',
}

const route = useRoute()
const router = useRouter()
// Fixed at open: the route changes before the page unmounts.
const clusterId = String(route.params.id ?? '')
const node = String(route.query.node ?? '')
const login = String(route.query.login ?? '')
const host = String(route.query.host ?? node)

const view = ref<TerminalView | null>(null)
const starting = ref(true)
const error = ref('')
const ended = ref('')
const connected = ref(false)

const frame = ref<HTMLElement | null>(null)
const screen = ref<HTMLElement | null>(null)
let term: Terminal | null = null
let styles: StyleMirror | null = null
let source: EventSource | null = null
let offset = 0
let keepalive: ReturnType<typeof setInterval> | undefined
let resizeTimer: ReturnType<typeof setTimeout> | undefined
let resizeObserver: ResizeObserver | null = null
let closed = false
let sending: Promise<unknown> = Promise.resolve()
const encoder = new TextEncoder()

/** Columns and rows that fit the frame (approximate monospace cell). */
function fitSize(): { cols: number; rows: number } {
  const w = frame.value?.clientWidth ?? 0
  const h = frame.value?.clientHeight ?? 0
  const cols = w > 0 ? Math.floor((w - 16) / 8.5) : 100
  const rows = h > 0 ? Math.floor((h - 16) / 17) : 30
  return { cols: Math.min(500, Math.max(20, cols)), rows: Math.min(200, Math.max(8, rows)) }
}

function finish(reason: string): void {
  ended.value = END_TEXT[reason] ?? 'The terminal ended.'
  connected.value = false
  source?.close()
  source = null
  if (keepalive) clearInterval(keepalive)
  keepalive = undefined
}

function connect(): void {
  if (!view.value || closed || ended.value) return
  source?.close()
  source = new EventSource(accessApi.outputUrl(clusterId, view.value.terminal_id, offset))
  source.onopen = () => (connected.value = true)
  source.addEventListener('output', (ev) => {
    const m = ev as MessageEvent<string>
    const next = Number(m.lastEventId)
    if (Number.isFinite(next) && next > offset) offset = next
    term?.write(fromBase64(m.data))
  })
  source.addEventListener('gap', () => term?.write('\r\n[earlier output was dropped]\r\n'))
  source.addEventListener('end', (ev) => {
    let reason = ''
    try {
      reason = JSON.parse((ev as MessageEvent<string>).data).reason ?? ''
    } catch {
      // keep the generic text
    }
    finish(reason)
  })
  // The stream closes every few minutes (gateway timeout): reconnect from
  // the last offset rather than letting the browser replay the old URL.
  source.addEventListener('bye', () => {
    source?.close()
    source = null
    connect()
  })
  source.onerror = () => {
    connected.value = false
    if (source?.readyState === EventSource.CLOSED && !ended.value && !closed) {
      source = null
      setTimeout(() => {
        // Gone (404) or refused: ask the API so the page can say why.
        if (!view.value || closed || ended.value) return
        accessApi.keepalive(clusterId, view.value.terminal_id).then(connect, (e) => {
          const reason = (e as { reason?: string }).reason
          if (reason === 'terminal_ended' || reason === 'not_found') finish('')
          else error.value = explain(e)
        })
      }, 2000)
    }
  }
}

function send(data: string): void {
  const v = view.value
  if (!v || ended.value) return
  const bytes = encoder.encode(data)
  sending = sending.then(() => accessApi.input(clusterId, v.terminal_id, bytes)).catch((e) => {
    if ((e as { reason?: string }).reason === 'terminal_ended') finish('')
    else error.value = explain(e)
  })
}

function resize(): void {
  if (!term || !view.value || ended.value) return
  const { cols, rows } = fitSize()
  if (cols === term.cols && rows === term.rows) return
  term.resize(cols, rows)
  styles?.sync()
  const v = view.value
  if (resizeTimer) clearTimeout(resizeTimer)
  resizeTimer = setTimeout(() => void accessApi.resize(clusterId, v.terminal_id, cols, rows).catch(() => undefined), 200)
}

async function end(): Promise<void> {
  const v = view.value
  if (!v || ended.value) return
  try {
    await accessApi.close(clusterId, v.terminal_id)
  } catch {
    // already ended
  }
  finish('closed')
}

function onUnload(): void {
  if (view.value && !ended.value) accessApi.closeOnUnload(clusterId, view.value.terminal_id)
}

onMounted(async () => {
  const size = fitSize()
  if (screen.value) {
    term = new Terminal({
      cols: size.cols,
      rows: size.rows,
      cursorBlink: true,
      scrollback: 5000,
      allowProposedApi: false,
      // OSC 8 hyperlinks from the node do nothing.
      linkHandler: { activate: () => {} },
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      fontSize: 14,
    })
    term.open(screen.value)
    styles = mirrorStyles(screen.value)
    styles.sync()
    term.onData(send)
    term.onResize(() => styles?.sync())
  }
  if (!node || !login) {
    starting.value = false
    error.value = 'Choose a node and a login from the Resources tab.'
    return
  }
  try {
    view.value = await accessApi.create(clusterId, { node, login, cols: size.cols, rows: size.rows })
  } catch (e) {
    const hint = IDENTITY_HINT[(e as { reason?: string }).reason ?? '']
    error.value = hint ? `${explain(e)} ${hint}` : explain(e)
    starting.value = false
    return
  }
  starting.value = false
  if (closed) {
    accessApi.closeOnUnload(clusterId, view.value.terminal_id)
    return
  }
  connect()
  term?.focus()
  keepalive = setInterval(() => {
    const v = view.value
    if (v && !ended.value) void accessApi.keepalive(clusterId, v.terminal_id).catch(() => undefined)
  }, KEEPALIVE_MS)
  if (typeof ResizeObserver !== 'undefined' && frame.value) {
    resizeObserver = new ResizeObserver(() => resize())
    resizeObserver.observe(frame.value)
  }
  window.addEventListener('pagehide', onUnload)
})

onBeforeUnmount(() => {
  closed = true
  window.removeEventListener('pagehide', onUnload)
  if (view.value && !ended.value) void accessApi.close(clusterId, view.value.terminal_id).catch(() => undefined)
  source?.close()
  source = null
  if (keepalive) clearInterval(keepalive)
  if (resizeTimer) clearTimeout(resizeTimer)
  resizeObserver?.disconnect()
  styles?.dispose()
  term?.dispose()
  term = null
})
</script>

<template>
  <UiPage title="Terminal" :subtitle="login && host ? login + '@' + host : 'SSH'" data-test="terminal-page">
    <template #actions>
      <UiButton variant="text" icon="mdi-arrow-left" @click="router.push({ name: 'teleport-cluster', params: { id: clusterId } })">Cluster</UiButton>
      <UiButton v-if="view && !ended" color="error" variant="soft" icon="mdi-power" data-test="terminal-end" @click="end()">End</UiButton>
    </template>
    <div class="flex flex-col gap-4">
      <UiAlert v-if="error" kind="error" data-test="terminal-error">{{ error }}</UiAlert>
      <UiAlert v-if="ended" kind="info" data-test="terminal-ended">{{ ended }}</UiAlert>
      <div v-if="view" class="flex flex-wrap items-center gap-2 text-sm" data-test="terminal-info">
        <UiBadge :color="ended ? 'neutral' : connected ? 'success' : 'warning'">{{ ended ? 'ended' : connected ? 'connected' : 'connecting' }}</UiBadge>
        <span>as <span class="font-mono">{{ view.teleport_user }}</span></span>
        <span class="opacity-70">ends at the latest {{ formatTime(view.expires_at) }}</span>
      </div>
      <UiCard :padded="false">
        <UiSkeleton v-if="starting" data-test="terminal-starting" />
        <div ref="frame" class="h-[70vh] w-full overflow-hidden rounded bg-black p-2" :class="{ hidden: !!error && !view }">
          <div ref="screen" class="h-full" data-test="terminal-screen" />
        </div>
      </UiCard>
    </div>
  </UiPage>
</template>
