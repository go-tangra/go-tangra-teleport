import { api, ApiError, BASE, csrfToken } from '@/api/client'
import type { AccessNode, AccessSettings, IssuedIdentity, MyAccess, TerminalView } from '@/api/types'

// Brokered Teleport access (spec 004): the caller's own provisioned
// Teleport user, never one a request names. Issuance needs an MFA portal
// session; the identity file is handed to the browser to save and is not
// kept anywhere in the page.
const c = (id: string) => 'clusters/' + id
const t = (id: string, tid: string) => c(id) + '/terminals/' + encodeURIComponent(tid)

/** base64 of bytes (keystrokes). */
export function toBase64(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(s)
}

/** Bytes of base64 terminal output. */
export function fromBase64(b64: string): Uint8Array {
  const s = atob(b64)
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}

async function refusal(r: Response): Promise<ApiError> {
  let body: { reason?: string; detail?: Record<string, unknown>; message?: string } = {}
  try {
    body = await r.json()
  } catch {
    // not JSON
  }
  const detail = body.detail ?? (body.message ? { message: body.message } : undefined)
  return new ApiError(r.status, body.reason ?? 'error', detail)
}

export const accessApi = {
  mine: (id: string) => api<MyAccess>('GET', c(id) + '/access'),
  nodes: (id: string) => api<{ items: AccessNode[] }>('GET', c(id) + '/access/nodes'),
  putSettings: (id: string, body: AccessSettings) => api<AccessSettings>('PUT', c(id) + '/access/settings', body),

  /**
   * Issues an identity file and hands it to the browser as a download. The
   * file never enters component state; only its user and expiry are returned.
   */
  async download(id: string, ttlMinutes?: number): Promise<IssuedIdentity> {
    const r = await fetch(`${BASE}/${c(id)}/access/identity`, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
      body: JSON.stringify(ttlMinutes ? { ttl_minutes: ttlMinutes } : {}),
    })
    if (!r.ok) throw await refusal(r)
    const disposition = r.headers.get('Content-Disposition') ?? ''
    const filename = /filename="([^"]+)"/.exec(disposition)?.[1] ?? 'teleport.identity'
    const blob = await r.blob()
    const url = URL.createObjectURL(blob)
    try {
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.rel = 'noopener'
      document.body.appendChild(a)
      a.click()
      a.remove()
    } finally {
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    }
    return { user: r.headers.get('X-Teleport-User') ?? '', expires_at: r.headers.get('X-Teleport-Expires') ?? '', filename }
  },

  create: (id: string, body: { node: string; login: string; cols: number; rows: number }) => api<TerminalView>('POST', c(id) + '/terminals', body),
  input: (id: string, tid: string, data: Uint8Array) => api('POST', t(id, tid) + '/input', { data: toBase64(data) }),
  resize: (id: string, tid: string, cols: number, rows: number) => api('POST', t(id, tid) + '/resize', { cols, rows }),
  keepalive: (id: string, tid: string) => api('POST', t(id, tid) + '/keepalive'),
  close: (id: string, tid: string) => api('DELETE', t(id, tid)),
  /** Ends the terminal while the page unloads (the request outlives the page). */
  closeOnUnload(id: string, tid: string): void {
    void fetch(`${BASE}/${t(id, tid)}`, { method: 'DELETE', credentials: 'same-origin', keepalive: true, headers: { 'X-CSRF-Token': csrfToken() } }).catch(() => undefined)
  },
  /** The SSE output stream from a byte offset. */
  outputUrl: (id: string, tid: string, from = 0) => `${BASE}/${t(id, tid)}/output${from > 0 ? '?from=' + from : ''}`,
}

/** The tsh command for a downloaded identity file. */
export function tshCommand(file: string, proxy: string, login?: string, host?: string): string {
  const target = login && host ? ` ssh ${login}@${host}` : ' ls'
  return `tsh -i ${file} --proxy=${proxy}${target}`
}
