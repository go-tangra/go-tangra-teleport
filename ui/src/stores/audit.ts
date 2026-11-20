import { api } from '@/api/client'
import type { AlertRule, AlertRuleInput, AuditEvent, AuditRecord, CursorPage, Page, TeleportSession } from '@/api/types'

// Teleport events and sessions of one cluster, the module audit trail and
// alert rules (US4). Searches are live: the window (from/to, at most 31
// days) is required, `next` is Teleport's opaque cursor and is passed back
// unchanged with the same window and filters.
const c = (id: string) => 'clusters/' + id

/** The maximum search window (contracts/http-api.md). */
export const MAX_WINDOW_MS = 31 * 86_400_000

export type EventQuery = {
  from: string
  to: string
  /** One event type (the API also takes the parameter repeated). */
  types?: string | undefined
  user?: string | undefined
  resource?: string | undefined
  limit?: number | undefined
  next?: string | undefined
}

export type SessionQuery = {
  from: string
  to: string
  limit?: number | undefined
  next?: string | undefined
}

export type TrailQuery = {
  page?: number | undefined
  page_size?: number | undefined
  order?: 'asc' | 'desc' | undefined
  cluster_id?: string | undefined
  action?: string | undefined
  outcome?: string | undefined
  from?: string | undefined
  to?: string | undefined
}

export const auditApi = {
  events: (id: string, query: EventQuery) => api<CursorPage<AuditEvent>>('GET', c(id) + '/events', undefined, { query }),
  sessions: (id: string, query: SessionQuery) => api<CursorPage<TeleportSession>>('GET', c(id) + '/sessions', undefined, { query }),
  trail: (query: TrailQuery = {}) => api<Page<AuditRecord>>('GET', 'audit', undefined, { query }),
}

export const alertRulesApi = {
  list: () => api<{ items: AlertRule[] }>('GET', 'alert-rules'),
  create: (body: AlertRuleInput) => api<AlertRule>('POST', 'alert-rules', body),
  update: (id: string, body: AlertRuleInput) => api<AlertRule>('PUT', 'alert-rules/' + encodeURIComponent(id), body),
  remove: (id: string) => api('DELETE', 'alert-rules/' + encodeURIComponent(id)),
}

/** A preset window ending now, as RFC 3339 strings. */
export function lastWindow(ms: number, now = Date.now()): { from: string; to: string } {
  return { from: new Date(now - ms).toISOString(), to: new Date(now).toISOString() }
}

/** datetime-local input value → RFC 3339 ('' when empty or invalid). */
export function fromLocalInput(v: string): string {
  if (!v) return ''
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? '' : d.toISOString()
}

/** "1 h 2 min" / "45 s" for a session duration. */
export function durationText(s: number): string {
  if (s < 60) return `${s} s`
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  return h > 0 ? `${h} h ${m} min` : `${m} min`
}
