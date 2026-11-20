import type { Cluster, ClusterStatus } from '@/api/types'

export const STATUS_LABELS: Record<ClusterStatus, string> = {
  connected: 'Connected',
  unreachable: 'Unreachable',
  credential_expiring: 'Credential expiring',
  credential_invalid: 'Credential invalid',
  unsupported_version: 'Unsupported version',
}

export const STATUS_COLORS = {
  connected: 'success',
  unreachable: 'error',
  credential_expiring: 'warning',
  credential_invalid: 'error',
  unsupported_version: 'warning',
} as const

export function formatTime(iso?: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString()
}

/** "in 12 days" / "expired" for a credential expiry. */
export function expiryText(c: Cluster, now = Date.now()): string {
  if (!c.credential_expires_at) return '—'
  const ms = new Date(c.credential_expires_at).getTime() - now
  if (ms <= 0) return 'expired'
  const days = Math.floor(ms / 86_400_000)
  if (days >= 1) return `in ${days} day${days === 1 ? '' : 's'}`
  const hours = Math.max(1, Math.floor(ms / 3_600_000))
  return `in ${hours} hour${hours === 1 ? '' : 's'}`
}

export const resourceCount = (c: Cluster) => c.counts.nodes + c.counts.apps + c.counts.dbs + c.counts.kube + c.counts.desktops

/** Reads an uploaded identity file as text (bounded by the schema's 64 KiB). */
export function readText(f: File): Promise<string> {
  return f.text()
}
