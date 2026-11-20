import { api, BASE } from '@/api/client'
import type { ArtifactName, Draft, DraftInput } from '@/api/types'

// Deployment-wizard drafts (US6). Artifacts are rendered by the server on
// every download and never stored.
export const deploymentsApi = {
  list: () => api<{ items: Draft[] }>('GET', 'deployments'),
  get: (id: string) => api<Draft>('GET', 'deployments/' + encodeURIComponent(id)),
  create: (body: DraftInput) => api<Draft>('POST', 'deployments', body),
  update: (id: string, body: DraftInput) => api<Draft>('PUT', 'deployments/' + encodeURIComponent(id), body),
  remove: (id: string) => api('DELETE', 'deployments/' + encodeURIComponent(id)),
  /** At most once per 10 s per draft (429 rate_limited otherwise). */
  check: (id: string) => api<Draft>('POST', 'deployments/' + encodeURIComponent(id) + '/checks'),
  /** Same-origin URL of an artifact (a text/plain attachment). */
  artifactUrl: (id: string, name: ArtifactName) => `${BASE}/deployments/${encodeURIComponent(id)}/artifacts/${encodeURIComponent(name)}`,
}
