import { api } from '@/api/client'
import type { CreateLink, CreateToken, JoinToken, ResourceLink, ResourcePage, TokenCreated } from '@/api/types'

// Join tokens and the resource inventory of one cluster (US3). A created
// token, its install command and config snippet are returned once to the
// caller and must not be stored: they live only in the enrol dialog until it
// closes.
const c = (id: string) => 'clusters/' + id

export const tokensApi = {
  list: (id: string) => api<{ items: JoinToken[] }>('GET', c(id) + '/tokens'),
  create: (id: string, body: CreateToken) => api<TokenCreated>('POST', c(id) + '/tokens', body),
  revoke: (id: string, tid: string) => api('DELETE', c(id) + '/tokens/' + encodeURIComponent(tid)),
}

export interface ResourceQuery {
  kind?: string
  label?: string
  q?: string
  status?: string
  next?: string
  page_size?: number
}

export const resourcesApi = {
  list: (id: string, query: ResourceQuery = {}) => api<ResourcePage>('GET', c(id) + '/resources', undefined, { query }),
  link: (id: string, rid: string, body: CreateLink) => api<ResourceLink>('POST', c(id) + '/resources/' + encodeURIComponent(rid) + '/links', body),
  unlink: (id: string, rid: string, lid: string) =>
    api('DELETE', c(id) + '/resources/' + encodeURIComponent(rid) + '/links/' + encodeURIComponent(lid)),
}
