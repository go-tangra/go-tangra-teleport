import { api } from '@/api/client'
import type {
  CreateEnrollments, CreateLink, CreateToken, Enrollment, EnrollmentPage, EnrollmentsCreated, EnrollmentTargets, JoinToken, ResourceLink,
  ResourcePage, TokenCreated,
} from '@/api/types'

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

export type ResourceQuery = {
  kind?: string | undefined
  label?: string | undefined
  q?: string | undefined
  status?: string | undefined
  next?: string | undefined
  page_size?: number | undefined
}

export const resourcesApi = {
  list: (id: string, query: ResourceQuery = {}) => api<ResourcePage>('GET', c(id) + '/resources', undefined, { query }),
  link: (id: string, rid: string, body: CreateLink) => api<ResourceLink>('POST', c(id) + '/resources/' + encodeURIComponent(rid) + '/links', body),
  unlink: (id: string, rid: string, lid: string) =>
    api('DELETE', c(id) + '/resources/' + encodeURIComponent(rid) + '/links/' + encodeURIComponent(lid)),
}

// Enrollment of inventory hosts through their agent (spec 002): no token
// ever reaches the browser, the agent fetches its own when it runs.
export const enrollmentsApi = {
  targets: (id: string, query: { q?: string | undefined; limit?: number | undefined } = {}) =>
    api<EnrollmentTargets>('GET', c(id) + '/enrollment-targets', undefined, { query }),
  list: (id: string) => api<EnrollmentPage>('GET', c(id) + '/enrollments'),
  create: (id: string, body: CreateEnrollments) => api<EnrollmentsCreated>('POST', c(id) + '/enrollments', body),
  cancel: (id: string, eid: string) => api<Enrollment>('POST', c(id) + '/enrollments/' + encodeURIComponent(eid) + '/cancel'),
  retry: (id: string, eid: string) => api<Enrollment>('POST', c(id) + '/enrollments/' + encodeURIComponent(eid) + '/retry'),
}
