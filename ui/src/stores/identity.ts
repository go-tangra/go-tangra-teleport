import { api } from '@/api/client'
import type {
  CreateLock, CreateUser, CursorPage, ResetLink, RoleDefinition, RolePreview, TeleportLock, TeleportRole, TeleportUser, UpdateUser, UserCreated,
} from '@/api/types'

// Users, roles and locks of one cluster (US2). Lists are read live from
// Teleport; nothing is kept here between views. Invite and reset links are
// returned to the caller once and must not be stored (they live only in the
// component that shows them, until its dialog closes).
const c = (id: string) => 'clusters/' + id

export const usersApi = {
  list: (id: string, query: { q?: string; next?: string } = {}) => api<CursorPage<TeleportUser>>('GET', c(id) + '/users', undefined, { query }),
  create: (id: string, body: CreateUser) => api<UserCreated>('POST', c(id) + '/users', body),
  update: (id: string, name: string, body: UpdateUser) => api<TeleportUser>('PUT', c(id) + '/users/' + encodeURIComponent(name), body),
  reset: (id: string, name: string) => api<ResetLink>('POST', c(id) + '/users/' + encodeURIComponent(name) + '/reset'),
  remove: (id: string, name: string) => api('DELETE', c(id) + '/users/' + encodeURIComponent(name)),
}

export const rolesApi = {
  list: (id: string, query: { next?: string } = {}) => api<CursorPage<TeleportRole>>('GET', c(id) + '/roles', undefined, { query }),
  get: (id: string, name: string) => api<RoleDefinition>('GET', c(id) + '/roles/' + encodeURIComponent(name)),
  /** Validation and diff only; nothing changes. */
  preview: (id: string, yaml: string, revision?: string) => api<RolePreview>('POST', c(id) + '/roles:preview', { yaml, revision }),
  /** An empty revision creates the role. */
  put: (id: string, name: string, yaml: string, revision?: string) => api<TeleportRole>('PUT', c(id) + '/roles/' + encodeURIComponent(name), { yaml, revision }),
  remove: (id: string, name: string) => api('DELETE', c(id) + '/roles/' + encodeURIComponent(name)),
}

export const locksApi = {
  list: (id: string) => api<CursorPage<TeleportLock>>('GET', c(id) + '/locks'),
  create: (id: string, body: CreateLock) => api<TeleportLock>('POST', c(id) + '/locks', body),
  remove: (id: string, name: string) => api('DELETE', c(id) + '/locks/' + encodeURIComponent(name)),
}
