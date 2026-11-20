import { api } from '@/api/client'
import type { ManagedUser, ProvisioningSummary, RoleMapping, RoleMappingInput, RoleMappingUpdate } from '@/api/types'

// Role mappings, managed users and "sync now" of one cluster (US5). Invites
// go to the tangra user through notification; no response carries them.
const c = (id: string) => 'clusters/' + id

export const mappingsApi = {
  list: (id: string) => api<{ items: RoleMapping[] }>('GET', c(id) + '/mappings'),
  create: (id: string, body: RoleMappingInput) => api<RoleMapping>('POST', c(id) + '/mappings', body),
  update: (id: string, mid: string, body: RoleMappingUpdate) => api<RoleMapping>('PUT', c(id) + '/mappings/' + encodeURIComponent(mid), body),
  remove: (id: string, mid: string) => api('DELETE', c(id) + '/mappings/' + encodeURIComponent(mid)),
}

export const managedApi = {
  list: (id: string) => api<{ items: ManagedUser[] }>('GET', c(id) + '/managed-users'),
  provision: (id: string, tangraUserId: string) => api<ManagedUser>('POST', c(id) + '/managed-users', { tangra_user_id: tangraUserId }),
  sync: (id: string) => api<ProvisioningSummary>('POST', c(id) + '/provisioning:sync'),
}
