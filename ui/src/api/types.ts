// Response and request shapes of the cluster routes (api/openapi/teleport.yaml,
// components/schemas). `npm run gen:api` generates schema.d.ts from the same
// document; these names are what the views import.

export type ClusterStatus = 'connected' | 'unreachable' | 'credential_expiring' | 'credential_invalid' | 'unsupported_version'
export type Edition = 'community' | 'enterprise' | 'unknown'

export interface Counts {
  users: number
  roles: number
  nodes: number
  apps: number
  dbs: number
  kube: number
  desktops: number
}

export interface ClusterSettings {
  offline_threshold_minutes: number
  alerts_enabled: boolean
}

/** A registered cluster. The credential itself is never returned. */
export interface Cluster {
  id: string
  display_name: string
  proxy_addr: string
  cluster_name: string
  edition: Edition
  server_version: string
  credential_kind: 'identity_file'
  credential_identity: string
  credential_expires_at?: string | undefined
  status: ClusterStatus
  status_reason: string
  missing_permissions: string[]
  last_contact_at?: string | undefined
  counts: Counts
  settings: ClusterSettings
  writes_blocked: boolean
  created_by: string
  created_at: string
  updated_at: string
}

export interface Page<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  sort: string
  order: 'asc' | 'desc'
}

export interface RegisterCluster {
  display_name: string
  proxy_addr: string
  credential_kind?: 'identity_file' | undefined
  credential: string
}

export interface RotateCredential {
  credential_kind?: 'identity_file' | undefined
  credential: string
}

export interface UpdateCluster {
  display_name?: string | undefined
  settings?: Partial<ClusterSettings> | undefined
}

// ---- Users, roles and locks (US2)

/** A Teleport user. `revision` goes back with an update (409 when stale). */
export interface TeleportUser {
  name: string
  roles: string[]
  logins: string[]
  created?: string | undefined
  managed: boolean
  tangra_user_id?: string | undefined
  locked: boolean
  revision: string
}

/** Teleport-backed lists page with an opaque cursor. */
export interface CursorPage<T> {
  items: T[]
  next?: string | undefined
}

export interface CreateUser {
  name: string
  roles: string[]
  logins?: string[] | undefined
}

export interface UpdateUser {
  roles: string[]
  logins?: string[] | undefined
  revision: string
}

/** The create result: invite_url is shown once and never again. */
export interface UserCreated {
  user: TeleportUser
  invite_url: string
  invite_expires_at: string
}

/** The reset result: reset_url is shown once and never again. */
export interface ResetLink {
  reset_url: string
  expires_at: string
}

export interface TeleportRole {
  name: string
  preset: boolean
  revision: string
}

export interface RoleDefinition {
  yaml: string
  revision: string
  preset: boolean
}

export interface RolePreview {
  valid: boolean
  errors: string[]
  diff: string
}

export type LockTargetKind = 'user' | 'role' | 'server_id'

export type TeleportLock = {
  name: string
  target_kind: LockTargetKind
  target: { user?: string; role?: string; server_id?: string }
  message: string
  created_by: string
  expires_at?: string | undefined
}

export interface CreateLock {
  target_kind: LockTargetKind
  target: string
  reason: string
  expires_at?: string | undefined
}

// ---- US3: join tokens and resources

export type ResourceKind = 'node' | 'app' | 'db' | 'kube' | 'desktop'

export interface CreateToken {
  resource_type: ResourceKind
  ttl_minutes?: number | undefined
}

/** The token, command and snippet are one-time: shown once, never stored. */
export interface TokenCreated {
  id: string
  resource_type: ResourceKind
  token: string
  expires_at: string
  install_command: string
  config_snippet: string
}

export interface JoinToken {
  id: string
  resource_type: ResourceKind
  created_by: string
  created_at: string
  expires_at: string
  expired: boolean
  revoked: boolean
  revoked_at?: string | undefined
}

export type LinkMatch = 'auto' | 'candidate' | 'confirmed'

export interface ResourceLink {
  id: string
  target_module: 'inventory' | 'asset'
  target_id: string
  match: LinkMatch
  matched_on: 'hostname' | 'ip'
  created_at: string
}

export type ResourceStatus = 'online' | 'offline' | 'flagged'

export interface TeleportResource {
  id: string
  kind: ResourceKind
  name: string
  hostname?: string | undefined
  addr?: string | undefined
  labels: Record<string, string>
  agent_version: string
  status: ResourceStatus
  last_seen_at?: string | undefined
  offline_since?: string | undefined
  flagged_at?: string | undefined
  links: ResourceLink[]
}

export interface ResourcePage {
  items: TeleportResource[]
  next?: string | undefined
  link_status: 'ok' | 'dependency_unavailable'
}

export interface CreateLink {
  target_module: 'inventory' | 'asset'
  target_id: string
}

// ---- Audit and alerts (US4)

/** Allow-listed normalized Teleport event types (components/schemas/EventType). */
export const EVENT_TYPES = [
  'access_request.create', 'access_request.review', 'app.session.start', 'cert.create', 'db.session.start', 'exec',
  'lock.created', 'lock.deleted', 'reset_password_token.create', 'role.created', 'role.deleted', 'role.updated',
  'session.end', 'session.join', 'session.leave', 'session.start', 'user.create', 'user.delete', 'user.login',
  'user.login.failure', 'user.password_change', 'user.update', 'windows.desktop.session.start',
] as const
export type EventType = (typeof EVENT_TYPES)[number]

/**
 * A normalized Teleport audit event. user, resource, summary and raw are
 * Teleport-supplied: render them as text only (never v-html).
 */
export interface AuditEvent {
  id: string
  time: string
  type: string
  code: string
  user: string
  resource: string
  success: boolean
  summary: string
  raw: Record<string, unknown>
}

export type SessionKind = 'ssh' | 'kube' | 'db' | 'app' | 'desktop'

export interface TeleportSession {
  sid: string
  participants: string[]
  user: string
  target: string
  kind: SessionKind
  started_at: string
  duration_s: number
  playback_url?: string | undefined
}

export interface AuditRecord {
  id: string
  time: string
  actor_kind: 'user' | 'module' | 'worker' | 'system'
  actor_id: string
  cluster_id?: string | undefined
  action: string
  target_kind: string
  target_name: string
  outcome: 'success' | 'failure' | 'unknown'
  reason?: string | undefined
  correlation_id?: string | undefined
  detail: Record<string, unknown>
}

export type ConditionKind = 'teleport_event' | 'cluster_unreachable' | 'credential_expiring' | 'resource_offline'

export interface Recipients {
  user_ids: string[]
  channel_ids?: string[] | undefined
}

export interface AlertRuleInput {
  cluster_id?: string | undefined
  name: string
  condition_kind: ConditionKind
  event_types?: EventType[] | undefined
  threshold_count?: number | undefined
  window_minutes?: number | undefined
  recipients: Recipients
  enabled?: boolean | undefined
}

export interface AlertRule {
  id: string
  cluster_id?: string | undefined
  name: string
  condition_kind: ConditionKind
  event_types: string[]
  threshold_count: number
  window_minutes: number
  recipients: Required<Recipients>
  enabled: boolean
  created_by: string
  created_at: string
  updated_at: string
}

// ---- Provisioning (US5)

export type SubjectKind = 'module_role' | 'group'
export type ManagedState = 'provisioning' | 'active' | 'locked_pending_deletion' | 'error'

export interface RoleMappingInput {
  subject_kind: SubjectKind
  subject_ref: string
  teleport_roles: string[]
  logins?: string[] | undefined
}

export interface RoleMappingUpdate {
  teleport_roles: string[]
  logins?: string[] | undefined
}

export interface RoleMapping {
  id: string
  cluster_id: string
  subject_kind: SubjectKind
  subject_ref: string
  teleport_roles: string[]
  logins: string[]
  created_by: string
  created_at: string
  updated_at: string
}

/** A Teleport user tangra provisioned. The invite link is never returned. */
export interface ManagedUser {
  id: string
  tangra_user_id: string
  teleport_username: string
  state: ManagedState
  applied_roles: string[]
  applied_logins: string[]
  locked: boolean
  deprovision_after?: string | undefined
  last_synced_at?: string | undefined
  created_at: string
}

export interface ProvisioningSummary {
  created: number
  updated: number
  locked: number
  unlocked: number
  deleted: number
  errors: number
}

// ---- Deployment wizard (US6)

export type CertMode = 'acme' | 'own_cert'
export type ArtifactName = 'teleport.yaml' | 'install.sh' | 'tangra-manager-role.yaml' | 'setup-commands.txt' | 'checklist.md'

export interface DraftInput {
  domain: string
  cert_mode: CertMode
  acme_email?: string | undefined
  teleport_version: string
  admin_username: string
  admin_logins: string[]
  registered_cluster_id?: string | undefined
}

export interface DraftCheck {
  name: 'dns_apex' | 'dns_wildcard' | 'tls_443'
  ok: boolean
  detail: string
  checked_at: string
}

export interface Draft extends Omit<DraftInput, 'registered_cluster_id'> {
  id: string
  checks: DraftCheck[]
  registered_cluster_id?: string | undefined
  /** The address the registration dialog is filled with. */
  proxy_addr: string
  artifacts: ArtifactName[]
  created_by: string
  created_at: string
  updated_at: string
}
