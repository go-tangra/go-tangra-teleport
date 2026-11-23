<script setup lang="ts">
// Enrolled resources of one cluster: online ones live from Teleport,
// offline and flagged ones from their last-known state, with their
// inventory/asset links. Candidates can be confirmed, links added by hand
// or removed (resources:link). When the inventory/asset lookup is down the
// list says so; manual links still work.
import { computed, inject, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ABILITY_TOKEN } from '@casl/vue'
import type { AnyAbility } from '@casl/ability'
import { UiAlert, UiBadge, UiButton, UiCard, UiDataTable, UiDialog, UiInput, UiSelect, useConfirm, type Column } from '@go-tangra/ui'
import { explain } from '@/api/client'
import { enrollmentsApi, resourcesApi, type ResourceQuery } from '@/stores/resources'
import { accessApi } from '@/stores/access'
import type { Cluster, Enrollment, EnrollmentState, ResourceLink, ResourcePage, TeleportResource } from '@/api/types'
import { formatTime } from '../status'
import EnrollDialog from '@/components/EnrollDialog.vue'
import InventoryEnrollDialog from '@/components/InventoryEnrollDialog.vue'

const props = defineProps<{ cluster: Cluster }>()
const ability = inject<AnyAbility | null>(ABILITY_TOKEN, null)
const canLink = computed(() => (ability ? ability.can('link', 'TeleportResource') : true))
const canEnroll = computed(() => (ability ? ability.can('manage', 'TeleportToken') : true) && !props.cluster.writes_blocked)
const confirm = useConfirm()
const router = useRouter()

// Spec 004: a terminal on a node as the caller's own Teleport user
// (access:terminal). The logins offered are the user's; Teleport decides.
const canTerminal = computed(() => (ability ? ability.can('terminal', 'TeleportAccess') : true))
const terminalFor = ref<TeleportResource | null>(null)
const terminalLogins = ref<string[]>([])
const terminalLogin = ref('')
const terminalError = ref('')
const terminalLoading = ref(false)
async function openTerminal(r: TeleportResource): Promise<void> {
  terminalFor.value = r
  terminalError.value = ''
  terminalLogins.value = []
  terminalLoading.value = true
  try {
    const nodes = await accessApi.nodes(props.cluster.id)
    const n = nodes.items.find((x) => x.name === r.name)
    if (!n) terminalError.value = 'Your Teleport user cannot reach this node.'
    else terminalLogins.value = n.logins
    terminalLogin.value = terminalLogins.value[0] ?? ''
    if (n && !n.logins.length) terminalError.value = 'Your Teleport user holds no login.'
  } catch (e) {
    terminalError.value = explain(e)
  } finally {
    terminalLoading.value = false
  }
}
function startTerminal(): void {
  const r = terminalFor.value
  if (!r || !terminalLogin.value) return
  const href = router.resolve({ name: 'teleport-terminal', params: { id: props.cluster.id }, query: { node: r.name, login: terminalLogin.value, host: r.hostname || r.name } }).href
  window.open(href, '_blank', 'noopener')
  terminalFor.value = null
}

const filter = ref<ResourceQuery>({})
const items = ref<TeleportResource[]>([])
const next = ref<string | undefined>()
const linkStatus = ref<ResourcePage['link_status']>('ok')
const loading = ref(false)
const error = ref('')
const notice = ref('')
const enrolling = ref(false)
const enrollingInventory = ref(false)
const canEnrollInventory = computed(() => (ability ? ability.can('enroll', 'TeleportResource') : true) && !props.cluster.writes_blocked)

// Spec 002: enrollments through the inventory agent.
const enrollments = ref<Enrollment[]>([])
const enrollmentsStale = ref(false)
const ACTIVE: EnrollmentState[] = ['pending', 'delivered', 'fetched', 'installing']
const RETRYABLE: EnrollmentState[] = ['failed', 'unsupported', 'expired', 'superseded', 'cancelled']
const ENROLL_COLORS: Record<EnrollmentState, 'success' | 'warning' | 'error' | 'info' | 'neutral'> = {
  pending: 'neutral', delivered: 'info', fetched: 'info', installing: 'info', joined: 'success',
  failed: 'error', unsupported: 'warning', superseded: 'neutral', expired: 'warning', cancelled: 'neutral',
}
async function loadEnrollments(): Promise<void> {
  try {
    const p = await enrollmentsApi.list(props.cluster.id)
    enrollments.value = p.items
    enrollmentsStale.value = p.stale
  } catch (e) {
    error.value = explain(e)
  }
}
async function cancelEnrollment(x: Enrollment): Promise<void> {
  const ok = await confirm.ask({ title: 'Cancel this enrollment?', text: `${x.hostname || x.host_id} will not join.`, confirmLabel: 'Cancel enrollment', danger: true })
  if (!ok) return
  try {
    await enrollmentsApi.cancel(props.cluster.id, x.id)
    notice.value = 'Enrollment cancelled.'
    void loadEnrollments()
  } catch (e) {
    error.value = explain(e)
  }
}
async function retryEnrollment(x: Enrollment): Promise<void> {
  try {
    await enrollmentsApi.retry(props.cluster.id, x.id)
    notice.value = 'Enrollment restarted.'
    void loadEnrollments()
  } catch (e) {
    error.value = explain(e)
  }
}

async function load(more = false): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const p = await resourcesApi.list(props.cluster.id, { ...filter.value, next: more ? next.value : undefined, page_size: 100 })
    items.value = more ? [...items.value, ...p.items] : p.items
    next.value = p.next
    linkStatus.value = p.link_status
  } catch (e) {
    error.value = explain(e)
  } finally {
    loading.value = false
  }
}
onMounted(() => {
  void load()
  void loadEnrollments()
})

const STATUS_COLORS = { online: 'success', offline: 'warning', flagged: 'error' } as const
const kinds = [
  { title: 'All types', value: '' },
  { title: 'Servers', value: 'node' },
  { title: 'Applications', value: 'app' },
  { title: 'Databases', value: 'db' },
  { title: 'Kubernetes', value: 'kube' },
  { title: 'Desktops', value: 'desktop' },
]
const statuses = [
  { title: 'Any status', value: '' },
  { title: 'Online', value: 'online' },
  { title: 'Offline', value: 'offline' },
  { title: 'Flagged', value: 'flagged' },
]
const columns: Column<TeleportResource>[] = [
  { key: 'name', label: 'Name' },
  { key: 'kind', label: 'Type', width: 'sm' },
  { key: 'status', label: 'Status', width: 'sm' },
  { key: 'hostname', label: 'Host', hideOnStack: true, format: (r) => r.hostname || r.addr || '—' },
  { key: 'agent_version', label: 'Agent', width: 'sm', hideOnStack: true },
  { key: 'last_seen_at', label: 'Last seen', width: 'md', format: (r) => (r.last_seen_at ? formatTime(r.last_seen_at) : '—') },
  { key: 'links', label: 'Links' },
]

const linking = ref<TeleportResource | null>(null)
const linkModule = ref<'inventory' | 'asset'>('inventory')
const linkTarget = ref('')
function openLink(r: TeleportResource): void {
  linking.value = r
  linkModule.value = 'inventory'
  linkTarget.value = ''
}
async function confirmLink(r: TeleportResource, l: Pick<ResourceLink, 'target_module' | 'target_id'>): Promise<void> {
  try {
    await resourcesApi.link(props.cluster.id, r.id, { target_module: l.target_module, target_id: l.target_id })
    notice.value = 'Link confirmed.'
    linking.value = null
    void load()
  } catch (e) {
    error.value = explain(e)
  }
}
async function unlink(r: TeleportResource, l: ResourceLink): Promise<void> {
  const ok = await confirm.ask({ title: 'Remove this link?', text: `${r.name} is no longer linked to ${l.target_module} ${l.target_id}.`, confirmLabel: 'Remove', danger: true })
  if (!ok) return
  try {
    await resourcesApi.unlink(props.cluster.id, r.id, l.id)
    notice.value = 'Link removed.'
    void load()
  } catch (e) {
    error.value = explain(e)
  }
}
</script>

<template>
  <div class="flex flex-col gap-4" data-test="resources-tab">
    <UiAlert v-if="error" kind="error" data-test="resources-error">{{ error }}</UiAlert>
    <UiAlert v-if="notice" kind="success" dismissible @close="notice = ''">{{ notice }}</UiAlert>
    <UiAlert v-if="linkStatus === 'dependency_unavailable'" kind="info" data-test="resources-link-unavailable">
      Automatic matching with inventory and assets is unavailable. Existing links stay and you can still link resources by hand.
    </UiAlert>
    <div class="flex flex-wrap items-end gap-2">
      <UiSelect id="resources-kind" v-model="filter.kind" label="Type" :options="kinds" class="w-44" data-test="resources-kind" @update:model-value="load()" />
      <UiSelect id="resources-status" v-model="filter.status" label="Status" :options="statuses" class="w-40" data-test="resources-status" @update:model-value="load()" />
      <UiInput id="resources-label" v-model="filter.label" label="Label (key=value)" class="w-48" data-test="resources-label" @keyup.enter="load()" />
      <UiInput id="resources-q" v-model="filter.q" label="Search" class="w-48" data-test="resources-q" @keyup.enter="load()" />
      <div class="grow" />
      <UiButton v-if="canEnrollInventory" variant="outline" icon="mdi-plus-box-outline" data-test="resources-enroll-inventory" @click="enrollingInventory = true">
        Enroll inventory hosts
      </UiButton>
      <UiButton v-if="canEnroll" color="primary" icon="mdi-plus" data-test="resources-enroll" @click="enrolling = true">Enroll</UiButton>
    </div>
    <UiCard :padded="false">
      <UiDataTable :items="items" :columns="columns" row-key="id" :loading="loading" caption="Resources" empty-title="No enrolled resources" data-test="resources-table">
        <template #cell-status="{ row }">
          <UiBadge :color="STATUS_COLORS[row.status]">{{ row.status }}</UiBadge>
        </template>
        <template #cell-links="{ row }">
          <div class="flex flex-wrap items-center gap-1">
            <template v-for="l in row.links" :key="l.id">
              <UiBadge :color="l.match === 'candidate' ? 'warning' : 'info'" :data-test="'link-' + l.id">
                {{ l.target_module }}: {{ l.target_id }}{{ l.match === 'candidate' ? ' (candidate)' : '' }}
              </UiBadge>
              <UiButton v-if="canLink && l.match === 'candidate'" size="sm" variant="text" icon="mdi-check" icon-only label="Confirm link" @click="confirmLink(row, l)" />
              <UiButton v-if="canLink" size="sm" variant="text" icon="mdi-cancel" icon-only label="Remove link" @click="unlink(row, l)" />
            </template>
            <UiButton v-if="canLink" size="sm" variant="text" icon="mdi-link-variant" icon-only label="Link" :data-test="'resource-link-' + row.id" @click="openLink(row)" />
            <UiButton
              v-if="canTerminal && row.kind === 'node' && row.status === 'online'"
              size="sm"
              variant="text"
              icon="mdi-console"
              icon-only
              label="Terminal"
              :data-test="'resource-terminal-' + row.id"
              @click="openTerminal(row)"
            />
          </div>
        </template>
      </UiDataTable>
    </UiCard>
    <div v-if="next" class="flex justify-center">
      <UiButton variant="text" :loading="loading" data-test="resources-more" @click="load(true)">Load more</UiButton>
    </div>

    <UiCard v-if="enrollments.length" title="Inventory enrollments" data-test="enrollments">
      <UiAlert v-if="enrollmentsStale" kind="info" class="mb-2">Inventory is unavailable: these are the last known states.</UiAlert>
      <ul class="flex flex-col gap-2">
        <li v-for="x in enrollments" :key="x.id" class="flex flex-wrap items-center gap-2" :data-test="'enrollment-' + x.id">
          <span class="font-medium">{{ x.hostname || x.host_id }}</span>
          <UiBadge :color="ENROLL_COLORS[x.state]">{{ x.state }}</UiBadge>
          <span v-if="x.reason" class="text-xs opacity-70">{{ x.reason }}</span>
          <span class="text-xs opacity-70">updated {{ formatTime(x.updated_at) }}</span>
          <div class="grow" />
          <UiButton v-if="canEnrollInventory && ACTIVE.includes(x.state)" size="sm" variant="text" icon="mdi-close" @click="cancelEnrollment(x)">Cancel</UiButton>
          <UiButton v-if="canEnrollInventory && RETRYABLE.includes(x.state)" size="sm" variant="text" icon="mdi-refresh" @click="retryEnrollment(x)">Retry</UiButton>
        </li>
      </ul>
    </UiCard>

    <UiDialog :model-value="linking !== null" title="Link resource" data-test="resource-link-dialog" @update:model-value="(v: boolean) => { if (!v) linking = null }">
      <div class="flex flex-col gap-4">
        <UiSelect id="resourcestab-module" v-model="linkModule" label="Module" :options="[{ title: 'Inventory', value: 'inventory' }, { title: 'Asset', value: 'asset' }]" :clearable="false" />
        <UiInput id="resource-link-target" v-model="linkTarget" label="Record ID" required data-test="resource-link-target" />
      </div>
      <template #actions>
        <UiButton variant="text" @click="linking = null">Cancel</UiButton>
        <UiButton color="primary" :disabled="!linkTarget" data-test="resource-link-save" @click="linking && confirmLink(linking, { target_module: linkModule, target_id: linkTarget })">Link</UiButton>
      </template>
    </UiDialog>
    <UiDialog :model-value="terminalFor !== null" title="Open a terminal" data-test="resource-terminal-dialog" @update:model-value="(v: boolean) => { if (!v) terminalFor = null }">
      <div class="flex flex-col gap-4">
        <p v-if="terminalFor" class="text-sm">On <span class="font-mono">{{ terminalFor.hostname || terminalFor.name }}</span> as your own Teleport user. The session is recorded by Teleport.</p>
        <UiAlert v-if="terminalError" kind="error" data-test="resource-terminal-error">{{ terminalError }}</UiAlert>
        <UiSelect
          v-if="terminalLogins.length"
          id="resource-terminal-login"
          :model-value="terminalLogin"
          label="Login"
          :options="terminalLogins.map((l) => ({ title: l, value: l }))"
          :clearable="false"
          data-test="resource-terminal-login"
          @update:model-value="(v: unknown) => (terminalLogin = String(v ?? ''))"
        />
      </div>
      <template #actions>
        <UiButton variant="text" @click="terminalFor = null">Cancel</UiButton>
        <UiButton color="primary" icon="mdi-console" :loading="terminalLoading" :disabled="!terminalLogin" data-test="resource-terminal-open" @click="startTerminal()">Open</UiButton>
      </template>
    </UiDialog>
    <EnrollDialog v-model="enrolling" :cluster="cluster" @issued="load()" />
    <InventoryEnrollDialog v-model="enrollingInventory" :cluster="cluster" @created="loadEnrollments()" />
  </div>
</template>
