<script setup lang="ts">
// Enrolled resources of one cluster: online ones live from Teleport,
// offline and flagged ones from their last-known state, with their
// inventory/asset links. Candidates can be confirmed, links added by hand
// or removed (resources:link). When the inventory/asset lookup is down the
// list says so; manual links still work.
import { computed, inject, onMounted, ref } from 'vue'
import { ABILITY_TOKEN } from '@casl/vue'
import type { AnyAbility } from '@casl/ability'
import { UiAlert, UiBadge, UiButton, UiCard, UiDataTable, UiDialog, UiInput, UiSelect, UiStatusChip, useConfirm, type Column } from '@go-tangra/ui'
import { explain } from '@/api/client'
import { resourcesApi, type ResourceQuery } from '@/stores/resources'
import type { Cluster, ResourceLink, ResourcePage, TeleportResource } from '@/api/types'
import { formatTime } from '../status'
import EnrollDialog from '@/components/EnrollDialog.vue'

const props = defineProps<{ cluster: Cluster }>()
const ability = inject<AnyAbility | null>(ABILITY_TOKEN, null)
const canLink = computed(() => (ability ? ability.can('link', 'TeleportResource') : true))
const canEnroll = computed(() => (ability ? ability.can('manage', 'TeleportToken') : true) && !props.cluster.writes_blocked)
const confirm = useConfirm()

const filter = ref<ResourceQuery>({})
const items = ref<TeleportResource[]>([])
const next = ref<string | undefined>()
const linkStatus = ref<ResourcePage['link_status']>('ok')
const loading = ref(false)
const error = ref('')
const notice = ref('')
const enrolling = ref(false)

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
onMounted(() => void load())

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
      <UiSelect v-model="filter.kind" label="Type" :options="kinds" class="w-44" data-test="resources-kind" @update:model-value="load()" />
      <UiSelect v-model="filter.status" label="Status" :options="statuses" class="w-40" data-test="resources-status" @update:model-value="load()" />
      <UiInput v-model="filter.label" label="Label (key=value)" class="w-48" data-test="resources-label" @keyup.enter="load()" />
      <UiInput v-model="filter.q" label="Search" class="w-48" data-test="resources-q" @keyup.enter="load()" />
      <div class="grow" />
      <UiButton v-if="canEnroll" color="primary" icon="mdi-plus" data-test="resources-enroll" @click="enrolling = true">Enroll</UiButton>
    </div>
    <UiCard :padded="false">
      <UiDataTable :items="items" :columns="columns" row-key="id" :loading="loading" caption="Resources" empty-title="No enrolled resources" data-test="resources-table">
        <template #cell-status="{ row }">
          <UiStatusChip :color="STATUS_COLORS[row.status]" :label="row.status" />
        </template>
        <template #cell-links="{ row }">
          <div class="flex flex-wrap items-center gap-1">
            <template v-for="l in row.links" :key="l.id">
              <UiBadge :color="l.match === 'candidate' ? 'warning' : 'info'" :data-test="'link-' + l.id">
                {{ l.target_module }}: {{ l.target_id }}{{ l.match === 'candidate' ? ' (candidate)' : '' }}
              </UiBadge>
              <UiButton v-if="canLink && l.match === 'candidate'" size="sm" variant="text" icon="mdi-check" icon-only label="Confirm link" @click="confirmLink(row, l)" />
              <UiButton v-if="canLink" size="sm" variant="text" icon="mdi-link-off" icon-only label="Remove link" @click="unlink(row, l)" />
            </template>
            <UiButton v-if="canLink" size="sm" variant="text" icon="mdi-link-plus" icon-only label="Link" :data-test="'resource-link-' + row.id" @click="openLink(row)" />
          </div>
        </template>
      </UiDataTable>
    </UiCard>
    <div v-if="next" class="flex justify-center">
      <UiButton variant="text" :loading="loading" data-test="resources-more" @click="load(true)">Load more</UiButton>
    </div>

    <UiDialog :model-value="linking !== null" title="Link resource" data-test="resource-link-dialog" @update:model-value="(v: boolean) => { if (!v) linking = null }">
      <div class="flex flex-col gap-4">
        <UiSelect v-model="linkModule" label="Module" :options="[{ title: 'Inventory', value: 'inventory' }, { title: 'Asset', value: 'asset' }]" :clearable="false" />
        <UiInput v-model="linkTarget" label="Record ID" required data-test="resource-link-target" />
      </div>
      <template #actions>
        <UiButton variant="text" @click="linking = null">Cancel</UiButton>
        <UiButton color="primary" :disabled="!linkTarget" data-test="resource-link-save" @click="linking && confirmLink(linking, { target_module: linkModule, target_id: linkTarget })">Link</UiButton>
      </template>
    </UiDialog>
    <EnrollDialog v-model="enrolling" :cluster="cluster" @issued="load()" />
  </div>
</template>
