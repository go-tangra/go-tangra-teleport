<script setup lang="ts">
// Clusters: a server-paged, sortable table of the tenant's Teleport clusters
// with status, version, edition, credential expiry and object counts.
// Selecting a row opens the overview; "Register cluster" opens the register
// dialog. The list refreshes when the module's event stream reports a
// cluster change.
import { computed, inject, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ABILITY_TOKEN } from '@casl/vue'
import type { AnyAbility } from '@casl/ability'
import { UiPage, UiAlert, UiCard, UiButton, UiBadge, UiDataTable, UiStatusChip, useListQuery, type Column } from '@go-tangra/ui'
import { BASE } from '@/api/client'
import { useClusters, CLUSTER_SORTABLE } from '@/stores/clusters'
import type { Cluster } from '@/api/types'
import RegisterClusterDialog from './RegisterClusterDialog.vue'
import { STATUS_COLORS, STATUS_LABELS, expiryText, resourceCount } from './status'

const store = useClusters()
const router = useRouter()
const ability = inject<AnyAbility | null>(ABILITY_TOKEN, null)
// Without an ability provider (standalone dev) the server stays the judge.
const canCreate = computed(() => (ability ? ability.can('create', 'TeleportCluster') : true))

const lq = useListQuery('clusters', { sortable: CLUSTER_SORTABLE, defaultSort: { key: 'display_name', dir: 'asc' } })
async function reload(): Promise<void> {
  const p = await store.list({ ...lq.query.value })
  if (p) lq.clampTo(p)
}
watch(lq.query, () => void reload())

// Live updates: the stream carries ids only; any cluster event refetches the page.
let events: EventSource | null = null
onMounted(() => {
  void reload()
  if (typeof EventSource === 'undefined') return
  events = new EventSource(BASE + '/stream', { withCredentials: true })
  for (const type of ['teleport.cluster.registered', 'teleport.cluster.updated', 'teleport.cluster.removed', 'teleport.cluster.status_changed', 'teleport.credential.rotated']) {
    events.addEventListener(type, () => void reload())
  }
})
onBeforeUnmount(() => events?.close())

const columns: Column<Cluster>[] = [
  { key: 'display_name', label: 'Cluster', sortable: true },
  { key: 'status', label: 'Status', width: 'md', sortable: true },
  { key: 'server_version', label: 'Version', width: 'sm', hideOnStack: true },
  { key: 'edition', label: 'Edition', width: 'sm', hideOnStack: true },
  { key: 'credential_expires_at', label: 'Credential expires', width: 'md', hideOnStack: true, format: (c) => expiryText(c) },
  { key: 'counts', label: 'Users / roles / resources', width: 'md', hideOnStack: true, format: (c) => `${c.counts.users} / ${c.counts.roles} / ${resourceCount(c)}` },
]

const registering = ref(false)
const open = (id: string) => void router.push({ name: 'teleport-cluster', params: { id } })
function onRegistered(c: Cluster): void {
  void reload()
  open(c.id)
}
</script>

<template>
  <UiPage title="Teleport clusters">
    <template #actions>
      <UiButton v-if="canCreate" icon="mdi-plus" data-test="cluster-new" @click="registering = true">Register cluster</UiButton>
      <UiButton variant="text" icon="mdi-refresh" icon-only label="Refresh" @click="reload" />
    </template>
    <UiAlert v-if="store.error" kind="error">{{ store.error }}</UiAlert>
    <UiCard :padded="false">
      <UiDataTable
        :items="store.items" :columns="columns" :loading="store.loading" :total="store.total" :page="lq.page.value" :page-size="lq.pageSize.value" :sort="lq.sort.value"
        caption="Teleport clusters — select one to see its health" empty-title="No clusters" empty-text="Register a Teleport cluster to manage it from the platform."
        clickable :row-attrs="(c) => ({ 'data-test': 'cluster-row-' + c.id })" data-test="clusters-table"
        @row-click="open($event.id)" @update:page="lq.setPage" @update:page-size="lq.setPageSize" @update:sort="lq.setSort"
      >
        <template #cell-display_name="{ row }">
          <div class="flex flex-col">
            <span class="font-medium">{{ row.display_name }}</span>
            <span class="text-base-content/70 font-mono text-xs">{{ row.cluster_name || row.proxy_addr }}</span>
          </div>
        </template>
        <template #cell-status="{ row }">
          <UiStatusChip :status="row.status" :label="STATUS_LABELS[row.status]" :colors="STATUS_COLORS" :data-test="'cluster-status-' + row.id" />
        </template>
        <template #cell-edition="{ row }"><UiBadge :color="row.edition === 'enterprise' ? 'accent' : 'neutral'">{{ row.edition }}</UiBadge></template>
        <template #cell-server_version="{ row }">
          <span class="font-mono">{{ row.server_version || '—' }}</span>
          <UiBadge v-if="row.writes_blocked" color="warning" class="ml-1">read-only</UiBadge>
        </template>
      </UiDataTable>
    </UiCard>
    <RegisterClusterDialog v-model="registering" @saved="onRegistered" />
  </UiPage>
</template>
