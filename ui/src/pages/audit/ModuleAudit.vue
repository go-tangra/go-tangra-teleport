<script setup lang="ts">
// The module's own audit trail (audit:read): every change the module made
// or attempted — actor, cluster, action, target and outcome — newest first,
// paged with the platform list contract. Details never carry credentials,
// tokens, invite links or role YAML; they are shown as text.
import { onMounted, ref } from 'vue'
import { UiAlert, UiBadge, UiButton, UiCard, UiDataTable, UiDialog, UiInput, UiPage, UiSelect, type Column } from '@go-tangra/ui'
import { explain } from '@/api/client'
import type { AuditRecord, Page } from '@/api/types'
import { auditApi, fromLocalInput, type TrailQuery } from '@/stores/audit'
import { useClusters } from '@/stores/clusters'
import { formatTime } from '../clusters/status'

const clusters = useClusters()
const OUTCOMES = [
  { title: 'Any outcome', value: '' },
  { title: 'Success', value: 'success' },
  { title: 'Failure', value: 'failure' },
  { title: 'Unknown', value: 'unknown' },
]
const OUTCOME_COLORS = { success: 'success', failure: 'error', unknown: 'warning' } as const

const filter = ref({ cluster_id: '', action: '', outcome: '', from: '', to: '' })
const page = ref<Page<AuditRecord> | null>(null)
const current = ref(1)
const size = ref(50)
const loading = ref(false)
const error = ref('')
const shown = ref<AuditRecord | null>(null)

async function load(reset = false): Promise<void> {
  if (reset) current.value = 1
  loading.value = true
  error.value = ''
  const q: TrailQuery = { page: current.value, page_size: size.value }
  const f = filter.value
  if (f.cluster_id) q.cluster_id = f.cluster_id
  if (f.action.trim()) q.action = f.action.trim()
  if (f.outcome) q.outcome = f.outcome
  if (fromLocalInput(f.from)) q.from = fromLocalInput(f.from)
  if (fromLocalInput(f.to)) q.to = fromLocalInput(f.to)
  try {
    page.value = await auditApi.trail(q)
    current.value = page.value.page
  } catch (e) {
    error.value = explain(e)
  } finally {
    loading.value = false
  }
}
onMounted(() => {
  void load()
  void clusters.list({ page_size: 200 })
})

const clusterName = (id?: string) => (id ? (clusters.items.find((c) => c.id === id)?.display_name ?? id) : '—')
const columns: Column<AuditRecord>[] = [
  { key: 'time', label: 'Time', width: 'md', format: (r) => formatTime(r.time) },
  { key: 'action', label: 'Action' },
  { key: 'actor_id', label: 'Actor', hideOnStack: true, format: (r) => `${r.actor_kind}: ${r.actor_id}` },
  { key: 'cluster_id', label: 'Cluster', hideOnStack: true, format: (r) => clusterName(r.cluster_id) },
  { key: 'target_name', label: 'Target', format: (r) => `${r.target_kind} ${r.target_name}`.trim() },
  { key: 'outcome', label: 'Outcome', width: 'sm' },
  { key: 'actions', label: '', width: 'sm' },
]
</script>

<template>
  <UiPage title="Teleport module audit">
    <template #actions>
      <UiButton variant="text" icon="mdi-refresh" icon-only label="Refresh" @click="load()" />
    </template>
    <div class="flex flex-col gap-4">
      <UiAlert v-if="error" kind="error" data-test="audit-error">{{ error }}</UiAlert>
      <div class="flex flex-wrap items-end gap-2">
        <UiSelect
          id="moduleaudit-cluster" v-model="filter.cluster_id" label="Cluster" :options="[{ title: 'All clusters', value: '' }, ...clusters.items.map((c) => ({ title: c.display_name, value: c.id }))]"
          class="w-48" data-test="audit-cluster"
        />
        <UiInput id="audit-action" v-model="filter.action" label="Action (e.g. teleport.lock.create)" class="w-64" data-test="audit-action" @keyup.enter="load(true)" />
        <UiSelect id="audit-outcome" v-model="filter.outcome" label="Outcome" :options="OUTCOMES" class="w-40" data-test="audit-outcome" />
        <UiInput id="audit-from" v-model="filter.from" type="datetime-local" label="From" data-test="audit-from" />
        <UiInput id="audit-to" v-model="filter.to" type="datetime-local" label="To" data-test="audit-to" />
        <UiButton color="primary" icon="mdi-magnify" :disabled="loading" data-test="audit-search" @click="load(true)">Search</UiButton>
      </div>
      <UiCard :padded="false">
        <UiDataTable
          :items="page?.items ?? []" :columns="columns" row-key="id" :total="page?.total" :page="current" :page-size="size" :loading="loading"
          caption="Module audit trail, newest first" empty-title="No audit records" data-test="audit-table"
          @update:page="current = $event; load()" @update:page-size="size = $event; load(true)"
        >
          <template #cell-outcome="{ row }">
            <UiBadge :color="OUTCOME_COLORS[row.outcome]">{{ row.outcome }}</UiBadge>
            <span v-if="row.reason" class="ms-1 text-xs">{{ row.reason }}</span>
          </template>
          <template #cell-actions="{ row }">
            <div class="flex justify-end">
              <UiButton size="sm" variant="text" icon="mdi-information-outline" icon-only label="Details" :data-test="'audit-detail-' + row.id" @click="shown = row" />
            </div>
          </template>
        </UiDataTable>
      </UiCard>
    </div>
    <UiDialog :model-value="!!shown" title="Audit record" @update:model-value="shown = null">
      <pre class="max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs" data-test="audit-detail">{{ JSON.stringify(shown, null, 2) }}</pre>
    </UiDialog>
  </UiPage>
</template>
