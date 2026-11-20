<script setup lang="ts">
// Teleport audit events of one cluster, searched live (audit:read): a time
// range (preset or custom, at most 31 days), event type, user and resource
// filters, newest first, paged with Teleport's cursor. Every Teleport-
// supplied string (user, resource, summary, raw) is rendered with text
// interpolation only — never v-html — so it shows as text and never runs
// (SR-004).
import { computed, onMounted, ref } from 'vue'
import { UiAlert, UiBadge, UiButton, UiCard, UiDataTable, UiDialog, UiInput, UiSelect, type Column } from '@go-tangra/ui'
import { explain } from '@/api/client'
import { EVENT_TYPES, type AuditEvent, type Cluster } from '@/api/types'
import { auditApi, fromLocalInput, lastWindow, MAX_WINDOW_MS, type EventQuery } from '@/stores/audit'
import { formatTime } from '../status'

const props = defineProps<{ cluster: Cluster }>()

const RANGES = [
  { title: 'Last hour', value: '3600000' },
  { title: 'Last 24 hours', value: '86400000' },
  { title: 'Last 7 days', value: '604800000' },
  { title: 'Last 31 days', value: String(MAX_WINDOW_MS) },
  { title: 'Custom', value: 'custom' },
]
const range = ref('86400000')
const customFrom = ref('')
const customTo = ref('')
const type = ref('')
const user = ref('')
const resource = ref('')
const types = [{ title: 'All event types', value: '' }, ...EVENT_TYPES.map((t) => ({ title: t, value: t }))]

const items = ref<AuditEvent[]>([])
const next = ref<string | undefined>()
const loading = ref(false)
const error = ref('')
const shown = ref<AuditEvent | null>(null)
// The window and filters of the first page: `next` is only valid with them.
let query: EventQuery | null = null

function windowOf(): { from: string; to: string } | null {
  if (range.value !== 'custom') return lastWindow(Number(range.value))
  const from = fromLocalInput(customFrom.value)
  const to = fromLocalInput(customTo.value)
  if (!from || !to) {
    error.value = 'Choose both the start and the end of the range.'
    return null
  }
  const ms = new Date(to).getTime() - new Date(from).getTime()
  if (ms < 0 || ms > MAX_WINDOW_MS) {
    error.value = 'The range must end after it starts and span at most 31 days.'
    return null
  }
  return { from, to }
}

async function load(more = false): Promise<void> {
  error.value = ''
  if (!more) {
    const w = windowOf()
    if (!w) return
    query = { ...w, limit: 100, types: type.value || undefined, user: user.value.trim() || undefined, resource: resource.value.trim() || undefined }
  }
  if (!query) return
  loading.value = true
  try {
    const p = await auditApi.events(props.cluster.id, { ...query, next: more ? next.value : undefined })
    items.value = more ? [...items.value, ...p.items] : p.items
    next.value = p.next
  } catch (e) {
    error.value = explain(e)
  } finally {
    loading.value = false
  }
}
onMounted(() => void load())

const rawText = computed(() => (shown.value ? JSON.stringify(shown.value.raw, null, 2) : ''))
const columns: Column<AuditEvent>[] = [
  { key: 'time', label: 'Time', width: 'md', format: (e) => formatTime(e.time) },
  { key: 'type', label: 'Event' },
  { key: 'user', label: 'User', format: (e) => e.user || '—' },
  { key: 'resource', label: 'Resource', hideOnStack: true, format: (e) => e.resource || '—' },
  { key: 'summary', label: 'Summary', hideOnStack: true },
  { key: 'actions', label: '', width: 'sm' },
]
</script>

<template>
  <div class="flex flex-col gap-4" data-test="events-tab">
    <UiAlert v-if="error" kind="error" data-test="events-error">{{ error }}</UiAlert>
    <div class="flex flex-wrap items-end gap-2">
      <UiSelect v-model="range" label="Time range" :options="RANGES" class="w-44" data-test="events-range" />
      <template v-if="range === 'custom'">
        <UiInput id="events-from" v-model="customFrom" type="datetime-local" label="From" data-test="events-from" />
        <UiInput id="events-to" v-model="customTo" type="datetime-local" label="To" data-test="events-to" />
      </template>
      <UiSelect v-model="type" label="Event type" :options="types" class="w-60" data-test="events-type" />
      <UiInput id="events-user" v-model="user" label="User" class="w-40" data-test="events-user" @keyup.enter="load()" />
      <UiInput id="events-resource" v-model="resource" label="Resource" class="w-40" data-test="events-resource" @keyup.enter="load()" />
      <UiButton color="primary" icon="mdi-magnify" :disabled="loading" data-test="events-search" @click="load()">Search</UiButton>
    </div>
    <UiCard :padded="false">
      <UiDataTable :items="items" :columns="columns" row-key="id" :loading="loading" caption="Audit events, newest first" empty-title="No events in this range" data-test="events-table">
        <template #cell-type="{ row }">
          <div class="flex items-center gap-2">
            <span>{{ row.type }}</span>
            <UiBadge v-if="!row.success" color="error">failed</UiBadge>
          </div>
        </template>
        <template #cell-actions="{ row }">
          <div class="flex justify-end">
            <UiButton size="sm" variant="text" icon="mdi-code-json" icon-only label="Show the raw event" :data-test="'event-raw-' + row.id" @click="shown = row" />
          </div>
        </template>
      </UiDataTable>
    </UiCard>
    <div v-if="next" class="flex justify-center">
      <UiButton variant="outlined" :disabled="loading" data-test="events-more" @click="load(true)">Load more</UiButton>
    </div>
    <UiDialog :model-value="!!shown" title="Raw event" @update:model-value="shown = null">
      <p class="mb-2 text-sm">{{ shown?.summary }} · {{ shown?.code }}</p>
      <!-- Text interpolation: Teleport's JSON is shown, never interpreted. -->
      <pre class="max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs" data-test="event-raw">{{ rawText }}</pre>
    </UiDialog>
  </div>
</template>
