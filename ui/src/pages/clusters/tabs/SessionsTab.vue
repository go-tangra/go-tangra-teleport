<script setup lang="ts">
// Recorded sessions of one cluster (audit:read): participants, target,
// start and duration, newest first, with a deep link that opens playback in
// the Teleport web UI (a new tab, without opener). Teleport-supplied text is
// rendered as text only (SR-004); the link comes from the module, which
// builds it only for safe session ids.
import { onMounted, ref } from 'vue'
import { UiAlert, UiBadge, UiButton, UiCard, UiDataTable, UiSelect, type Column } from '@go-tangra/ui'
import { explain } from '@/api/client'
import type { Cluster, TeleportSession } from '@/api/types'
import { auditApi, durationText, lastWindow, MAX_WINDOW_MS, type SessionQuery } from '@/stores/audit'
import { formatTime } from '../status'

const props = defineProps<{ cluster: Cluster }>()

const RANGES = [
  { title: 'Last 24 hours', value: '86400000' },
  { title: 'Last 7 days', value: '604800000' },
  { title: 'Last 31 days', value: String(MAX_WINDOW_MS) },
]
const KINDS = { ssh: 'Server', kube: 'Kubernetes', db: 'Database', app: 'Application', desktop: 'Desktop' } as const
const range = ref('86400000')
const items = ref<TeleportSession[]>([])
const next = ref<string | undefined>()
const loading = ref(false)
const error = ref('')
let query: SessionQuery | null = null

async function load(more = false): Promise<void> {
  error.value = ''
  if (!more) query = { ...lastWindow(Number(range.value)), limit: 100 }
  if (!query) return
  loading.value = true
  try {
    const p = await auditApi.sessions(props.cluster.id, { ...query, next: more ? next.value : undefined })
    items.value = more ? [...items.value, ...p.items] : p.items
    next.value = p.next
  } catch (e) {
    error.value = explain(e)
  } finally {
    loading.value = false
  }
}
onMounted(() => void load())

/** Only https links from the module are opened. */
const safeLink = (s: TeleportSession) => (s.playback_url && s.playback_url.startsWith('https://') ? s.playback_url : '')

const columns: Column<TeleportSession>[] = [
  { key: 'started_at', label: 'Started', width: 'md', format: (s) => formatTime(s.started_at) },
  { key: 'kind', label: 'Type', width: 'sm' },
  { key: 'target', label: 'Target', format: (s) => s.target || '—' },
  { key: 'participants', label: 'Participants', format: (s) => s.participants.join(', ') || '—' },
  { key: 'duration_s', label: 'Duration', width: 'sm', format: (s) => durationText(s.duration_s) },
  { key: 'sid', label: 'Session', hideOnStack: true },
  { key: 'actions', label: '', width: 'sm' },
]
</script>

<template>
  <div class="flex flex-col gap-4" data-test="sessions-tab">
    <UiAlert v-if="error" kind="error" data-test="sessions-error">{{ error }}</UiAlert>
    <div class="flex flex-wrap items-end gap-2">
      <UiSelect v-model="range" label="Ended within" :options="RANGES" class="w-44" data-test="sessions-range" @update:model-value="load()" />
    </div>
    <UiCard :padded="false">
      <UiDataTable :items="items" :columns="columns" row-key="sid" :loading="loading" caption="Recorded sessions, newest first" empty-title="No recorded sessions in this range" data-test="sessions-table">
        <template #cell-kind="{ row }">
          <UiBadge>{{ KINDS[row.kind] ?? row.kind }}</UiBadge>
        </template>
        <template #cell-actions="{ row }">
          <div class="flex justify-end">
            <a v-if="safeLink(row)" :href="safeLink(row)" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-text" :data-test="'session-play-' + row.sid">
              Play in Teleport
            </a>
          </div>
        </template>
      </UiDataTable>
    </UiCard>
    <div v-if="next" class="flex justify-center">
      <UiButton variant="outlined" :disabled="loading" data-test="sessions-more" @click="load(true)">Load more</UiButton>
    </div>
  </div>
</template>
