<script setup lang="ts">
// Enroll inventory hosts as SSH nodes through their inventory agent (spec
// 002): pick hosts, see the labels each node will carry, and start the
// enrollment. The agent installs Teleport and joins on its own; no join
// token is shown or held here.
import { computed, ref, watch } from 'vue'
import { UiAlert, UiBadge, UiButton, UiCheckbox, UiDialog, UiInput, UiNumberInput } from '@go-tangra/ui'
import { explain } from '@/api/client'
import { enrollmentsApi } from '@/stores/resources'
import type { Cluster, EnrollmentsCreated, EnrollmentTarget } from '@/api/types'

const props = defineProps<{ cluster: Cluster }>()
const open = defineModel<boolean>({ required: true })
const emit = defineEmits<{ created: [] }>()

const MAX_HOSTS = 50
const query = ref('')
const targets = ref<EnrollmentTarget[]>([])
const truncated = ref(false)
const selected = ref<string[]>([])
const ttl = ref(24)
const busy = ref(false)
const error = ref('')
const result = ref<EnrollmentsCreated | null>(null)

const REASONS: Record<string, string> = {
  no_agent: 'no inventory agent',
  ambiguous_agent: 'more than one agent',
  not_supported_platform: 'platform not supported (Linux only)',
  upgrade_required: 'agent needs an upgrade',
  retired: 'host retired',
  disabled_on_server: 'disabled in inventory',
  not_found: 'host not found',
  dependency_unavailable: 'inventory unavailable',
}
const reasonText = (r: string): string => REASONS[r] ?? r
const enrollable = (t: EnrollmentTarget): boolean =>
  t.capability === 'enabled' && !(t.enrollment && ['pending', 'delivered', 'fetched', 'installing', 'joined'].includes(t.enrollment.state))
const canSubmit = computed(() => selected.value.length > 0 && selected.value.length <= MAX_HOSTS && !busy.value)

async function search(): Promise<void> {
  busy.value = true
  error.value = ''
  try {
    const p = await enrollmentsApi.targets(props.cluster.id, { q: query.value || undefined, limit: 100 })
    targets.value = p.items
    truncated.value = p.truncated
  } catch (e) {
    error.value = explain(e)
  } finally {
    busy.value = false
  }
}

function toggle(id: string, on: boolean): void {
  selected.value = on ? [...new Set([...selected.value, id])] : selected.value.filter((x) => x !== id)
}

watch(open, (v) => {
  if (v) {
    result.value = null
    selected.value = []
    void search()
  }
})

async function submit(): Promise<void> {
  busy.value = true
  error.value = ''
  try {
    result.value = await enrollmentsApi.create(props.cluster.id, { host_ids: selected.value, ttl_hours: ttl.value })
    selected.value = []
    emit('created')
    void search()
  } catch (e) {
    error.value = explain(e)
  } finally {
    busy.value = false
  }
}

const hostname = (id: string): string => targets.value.find((t) => t.host_id === id)?.hostname ?? id
</script>

<template>
  <UiDialog v-model="open" title="Enroll inventory hosts" size="lg" data-test="inventory-enroll-dialog">
    <div class="flex flex-col gap-4">
      <p class="text-sm">
        Each selected host's inventory agent installs Teleport and joins <strong>{{ cluster.display_name }}</strong> as an SSH node,
        labelled with its inventory facts. A single-use join token is created only when the agent asks for it.
      </p>
      <UiAlert v-if="error" kind="error" data-test="inventory-enroll-error">{{ error }}</UiAlert>
      <UiAlert v-if="result" :kind="result.refused.length ? 'warning' : 'success'" data-test="inventory-enroll-result">
        {{ result.items.length }} enrollment(s) started.
        <template v-if="result.refused.length">
          Not enrolled:
          <span v-for="r in result.refused" :key="r.host_id">{{ hostname(r.host_id) }} ({{ reasonText(r.reason) }}); </span>
        </template>
      </UiAlert>
      <div class="flex items-end gap-2">
        <UiInput id="inventory-enroll-q" v-model="query" label="Search hostname" class="grow" :maxlength="64" data-test="inventory-enroll-q" @keyup.enter="search()" />
        <UiButton variant="outline" :loading="busy" data-test="inventory-enroll-search" @click="search()">Search</UiButton>
      </div>
      <ul class="flex max-h-96 flex-col gap-2 overflow-y-auto" data-test="inventory-enroll-targets">
        <li v-if="!targets.length && !busy" class="text-sm opacity-70">No inventory hosts match.</li>
        <li v-for="t in targets" :key="t.host_id" class="flex flex-col gap-1 rounded border p-2" :data-test="'target-' + t.host_id">
          <div class="flex flex-wrap items-center gap-2">
            <UiCheckbox
              :id="'inventory-enroll-' + t.host_id" :model-value="selected.includes(t.host_id)" :disabled="!enrollable(t)" :label="t.hostname || t.host_id"
              @update:model-value="toggle(t.host_id, !!$event)"
            />
            <UiBadge :color="t.agent_online ? 'success' : 'neutral'">{{ t.agent_online ? 'agent online' : 'agent offline' }}</UiBadge>
            <UiBadge v-if="t.capability !== 'enabled'" color="warning">{{ reasonText(t.capability) }}</UiBadge>
            <UiBadge v-if="t.enrollment" color="info">{{ t.enrollment.state }}</UiBadge>
          </div>
          <div class="flex flex-wrap gap-1 text-xs">
            <UiBadge v-for="(v, k) in t.labels" :key="k" color="neutral" variant="outline">{{ k }}={{ v }}</UiBadge>
          </div>
        </li>
      </ul>
      <p v-if="truncated" class="text-xs opacity-70">More hosts match: refine the search.</p>
      <UiNumberInput id="inventory-enroll-ttl" v-model="ttl" label="Give up after (hours)" :min="1" :max="72" class="w-56" data-test="inventory-enroll-ttl" />
    </div>
    <template #actions>
      <UiButton variant="text" @click="open = false">Close</UiButton>
      <UiButton color="primary" :disabled="!canSubmit" :loading="busy" data-test="inventory-enroll-submit" @click="submit()">
        Enroll {{ selected.length || '' }} host{{ selected.length === 1 ? '' : 's' }}
      </UiButton>
    </template>
  </UiDialog>
</template>
