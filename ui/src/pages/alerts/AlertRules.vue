<script setup lang="ts">
// Alert rules of the tenant (alerts:read; changes need alerts:manage). A
// rule watches Teleport events (allow-listed types; any match, or at least
// N by one user within W minutes) or a module condition (cluster
// unreachable, credential expiring, resource offline), for one cluster or
// all of them, and notifies tangra users through the notification module.
// Recipients are tangra user ids: the notification SDK has no recipient
// directory for the browser yet, and channel ids are stored but not used
// for delivery (plan.md deviation).
import { computed, inject, onMounted, ref } from 'vue'
import { ABILITY_TOKEN } from '@casl/vue'
import type { AnyAbility } from '@casl/ability'
import {
  UiAlert, UiBadge, UiButton, UiCard, UiCheckbox, UiDataTable, UiDialog, UiInput, UiNumberInput, UiPage, UiSelect, UiSwitch, UiTextarea,
  useConfirm, type Column,
} from '@go-tangra/ui'
import { explain } from '@/api/client'
import { EVENT_TYPES, type AlertRule, type AlertRuleInput, type ConditionKind, type EventType } from '@/api/types'
import { alertRulesApi } from '@/stores/audit'
import { useClusters } from '@/stores/clusters'

const ability = inject<AnyAbility | null>(ABILITY_TOKEN, null)
const can = (action: string) => (ability ? ability.can(action, 'TeleportAlertRule') : true)
const confirm = useConfirm()
const clusters = useClusters()

const CONDITIONS: { title: string; value: ConditionKind }[] = [
  { title: 'Teleport events', value: 'teleport_event' },
  { title: 'Cluster unreachable', value: 'cluster_unreachable' },
  { title: 'Credential expiring', value: 'credential_expiring' },
  { title: 'Resource offline', value: 'resource_offline' },
]
const conditionLabel = (k: string) => CONDITIONS.find((c) => c.value === k)?.title ?? k

const items = ref<AlertRule[]>([])
const loading = ref(false)
const error = ref('')
const notice = ref('')

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    items.value = (await alertRulesApi.list()).items
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

const clusterOptions = computed(() => [{ title: 'All clusters', value: '' }, ...clusters.items.map((c) => ({ title: c.display_name, value: c.id }))])
const clusterName = (id?: string) => (id ? (clusters.items.find((c) => c.id === id)?.display_name ?? id) : 'All clusters')

// ---- editor
interface Draft {
  id?: string
  cluster_id: string
  name: string
  condition_kind: ConditionKind
  event_types: EventType[]
  burst: boolean
  threshold_count: number
  window_minutes: number
  recipients: string
  enabled: boolean
}
const editing = ref<Draft | null>(null)
const saving = ref(false)
const formError = ref('')

function open(r?: AlertRule): void {
  formError.value = ''
  editing.value = r
    ? { id: r.id, cluster_id: r.cluster_id ?? '', name: r.name, condition_kind: r.condition_kind, event_types: r.event_types as EventType[],
        burst: r.threshold_count > 0, threshold_count: r.threshold_count || 3, window_minutes: r.window_minutes || 5,
        recipients: r.recipients.user_ids.join('\n'), enabled: r.enabled }
    : { cluster_id: '', name: '', condition_kind: 'teleport_event', event_types: ['user.login.failure'], burst: false, threshold_count: 3,
        window_minutes: 5, recipients: '', enabled: true }
}

function toggleType(t: EventType, on: boolean): void {
  if (!editing.value) return
  const set = new Set(editing.value.event_types)
  if (on) set.add(t)
  else set.delete(t)
  editing.value.event_types = EVENT_TYPES.filter((x) => set.has(x))
}

function body(d: Draft): AlertRuleInput {
  const events = d.condition_kind === 'teleport_event'
  return {
    cluster_id: d.cluster_id || undefined,
    name: d.name.trim(),
    condition_kind: d.condition_kind,
    event_types: events ? d.event_types : undefined,
    threshold_count: events && d.burst ? d.threshold_count : undefined,
    window_minutes: events && d.burst ? d.window_minutes : undefined,
    recipients: { user_ids: d.recipients.split(/[\s,]+/).filter(Boolean) },
    enabled: d.enabled,
  }
}

async function save(): Promise<void> {
  const d = editing.value
  if (!d) return
  saving.value = true
  formError.value = ''
  try {
    if (d.id) await alertRulesApi.update(d.id, body(d))
    else await alertRulesApi.create(body(d))
    notice.value = d.id ? 'Rule saved.' : 'Rule created.'
    editing.value = null
    void load()
  } catch (e) {
    formError.value = explain(e)
  } finally {
    saving.value = false
  }
}

async function remove(r: AlertRule): Promise<void> {
  const ok = await confirm.ask({ title: 'Delete this rule?', text: `"${r.name}" stops alerting.`, confirmLabel: 'Delete', danger: true })
  if (!ok) return
  try {
    await alertRulesApi.remove(r.id)
    notice.value = 'Rule deleted.'
    void load()
  } catch (e) {
    error.value = explain(e)
  }
}

const describeRule = (r: AlertRule) => {
  if (r.condition_kind !== 'teleport_event') return conditionLabel(r.condition_kind)
  const what = r.event_types.join(', ')
  return r.threshold_count > 0 ? `${r.threshold_count}× ${what} by one user within ${r.window_minutes} min` : `any ${what}`
}

const columns: Column<AlertRule>[] = [
  { key: 'name', label: 'Name' },
  { key: 'condition', label: 'When', format: describeRule },
  { key: 'cluster_id', label: 'Cluster', hideOnStack: true, format: (r) => clusterName(r.cluster_id) },
  { key: 'recipients', label: 'Recipients', width: 'sm', format: (r) => String(r.recipients.user_ids.length) },
  { key: 'enabled', label: 'State', width: 'sm' },
  { key: 'actions', label: '', width: 'sm' },
]
</script>

<template>
  <UiPage title="Teleport alert rules">
    <template #actions>
      <UiButton v-if="can('create')" icon="mdi-plus" data-test="rule-new" @click="open()">New rule</UiButton>
      <UiButton variant="text" icon="mdi-refresh" icon-only label="Refresh" @click="load" />
    </template>
    <div class="flex flex-col gap-4">
      <UiAlert v-if="error" kind="error" data-test="rules-error">{{ error }}</UiAlert>
      <UiAlert v-if="notice" kind="success" dismissible @close="notice = ''">{{ notice }}</UiAlert>
      <UiCard :padded="false">
        <UiDataTable :items="items" :columns="columns" row-key="id" :loading="loading" caption="Alert rules" empty-title="No alert rules" data-test="rules-table">
          <template #cell-enabled="{ row }">
            <UiBadge :color="row.enabled ? 'success' : 'default'">{{ row.enabled ? 'enabled' : 'disabled' }}</UiBadge>
          </template>
          <template #cell-actions="{ row }">
            <div class="flex justify-end gap-1">
              <UiButton v-if="can('update')" size="sm" variant="text" icon="mdi-pencil" icon-only label="Edit rule" :data-test="'rule-edit-' + row.id" @click="open(row)" />
              <UiButton v-if="can('delete')" size="sm" variant="text" icon="mdi-delete" icon-only label="Delete rule" :data-test="'rule-delete-' + row.id" @click="remove(row)" />
            </div>
          </template>
        </UiDataTable>
      </UiCard>
    </div>

    <UiDialog :model-value="!!editing" :title="editing?.id ? 'Edit alert rule' : 'New alert rule'" @update:model-value="editing = null">
      <form v-if="editing" class="flex flex-col gap-3" data-test="rule-form" @submit.prevent="save">
        <UiAlert v-if="formError" kind="error" data-test="rule-form-error">{{ formError }}</UiAlert>
        <UiInput id="rule-name" v-model="editing.name" label="Name" :maxlength="64" required data-test="rule-name" />
        <UiSelect v-model="editing.cluster_id" label="Cluster" :options="clusterOptions" :disabled="!!editing.id" hint="The scope cannot change after creation." data-test="rule-cluster" />
        <UiSelect v-model="editing.condition_kind" label="Alert when" :options="CONDITIONS" data-test="rule-condition" />
        <template v-if="editing.condition_kind === 'teleport_event'">
          <fieldset class="flex flex-col gap-1" data-test="rule-event-types">
            <legend class="mb-1 text-sm font-medium">Event types</legend>
            <div class="grid grid-cols-1 gap-1 sm:grid-cols-2">
              <UiCheckbox v-for="t in EVENT_TYPES" :id="'rule-type-' + t" :key="t" :model-value="editing.event_types.includes(t)" :label="t"
                @update:model-value="toggleType(t, !!$event)" />
            </div>
          </fieldset>
          <UiSwitch v-model="editing.burst" label="Only on a burst by one user" data-test="rule-burst" />
          <div v-if="editing.burst" class="flex gap-2">
            <UiNumberInput id="rule-count" v-model="editing.threshold_count" label="At least (events)" :min="1" :max="1000" data-test="rule-count" />
            <UiNumberInput id="rule-window" v-model="editing.window_minutes" label="Within (minutes)" :min="1" :max="1440" data-test="rule-window" />
          </div>
        </template>
        <UiTextarea id="rule-recipients" v-model="editing.recipients" label="Recipients (tangra user ids, one per line)" :rows="3" required data-test="rule-recipients" />
        <UiSwitch v-model="editing.enabled" label="Enabled" data-test="rule-enabled" />
        <div class="flex justify-end gap-2">
          <UiButton variant="text" @click="editing = null">Cancel</UiButton>
          <UiButton type="submit" color="primary" :disabled="saving" data-test="rule-save">Save</UiButton>
        </div>
      </form>
    </UiDialog>
  </UiPage>
</template>
