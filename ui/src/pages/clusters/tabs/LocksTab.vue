<script setup lang="ts">
// Active Teleport locks of one cluster, and the incident-response control:
// lock a user, role or server with a mandatory reason and an optional
// expiry; remove a lock. Teleport enforces a lock on live sessions within
// seconds. Locks on the management identity or its roles are refused by the
// server with an explanation.
import { computed, inject, onMounted, ref } from 'vue'
import { ABILITY_TOKEN } from '@casl/vue'
import type { AnyAbility } from '@casl/ability'
import { UiAlert, UiButton, UiCard, UiDataTable, UiDialog, UiForm, UiInput, UiSelect, useConfirm, type Column } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { explain } from '@/api/client'
import { locksApi } from '@/stores/identity'
import { lockSchema } from '@/schemas'
import type { Cluster, LockTargetKind, TeleportLock } from '@/api/types'
import { formatTime } from '../status'

const props = defineProps<{ cluster: Cluster }>()
const ability = inject<AnyAbility | null>(ABILITY_TOKEN, null)
const can = (action: string) => (ability ? ability.can(action, 'TeleportLock') : true)
const writable = computed(() => !props.cluster.writes_blocked)
const confirm = useConfirm()

const items = ref<TeleportLock[]>([])
const loading = ref(false)
const error = ref('')
const notice = ref('')

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    items.value = (await locksApi.list(props.cluster.id)).items
  } catch (e) {
    error.value = explain(e)
  } finally {
    loading.value = false
  }
}
onMounted(() => void load())

const KIND_LABELS: Record<LockTargetKind, string> = { user: 'User', role: 'Role', server_id: 'Server' }
const targetOf = (l: TeleportLock) => l.target.user ?? l.target.role ?? l.target.server_id ?? '—'
const columns: Column<TeleportLock>[] = [
  { key: 'target', label: 'Target', format: (l) => `${KIND_LABELS[l.target_kind]}: ${targetOf(l)}` },
  { key: 'message', label: 'Reason' },
  { key: 'created_by', label: 'Author', hideOnStack: true },
  { key: 'expires_at', label: 'Expires', width: 'md', format: (l) => (l.expires_at ? formatTime(l.expires_at) : 'until removed') },
  { key: 'actions', label: '', width: 'sm' },
]

const creating = ref(false)
const form = useZodForm(lockSchema, {
  onSubmit: (v) => {
    return locksApi.create(props.cluster.id, { ...v, expires_at: v.expires_at ? new Date(v.expires_at).toISOString() : undefined })
  },
  onSuccess: () => {
    creating.value = false
    notice.value = 'Lock created. Teleport ends matching sessions within seconds.'
    void load()
  },
})
const kinds = [
  { title: 'User', value: 'user' },
  { title: 'Role', value: 'role' },
  { title: 'Server (host ID)', value: 'server_id' },
]
function openCreate(): void {
  form.reset({ target_kind: 'user', target: '', reason: '', expires_at: '' })
  creating.value = true
}
async function save(): Promise<void> {
  try {
    await form.submit()
  } catch (e) {
    form.setServerError(explain(e))
  }
}

async function remove(l: TeleportLock): Promise<void> {
  const ok = await confirm.ask({ title: 'Remove this lock?', text: `${KIND_LABELS[l.target_kind]} ${targetOf(l)} can connect again.`, confirmLabel: 'Remove', danger: true })
  if (!ok) return
  try {
    await locksApi.remove(props.cluster.id, l.name)
    notice.value = 'Lock removed.'
    void load()
  } catch (e) {
    error.value = explain(e)
  }
}
</script>

<template>
  <div class="flex flex-col gap-4" data-test="locks-tab">
    <UiAlert v-if="error" kind="error" data-test="locks-error">{{ error }}</UiAlert>
    <UiAlert v-if="notice" kind="success" dismissible @close="notice = ''">{{ notice }}</UiAlert>
    <div class="flex justify-end">
      <UiButton v-if="can('create') && writable" color="error" icon="mdi-lock-outline" data-test="lock-new" @click="openCreate">Create lock</UiButton>
    </div>
    <UiCard :padded="false">
      <UiDataTable :items="items" :columns="columns" row-key="name" :loading="loading" caption="Active locks" empty-title="No active locks" data-test="locks-table">
        <template #cell-actions="{ row }">
          <div class="flex justify-end">
            <UiButton v-if="can('delete') && writable" size="sm" variant="text" icon="mdi-lock-open-outline" icon-only label="Remove lock" :data-test="'lock-remove-' + row.name" @click="remove(row)" />
          </div>
        </template>
      </UiDataTable>
    </UiCard>

    <UiDialog v-model="creating" title="Create lock" data-test="lock-create">
      <UiForm :form="form">
        <div class="flex flex-col gap-4">
          <UiAlert v-if="form.serverError.value" kind="error">{{ form.serverError.value }}</UiAlert>
          <UiSelect v-bind="form.field('target_kind')" label="Target" :options="kinds" :clearable="false" required data-test="lock-kind" />
          <UiInput v-bind="form.field('target')" label="User, role or host ID" required data-test="lock-target" />
          <UiInput v-bind="form.field('reason')" label="Reason" required hint="Shown to the locked-out user and recorded in the audit trail." data-test="lock-reason" />
          <UiInput v-bind="form.field('expires_at')" type="datetime-local" label="Expires" hint="Leave empty to lock until removed." data-test="lock-expires" />
        </div>
      </UiForm>
      <template #actions>
        <UiButton variant="text" @click="creating = false">Cancel</UiButton>
        <UiButton color="error" :loading="form.submitting.value" data-test="lock-save" @click="save">Lock</UiButton>
      </template>
    </UiDialog>
  </div>
</template>
