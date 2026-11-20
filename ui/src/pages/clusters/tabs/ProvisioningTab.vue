<script setup lang="ts">
// Tangra identity provisioning of one cluster (US5): role mappings from a
// tangra module role or group to Teleport roles and logins, the users tangra
// manages with their state, "provision" for one member and "sync now".
// Invites go to the user through notification and never reach this page.
// Unmanaged Teleport users are never shown or changed here.
import { computed, inject, onMounted, ref } from 'vue'
import { ABILITY_TOKEN } from '@casl/vue'
import type { AnyAbility } from '@casl/ability'
import { UiAlert, UiBadge, UiButton, UiCard, UiDataTable, UiDialog, UiForm, UiInput, UiSelect, useConfirm, type Column } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { explain } from '@/api/client'
import { managedApi, mappingsApi } from '@/stores/provisioning'
import { mappingEditSchema, mappingSchema, provisionSchema, type MappingEditForm, type MappingForm, type ProvisionForm } from '@/schemas'
import type { Cluster, ManagedState, ManagedUser, ProvisioningSummary, RoleMapping } from '@/api/types'
import { formatTime } from '../status'

const props = defineProps<{ cluster: Cluster }>()
const ability = inject<AnyAbility | null>(ABILITY_TOKEN, null)
const canManage = computed(() => (ability ? ability.can('manage', 'TeleportProvisioning') : true) && !props.cluster.writes_blocked)
const confirm = useConfirm()

const mappings = ref<RoleMapping[]>([])
const managed = ref<ManagedUser[]>([])
const loading = ref(false)
const error = ref('')
const notice = ref('')

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [m, u] = await Promise.all([mappingsApi.list(props.cluster.id), managedApi.list(props.cluster.id)])
    mappings.value = m.items
    managed.value = u.items
  } catch (e) {
    error.value = explain(e)
  } finally {
    loading.value = false
  }
}
onMounted(() => void load())

const SUBJECT_LABELS = { module_role: 'Module role', group: 'Group' } as const
const mappingColumns: Column<RoleMapping>[] = [
  { key: 'subject', label: 'Tangra role or group', format: (m) => `${SUBJECT_LABELS[m.subject_kind]}: ${m.subject_ref}` },
  { key: 'teleport_roles', label: 'Teleport roles', format: (m) => m.teleport_roles.join(', ') },
  { key: 'logins', label: 'Logins', hideOnStack: true, format: (m) => m.logins.join(', ') || '—' },
  { key: 'actions', label: '', width: 'sm' },
]

const STATE: Record<ManagedState, { label: string; color: string }> = {
  provisioning: { label: 'Provisioning', color: 'info' },
  active: { label: 'Active', color: 'success' },
  locked_pending_deletion: { label: 'Locked, pending deletion', color: 'warning' },
  error: { label: 'Error (retried at the next sync)', color: 'error' },
}
const managedColumns: Column<ManagedUser>[] = [
  { key: 'teleport_username', label: 'Teleport user' },
  { key: 'tangra_user_id', label: 'Tangra user', hideOnStack: true },
  { key: 'state', label: 'State' },
  { key: 'applied_roles', label: 'Roles', hideOnStack: true, format: (u) => u.applied_roles.join(', ') || '—' },
  { key: 'deprovision_after', label: 'Deleted after', width: 'md', format: (u) => (u.deprovision_after ? formatTime(u.deprovision_after) : '—') },
  { key: 'last_synced_at', label: 'Last sync', width: 'md', format: (u) => (u.last_synced_at ? formatTime(u.last_synced_at) : 'never') },
]

// ---- mapping editor
const creating = ref(false)
const createForm = useZodForm(mappingSchema, {
  onSubmit: (v) => mappingsApi.create(props.cluster.id, mappingSchema.parse(v as MappingForm)),
  onSuccess: () => {
    creating.value = false
    notice.value = 'Mapping saved. Matching users are provisioned at the next sync.'
    void load()
  },
})
const kinds = [
  { title: 'Tangra module role', value: 'module_role' },
  { title: 'Tangra group', value: 'group' },
]
function openCreate(): void {
  createForm.reset({ subject_kind: 'module_role', subject_ref: '', teleport_roles: '', logins: '' })
  creating.value = true
}
async function saveCreate(): Promise<void> {
  try {
    await createForm.submit()
  } catch (e) {
    createForm.setServerError(explain(e))
  }
}

const editing = ref<RoleMapping | null>(null)
const editForm = useZodForm(mappingEditSchema, {
  onSubmit: (v) => mappingsApi.update(props.cluster.id, editing.value!.id, mappingEditSchema.parse(v as MappingEditForm)),
  onSuccess: () => {
    editing.value = null
    notice.value = 'Mapping updated. Users are brought in line at the next sync.'
    void load()
  },
})
function openEdit(m: RoleMapping): void {
  editForm.reset({ teleport_roles: m.teleport_roles.join(', '), logins: m.logins.join(', ') })
  editing.value = m
}
async function saveEdit(): Promise<void> {
  try {
    await editForm.submit()
  } catch (e) {
    editForm.setServerError(explain(e))
  }
}

async function removeMapping(m: RoleMapping): Promise<void> {
  const ok = await confirm.ask({
    title: 'Remove this mapping?',
    text: `Users provisioned only through ${m.subject_ref} are locked at the next sync and deleted after the grace period.`,
    confirmLabel: 'Remove',
    danger: true,
  })
  if (!ok) return
  try {
    await mappingsApi.remove(props.cluster.id, m.id)
    notice.value = 'Mapping removed.'
    void load()
  } catch (e) {
    error.value = explain(e)
  }
}

// ---- provision one member, sync now
const provisioning = ref(false)
const provisionForm = useZodForm(provisionSchema, {
  onSubmit: (v) => managedApi.provision(props.cluster.id, provisionSchema.parse(v as ProvisionForm).tangra_user_id),
  onSuccess: () => {
    provisioning.value = false
    notice.value = 'User provisioned. The invite was sent to them through tangra notifications.'
    void load()
  },
})
function openProvision(): void {
  provisionForm.reset({ tangra_user_id: '' })
  provisioning.value = true
}
async function saveProvision(): Promise<void> {
  try {
    await provisionForm.submit()
  } catch (e) {
    provisionForm.setServerError(explain(e))
  }
}

const syncing = ref(false)
const summary = (s: ProvisioningSummary) =>
  `Sync done: ${s.created} created, ${s.updated} updated, ${s.unlocked} unlocked, ${s.locked} locked, ${s.deleted} deleted` +
  (s.errors ? `, ${s.errors} to retry (see the audit trail).` : '.')
async function syncNow(): Promise<void> {
  syncing.value = true
  error.value = ''
  try {
    notice.value = summary(await managedApi.sync(props.cluster.id))
    void load()
  } catch (e) {
    error.value = explain(e)
  } finally {
    syncing.value = false
  }
}
</script>

<template>
  <div class="flex flex-col gap-4" data-test="provisioning-tab">
    <UiAlert v-if="error" kind="error" data-test="provisioning-error">{{ error }}</UiAlert>
    <UiAlert v-if="notice" kind="success" dismissible @close="notice = ''">{{ notice }}</UiAlert>

    <div class="flex items-center justify-between">
      <h3 class="text-base font-medium">Role mappings</h3>
      <UiButton v-if="canManage" icon="mdi-plus" data-test="mapping-new" @click="openCreate">Add mapping</UiButton>
    </div>
    <UiCard :padded="false">
      <UiDataTable :items="mappings" :columns="mappingColumns" row-key="id" :loading="loading" caption="Role mappings"
        empty-title="No mappings" empty-text="Map a tangra role or group to Teleport roles to provision its members." data-test="mappings-table">
        <template #cell-actions="{ row }">
          <div v-if="canManage" class="flex justify-end gap-1">
            <UiButton size="sm" variant="text" icon="mdi-pencil" icon-only label="Edit mapping" :data-test="'mapping-edit-' + row.id" @click="openEdit(row)" />
            <UiButton size="sm" variant="text" icon="mdi-delete" icon-only label="Remove mapping" :data-test="'mapping-remove-' + row.id" @click="removeMapping(row)" />
          </div>
        </template>
      </UiDataTable>
    </UiCard>

    <div class="flex items-center justify-between">
      <h3 class="text-base font-medium">Managed users</h3>
      <div v-if="canManage" class="flex gap-2">
        <UiButton variant="soft" icon="mdi-account-plus" data-test="provision-new" @click="openProvision">Provision user</UiButton>
        <UiButton icon="mdi-sync" :loading="syncing" data-test="provisioning-sync" @click="syncNow">Sync now</UiButton>
      </div>
    </div>
    <UiCard :padded="false">
      <UiDataTable :items="managed" :columns="managedColumns" row-key="id" :loading="loading" caption="Managed users"
        empty-title="No managed users" empty-text="Users tangra provisions appear here. Teleport users created by hand are never changed." data-test="managed-table">
        <template #cell-state="{ row }">
          <UiBadge :color="STATE[row.state as ManagedState].color" :data-test="'managed-state-' + row.id">{{ STATE[row.state as ManagedState].label }}</UiBadge>
        </template>
      </UiDataTable>
    </UiCard>

    <UiDialog v-model="creating" title="Add role mapping" data-test="mapping-create">
      <UiForm :form="createForm">
        <div class="flex flex-col gap-4">
          <UiAlert v-if="createForm.serverError.value" kind="error">{{ createForm.serverError.value }}</UiAlert>
          <UiSelect v-bind="createForm.field('subject_kind')" label="Map" :options="kinds" :clearable="false" required data-test="mapping-kind" />
          <UiInput v-bind="createForm.field('subject_ref')" label="Tangra role slug or group id" required hint="For example operator." data-test="mapping-ref" />
          <UiInput v-bind="createForm.field('teleport_roles')" label="Teleport roles" required hint="Comma-separated; each must exist on the cluster." data-test="mapping-roles" />
          <UiInput v-bind="createForm.field('logins')" label="Logins" hint="Comma-separated, for example ubuntu." data-test="mapping-logins" />
        </div>
      </UiForm>
      <template #actions>
        <UiButton variant="text" @click="creating = false">Cancel</UiButton>
        <UiButton :loading="createForm.submitting.value" data-test="mapping-save" @click="saveCreate">Save</UiButton>
      </template>
    </UiDialog>

    <UiDialog :model-value="editing !== null" :title="editing ? 'Edit mapping for ' + editing.subject_ref : ''" data-test="mapping-edit" @update:model-value="(v: boolean) => { if (!v) editing = null }">
      <UiForm :form="editForm">
        <div class="flex flex-col gap-4">
          <UiAlert v-if="editForm.serverError.value" kind="error">{{ editForm.serverError.value }}</UiAlert>
          <UiInput v-bind="editForm.field('teleport_roles')" label="Teleport roles" required data-test="mapping-edit-roles" />
          <UiInput v-bind="editForm.field('logins')" label="Logins" data-test="mapping-edit-logins" />
        </div>
      </UiForm>
      <template #actions>
        <UiButton variant="text" @click="editing = null">Cancel</UiButton>
        <UiButton :loading="editForm.submitting.value" data-test="mapping-edit-save" @click="saveEdit">Save</UiButton>
      </template>
    </UiDialog>

    <UiDialog v-model="provisioning" title="Provision a tangra user" data-test="provision-dialog">
      <UiForm :form="provisionForm">
        <div class="flex flex-col gap-4">
          <UiAlert v-if="provisionForm.serverError.value" kind="error">{{ provisionForm.serverError.value }}</UiAlert>
          <UiInput v-bind="provisionForm.field('tangra_user_id')" label="Tangra user id" required
            hint="The member must hold a mapped role or group. The invite is sent to them, not shown here." data-test="provision-user" />
        </div>
      </UiForm>
      <template #actions>
        <UiButton variant="text" @click="provisioning = false">Cancel</UiButton>
        <UiButton :loading="provisionForm.submitting.value" data-test="provision-save" @click="saveProvision">Provision</UiButton>
      </template>
    </UiDialog>
  </div>
</template>
