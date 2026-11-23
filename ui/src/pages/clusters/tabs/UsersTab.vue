<script setup lang="ts">
// Teleport users of one cluster: list (with managed and locked flags), create
// with roles and logins (the invite link is shown once in the dialog), edit
// roles and logins against the revision read (a 409 reloads the user),
// reset (a one-time link) and delete. The management identity is shown but
// cannot be changed. Teleport-supplied text is rendered as text only.
import { computed, inject, onMounted, ref } from 'vue'
import { ABILITY_TOKEN } from '@casl/vue'
import type { AnyAbility } from '@casl/ability'
import { UiAlert, UiBadge, UiButton, UiCard, UiDataTable, UiDialog, UiForm, UiInput, useConfirm, type Column } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { ApiError, explain } from '@/api/client'
import { usersApi } from '@/stores/identity'
import { userSchema, userEditSchema } from '@/schemas'
import type { Cluster, ResetLink, TeleportUser, UserCreated } from '@/api/types'
import OneTimeLink from '@/components/OneTimeLink.vue'
import { formatTime } from '../status'

const props = defineProps<{ cluster: Cluster }>()
const ability = inject<AnyAbility | null>(ABILITY_TOKEN, null)
const can = (action: string) => (ability ? ability.can(action, 'TeleportUser') : true)
const writable = computed(() => !props.cluster.writes_blocked)
const confirm = useConfirm()

const items = ref<TeleportUser[]>([])
const next = ref<string | undefined>()
const q = ref('')
const loading = ref(false)
const error = ref('')
const notice = ref('')

async function load(more = false): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const p = await usersApi.list(props.cluster.id, { q: q.value || undefined, next: more ? next.value : undefined })
    items.value = more ? [...items.value, ...p.items] : p.items
    next.value = p.next
  } catch (e) {
    error.value = explain(e)
  } finally {
    loading.value = false
  }
}
onMounted(() => void load())

const isSelf = (u: TeleportUser) => u.name === props.cluster.credential_identity
const columns: Column<TeleportUser>[] = [
  { key: 'name', label: 'User' },
  { key: 'roles', label: 'Roles', format: (u) => u.roles.join(', ') },
  { key: 'logins', label: 'Logins', hideOnStack: true, format: (u) => u.logins.join(', ') || '—' },
  { key: 'created', label: 'Created', width: 'md', hideOnStack: true, format: (u) => formatTime(u.created) },
  { key: 'actions', label: '', width: 'md' },
]

// ---- create (the invite is shown once, then dropped with the dialog)
const creating = ref(false)
const created = ref<UserCreated | null>(null)
const createForm = useZodForm(userSchema, {
  onSubmit: (v) => {
    return usersApi.create(props.cluster.id, v)
  },
  onSuccess: (r) => {
    created.value = r as UserCreated
    void load()
  },
})
function openCreate(): void {
  created.value = null
  createForm.reset({ name: '', roles: '', logins: '' })
  creating.value = true
}
function closeCreate(): void {
  created.value = null
  createForm.reset()
  creating.value = false
}
async function saveCreate(): Promise<void> {
  try {
    await createForm.submit()
  } catch (e) {
    createForm.setServerError(explain(e))
  }
}

// ---- edit
const editing = ref<TeleportUser | null>(null)
const editForm = useZodForm(userEditSchema, {
  onSubmit: (v) => {
    const u = editing.value as TeleportUser
    return usersApi.update(props.cluster.id, u.name, { ...v, revision: u.revision })
  },
  onSuccess: () => {
    editing.value = null
    notice.value = 'User updated.'
    void load()
  },
})
function openEdit(u: TeleportUser): void {
  editForm.reset({ roles: u.roles.join(', '), logins: u.logins.join(', ') })
  editing.value = u
}
async function saveEdit(): Promise<void> {
  try {
    await editForm.submit()
  } catch (e) {
    if (e instanceof ApiError && e.reason === 'conflict') {
      editForm.setServerError('This user was changed in Teleport since you opened it. The form now shows the current values; review and save again.')
      await load()
      const fresh = items.value.find((x) => x.name === editing.value?.name)
      if (fresh) openEdit(fresh)
      return
    }
    editForm.setServerError(explain(e))
  }
}

// ---- reset and delete
const resetLink = ref<ResetLink | null>(null)
async function reset(u: TeleportUser): Promise<void> {
  const ok = await confirm.ask({ title: `Reset ${u.name}?`, text: 'Their password and second factors stop working until they use the reset link.', confirmLabel: 'Reset', danger: true })
  if (!ok) return
  try {
    resetLink.value = await usersApi.reset(props.cluster.id, u.name)
  } catch (e) {
    error.value = explain(e)
  }
}
async function remove(u: TeleportUser): Promise<void> {
  const ok = await confirm.ask({ title: `Delete ${u.name}?`, text: 'The user is deleted from Teleport and their sessions end.', confirmLabel: 'Delete', danger: true })
  if (!ok) return
  try {
    await usersApi.remove(props.cluster.id, u.name)
    notice.value = `${u.name} deleted.`
    void load()
  } catch (e) {
    error.value = explain(e)
  }
}
</script>

<template>
  <div class="flex flex-col gap-4" data-test="users-tab">
    <UiAlert v-if="error" kind="error" data-test="users-error">{{ error }}</UiAlert>
    <UiAlert v-if="notice" kind="success" dismissible @close="notice = ''">{{ notice }}</UiAlert>
    <div class="flex flex-wrap items-end gap-2">
      <UiInput id="users-q" v-model="q" label="Filter by name" class="max-w-xs" @keyup.enter="load()" />
      <UiButton variant="soft" icon="mdi-magnify" @click="load()">Search</UiButton>
      <span class="grow" />
      <UiButton v-if="can('create') && writable" icon="mdi-account-plus" data-test="user-new" @click="openCreate">New user</UiButton>
    </div>
    <UiCard :padded="false">
      <UiDataTable
        :items="items" :columns="columns" row-key="name" :loading="loading" :has-more="!!next" caption="Teleport users"
        empty-title="No users" empty-text="No Teleport user matches." data-test="users-table" @load-more="load(true)"
      >
        <template #cell-name="{ row }">
          <div class="flex flex-wrap items-center gap-1">
            <span class="font-mono">{{ row.name }}</span>
            <UiBadge v-if="isSelf(row)" color="info">management identity</UiBadge>
            <UiBadge v-if="row.managed" color="accent">managed</UiBadge>
            <UiBadge v-if="row.locked" color="error" :data-test="'user-locked-' + row.name">locked</UiBadge>
          </div>
        </template>
        <template #cell-actions="{ row }">
          <div v-if="!isSelf(row) && writable" class="flex justify-end gap-1">
            <UiButton v-if="can('update')" size="sm" variant="text" icon="mdi-pencil" icon-only label="Edit" :data-test="'user-edit-' + row.name" @click="openEdit(row)" />
            <UiButton v-if="can('reset')" size="sm" variant="text" icon="mdi-restart" icon-only label="Reset" :data-test="'user-reset-' + row.name" @click="reset(row)" />
            <UiButton v-if="can('delete')" size="sm" variant="text" color="error" icon="mdi-delete-outline" icon-only label="Delete" :data-test="'user-delete-' + row.name" @click="remove(row)" />
          </div>
        </template>
      </UiDataTable>
    </UiCard>

    <UiDialog :model-value="creating" :title="created ? 'User created' : 'New Teleport user'" persistent data-test="user-create" @update:model-value="!$event && closeCreate()">
      <OneTimeLink v-if="created" :url="created.invite_url" :expires-at="created.invite_expires_at" kind="invite" />
      <UiForm v-else :form="createForm">
        <div class="flex flex-col gap-4">
          <UiAlert v-if="createForm.serverError.value" kind="error">{{ createForm.serverError.value }}</UiAlert>
          <UiInput v-bind="createForm.field('name')" label="Username" required data-test="user-name" />
          <UiInput v-bind="createForm.field('roles')" label="Roles" required hint="Comma-separated Teleport roles, for example access." data-test="user-roles" />
          <UiInput v-bind="createForm.field('logins')" label="Logins" hint="Comma-separated OS logins, for example ubuntu." data-test="user-logins" />
        </div>
      </UiForm>
      <template #actions>
        <UiButton v-if="created" data-test="user-create-done" @click="closeCreate">Done</UiButton>
        <template v-else>
          <UiButton variant="text" @click="closeCreate">Cancel</UiButton>
          <UiButton :loading="createForm.submitting.value" data-test="user-create-save" @click="saveCreate">Create and invite</UiButton>
        </template>
      </template>
    </UiDialog>

    <UiDialog :model-value="!!editing" :title="`Edit ${editing?.name ?? ''}`" data-test="user-edit" @update:model-value="!$event && (editing = null)">
      <UiForm :form="editForm">
        <div class="flex flex-col gap-4">
          <UiAlert v-if="editForm.serverError.value" kind="error">{{ editForm.serverError.value }}</UiAlert>
          <UiInput v-bind="editForm.field('roles')" label="Roles" required />
          <UiInput v-bind="editForm.field('logins')" label="Logins" />
        </div>
      </UiForm>
      <template #actions>
        <UiButton variant="text" @click="editing = null">Cancel</UiButton>
        <UiButton :loading="editForm.submitting.value" data-test="user-edit-save" @click="saveEdit">Save</UiButton>
      </template>
    </UiDialog>

    <UiDialog :model-value="!!resetLink" title="Reset link" persistent data-test="user-reset-link" @update:model-value="!$event && (resetLink = null)">
      <OneTimeLink v-if="resetLink" :url="resetLink.reset_url" :expires-at="resetLink.expires_at" kind="reset" />
      <template #actions><UiButton @click="resetLink = null">Done</UiButton></template>
    </UiDialog>
  </div>
</template>
