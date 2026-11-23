<script setup lang="ts">
// Teleport roles of one cluster: list with a built-in badge, a YAML editor
// for a new or existing role, a preview (server validation and a diff of the
// normalized YAML, no side effects), apply after confirmation, and delete.
// A 409 (the role changed in Teleport since it was read) offers a reload.
// Built-in roles and roles held by the management identity cannot be
// deleted; the server refuses with an explanation.
import { inject, onMounted, ref } from 'vue'
import { ABILITY_TOKEN } from '@casl/vue'
import type { AnyAbility } from '@casl/ability'
import { UiAlert, UiBadge, UiButton, UiCard, UiDataTable, UiDialog, UiInput, UiTextarea, useConfirm, type Column } from '@go-tangra/ui'
import { ApiError, explain } from '@/api/client'
import { rolesApi } from '@/stores/identity'
import { MAX_ROLE_YAML_BYTES, TELEPORT_NAME } from '@/schemas'
import type { Cluster, RolePreview, TeleportRole } from '@/api/types'
import RoleDiff from '@/components/RoleDiff.vue'

const props = defineProps<{ cluster: Cluster }>()
const ability = inject<AnyAbility | null>(ABILITY_TOKEN, null)
const can = (action: string) => (ability ? ability.can(action, 'TeleportRole') : true)
const confirm = useConfirm()

const items = ref<TeleportRole[]>([])
const next = ref<string | undefined>()
const loading = ref(false)
const error = ref('')
const notice = ref('')

async function load(more = false): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const p = await rolesApi.list(props.cluster.id, { next: more ? next.value : undefined })
    items.value = more ? [...items.value, ...p.items] : p.items
    next.value = p.next
  } catch (e) {
    error.value = explain(e)
  } finally {
    loading.value = false
  }
}
onMounted(() => void load())

const columns: Column<TeleportRole>[] = [
  { key: 'name', label: 'Role' },
  { key: 'actions', label: '', width: 'sm' },
]

// ---- editor
const NEW_ROLE = 'kind: role\nversion: v7\nmetadata:\n  name: \nspec:\n  allow:\n    logins: []\n    node_labels: {}\n'
const open = ref(false)
const isNew = ref(false)
const name = ref('')
const yaml = ref('')
const revision = ref('')
const preset = ref(false)
const preview = ref<RolePreview | null>(null)
const editorError = ref('')
const busy = ref(false)

async function edit(r: TeleportRole): Promise<void> {
  editorError.value = ''
  preview.value = null
  try {
    const d = await rolesApi.get(props.cluster.id, r.name)
    isNew.value = false
    name.value = r.name
    yaml.value = d.yaml
    revision.value = d.revision
    preset.value = d.preset
    open.value = true
  } catch (e) {
    error.value = explain(e)
  }
}
function create(): void {
  isNew.value = true
  name.value = ''
  yaml.value = NEW_ROLE
  revision.value = ''
  preset.value = false
  preview.value = null
  editorError.value = ''
  open.value = true
}

async function runPreview(): Promise<void> {
  editorError.value = ''
  if (new Blob([yaml.value]).size > MAX_ROLE_YAML_BYTES) {
    editorError.value = 'The role definition is larger than 64 KiB.'
    return
  }
  busy.value = true
  try {
    preview.value = await rolesApi.preview(props.cluster.id, yaml.value, revision.value || undefined)
  } catch (e) {
    editorError.value = explain(e)
  } finally {
    busy.value = false
  }
}

async function apply(): Promise<void> {
  if (!preview.value?.valid) return
  if (isNew.value && !TELEPORT_NAME.test(name.value)) {
    editorError.value = 'Enter the role name (it must match metadata.name).'
    return
  }
  const ok = await confirm.ask({
    title: isNew.value ? `Create role ${name.value}?` : `Apply changes to ${name.value}?`,
    text: 'Teleport applies the role at once to every user who holds it.',
    confirmLabel: 'Apply',
    danger: !isNew.value,
  })
  if (!ok) return
  busy.value = true
  try {
    await rolesApi.put(props.cluster.id, name.value, yaml.value, revision.value || undefined)
    open.value = false
    notice.value = `Role ${name.value} saved.`
    void load()
  } catch (e) {
    if (e instanceof ApiError && e.reason === 'conflict') {
      editorError.value = isNew.value
        ? 'A role with this name already exists. Close the editor and open that role to change it.'
        : 'The role was changed in Teleport since you opened it. Reload to see the current definition; your edits are lost on reload.'
      return
    }
    editorError.value = explain(e)
  } finally {
    busy.value = false
  }
}
async function reload(): Promise<void> {
  await edit({ name: name.value, preset: preset.value, revision: '' })
}

async function remove(r: TeleportRole): Promise<void> {
  const ok = await confirm.ask({ title: `Delete role ${r.name}?`, text: 'Users holding it lose its access at once.', confirmLabel: 'Delete', danger: true })
  if (!ok) return
  try {
    await rolesApi.remove(props.cluster.id, r.name)
    notice.value = `Role ${r.name} deleted.`
    void load()
  } catch (e) {
    error.value = explain(e)
  }
}
</script>

<template>
  <div class="flex flex-col gap-4" data-test="roles-tab">
    <UiAlert v-if="error" kind="error" data-test="roles-error">{{ error }}</UiAlert>
    <UiAlert v-if="notice" kind="success" dismissible @close="notice = ''">{{ notice }}</UiAlert>
    <div class="flex justify-end">
      <UiButton v-if="can('create') && !cluster.writes_blocked" icon="mdi-plus" data-test="role-new" @click="create">New role</UiButton>
    </div>
    <UiCard :padded="false">
      <UiDataTable
        :items="items" :columns="columns" row-key="name" :loading="loading" :has-more="!!next" caption="Teleport roles — select one to view its definition"
        clickable empty-title="No roles" data-test="roles-table" @row-click="edit($event)" @load-more="load(true)"
      >
        <template #cell-name="{ row }">
          <span class="font-mono">{{ row.name }}</span>
          <UiBadge v-if="row.preset" color="neutral" class="ml-2" :data-test="'role-preset-' + row.name">built-in</UiBadge>
        </template>
        <template #cell-actions="{ row }">
          <div class="flex justify-end">
            <UiButton
              v-if="can('delete') && !row.preset && !cluster.writes_blocked" size="sm" variant="text" color="error" icon="mdi-delete-outline" icon-only label="Delete"
              :data-test="'role-delete-' + row.name" @click.stop="remove(row)"
            />
          </div>
        </template>
      </UiDataTable>
    </UiCard>

    <UiDialog v-model="open" :title="isNew ? 'New role' : `Role ${name}`" size="xl" persistent data-test="role-editor">
      <div class="flex flex-col gap-4">
        <UiAlert v-if="editorError" kind="error" data-test="role-editor-error">
          {{ editorError }}
          <UiButton v-if="!isNew && editorError.includes('changed in Teleport')" size="sm" variant="soft" class="ml-2" @click="reload">Reload</UiButton>
        </UiAlert>
        <UiAlert v-if="preset" kind="info">This is a Teleport built-in role. It can be edited but not deleted.</UiAlert>
        <UiInput v-if="isNew" id="role-name" v-model="name" label="Role name" required hint="Must match metadata.name in the definition." data-test="role-name" />
        <UiTextarea id="role-yaml" v-model="yaml" label="Definition (YAML)" :rows="18" :disabled="!can('update')" class="font-mono" data-test="role-yaml" @update:model-value="preview = null" />
        <template v-if="preview">
          <UiAlert v-if="!preview.valid" kind="error" data-test="role-preview-errors">
            <span v-for="(e, i) in preview.errors" :key="i" class="block">{{ e }}</span>
          </UiAlert>
          <RoleDiff :diff="preview.diff" />
        </template>
      </div>
      <template #actions>
        <UiButton variant="text" @click="open = false">Close</UiButton>
        <template v-if="can('update') && !cluster.writes_blocked">
          <UiButton variant="soft" :loading="busy" icon="mdi-file-search-outline" data-test="role-preview" @click="runPreview">Preview changes</UiButton>
          <UiButton :disabled="!preview?.valid || !preview.diff" :loading="busy" data-test="role-apply" @click="apply">Apply</UiButton>
        </template>
      </template>
    </UiDialog>
  </div>
</template>
