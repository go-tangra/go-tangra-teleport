<script setup lang="ts">
// Join tokens issued from tangra for one cluster: who issued them, for
// what, and until when. Values are never listed. Revoking deletes the token
// in Teleport, which then refuses any join with it.
import { computed, onMounted, ref } from 'vue'
import { UiAlert, UiBadge, UiButton, UiCard, UiDataTable, useConfirm, type Column } from '@go-tangra/ui'
import { explain } from '@/api/client'
import { tokensApi } from '@/stores/resources'
import type { Cluster, JoinToken } from '@/api/types'
import { formatTime } from '../status'
import EnrollDialog from '@/components/EnrollDialog.vue'

const props = defineProps<{ cluster: Cluster }>()
const writable = computed(() => !props.cluster.writes_blocked)
const confirm = useConfirm()

const items = ref<JoinToken[]>([])
const loading = ref(false)
const error = ref('')
const notice = ref('')
const enrolling = ref(false)

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    items.value = (await tokensApi.list(props.cluster.id)).items
  } catch (e) {
    error.value = explain(e)
  } finally {
    loading.value = false
  }
}
onMounted(() => void load())

const state = (t: JoinToken) => (t.revoked ? 'revoked' : t.expired ? 'expired' : 'active')
const columns: Column<JoinToken>[] = [
  { key: 'resource_type', label: 'For' },
  { key: 'state', label: 'State', width: 'sm' },
  { key: 'created_by', label: 'Issued by', hideOnStack: true },
  { key: 'created_at', label: 'Issued', width: 'md', format: (t) => formatTime(t.created_at) },
  { key: 'expires_at', label: 'Expires', width: 'md', format: (t) => formatTime(t.expires_at) },
  { key: 'actions', label: '', width: 'sm' },
]

async function revoke(t: JoinToken): Promise<void> {
  const ok = await confirm.ask({ title: 'Revoke this token?', text: 'Teleport will refuse any later join with it.', confirmLabel: 'Revoke', danger: true })
  if (!ok) return
  try {
    await tokensApi.revoke(props.cluster.id, t.id)
    notice.value = 'Token revoked.'
    void load()
  } catch (e) {
    error.value = explain(e)
  }
}
</script>

<template>
  <div class="flex flex-col gap-4" data-test="tokens-tab">
    <UiAlert v-if="error" kind="error" data-test="tokens-error">{{ error }}</UiAlert>
    <UiAlert v-if="notice" kind="success" dismissible @close="notice = ''">{{ notice }}</UiAlert>
    <div class="flex justify-end">
      <UiButton v-if="writable" color="primary" icon="mdi-plus" data-test="token-new" @click="enrolling = true">Enroll</UiButton>
    </div>
    <UiCard :padded="false">
      <UiDataTable :items="items" :columns="columns" row-key="id" :loading="loading" caption="Join tokens" empty-title="No join tokens" data-test="tokens-table">
        <template #cell-state="{ row }">
          <UiBadge :color="state(row) === 'active' ? 'success' : 'default'">{{ state(row) }}</UiBadge>
        </template>
        <template #cell-actions="{ row }">
          <div class="flex justify-end">
            <UiButton v-if="writable && state(row) === 'active'" size="sm" variant="text" icon="mdi-cancel" icon-only label="Revoke token" :data-test="'token-revoke-' + row.id" @click="revoke(row)" />
          </div>
        </template>
      </UiDataTable>
    </UiCard>
    <EnrollDialog v-model="enrolling" :cluster="cluster" @issued="load" />
  </div>
</template>
