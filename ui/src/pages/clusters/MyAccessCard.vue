<script setup lang="ts">
// The caller's own Teleport access on a cluster (spec 004): their
// provisioned Teleport user, roles and logins, and "Download access for
// tsh" (access:download). Explains the not-provisioned and MFA-required
// states, and (spec 005) a cluster whose access identity is missing or
// expired. Administrators (clusters:manage) set the access lifetime here.
import { computed, inject, onMounted, ref } from 'vue'
import { ABILITY_TOKEN } from '@casl/vue'
import type { AnyAbility } from '@casl/ability'
import { UiAlert, UiBadge, UiButton, UiCard, UiNumberInput } from '@go-tangra/ui'
import { ApiError, explain } from '@/api/client'
import type { Cluster, IssuedIdentity, MyAccess } from '@/api/types'
import { accessApi, tshCommand } from '@/stores/access'
import { formatTime } from './status'

const props = defineProps<{ cluster: Cluster }>()
const ability = inject<AnyAbility | null>(ABILITY_TOKEN, null)
const canAccess = computed(() => (ability ? ability.can('terminal', 'TeleportAccess') : true))
const canDownload = computed(() => (ability ? ability.can('download', 'TeleportAccess') : true))
const canManage = computed(() => (ability ? ability.can('update', 'TeleportCluster') : true))

const mine = ref<MyAccess | null>(null)
const state = ref<'loading' | 'ready' | 'not_provisioned' | 'error'>('loading')
const error = ref('')
const downloading = ref(false)
const issued = ref<IssuedIdentity | null>(null)
const ttl = ref<number | null>(null)
const saving = ref(false)
const notice = ref('')

async function load(): Promise<void> {
  if (!canAccess.value) return
  state.value = 'loading'
  error.value = ''
  try {
    mine.value = await accessApi.mine(props.cluster.id)
    ttl.value = mine.value.settings.access_ttl_minutes
    state.value = 'ready'
  } catch (e) {
    if (e instanceof ApiError && e.reason === 'not_provisioned') state.value = 'not_provisioned'
    else {
      state.value = 'error'
      error.value = explain(e)
    }
  }
}
onMounted(() => void load())

async function download(): Promise<void> {
  downloading.value = true
  error.value = ''
  try {
    issued.value = await accessApi.download(props.cluster.id)
  } catch (e) {
    error.value = explain(e)
  } finally {
    downloading.value = false
  }
}

async function saveTTL(): Promise<void> {
  if (!ttl.value) return
  saving.value = true
  notice.value = ''
  error.value = ''
  try {
    const s = await accessApi.putSettings(props.cluster.id, { access_ttl_minutes: ttl.value })
    if (mine.value) mine.value.settings = s
    notice.value = 'Access lifetime saved.'
  } catch (e) {
    error.value = explain(e)
  } finally {
    saving.value = false
  }
}

const command = computed(() => (issued.value ? tshCommand(issued.value.filename, props.cluster.proxy_addr, mine.value?.logins[0], '<node>') : ''))
const hours = (m: number) => (m % 60 === 0 ? `${m / 60} h` : `${m} min`)
</script>

<template>
  <UiCard v-if="canAccess || canManage" title="My Teleport access" subtitle="Your own provisioned Teleport user on this cluster" data-test="my-access">
    <div class="flex flex-col gap-3">
      <UiAlert v-if="error" kind="error" data-test="my-access-error">{{ error }}</UiAlert>
      <UiAlert v-if="notice" kind="success" dismissible @close="notice = ''">{{ notice }}</UiAlert>
      <p v-if="canAccess && state === 'loading'" class="text-sm opacity-70">Loading…</p>
      <UiAlert v-else-if="canAccess && state === 'not_provisioned'" kind="info" data-test="my-access-not-provisioned">
        You have no Teleport user on this cluster. Ask an administrator to provision you (Provisioning tab).
      </UiAlert>
      <template v-else-if="mine && state === 'ready'">
        <div class="flex flex-wrap items-center gap-2 text-sm">
          <span>Teleport user <span class="font-mono" data-test="my-access-user">{{ mine.teleport_user }}</span></span>
          <UiBadge v-for="r in mine.roles" :key="r" color="neutral">{{ r }}</UiBadge>
        </div>
        <div class="text-sm" data-test="my-access-logins">
          Logins: <span v-if="mine.logins.length" class="font-mono">{{ mine.logins.join(', ') }}</span><span v-else class="opacity-70">none</span>
        </div>
        <UiAlert v-if="!mine.mfa" kind="warning" data-test="my-access-mfa">
          Your portal session did not use a second factor. Sign out and sign in again with MFA to open terminals or download access.
        </UiAlert>
        <UiAlert v-if="mine.access_identity === 'missing'" kind="warning" data-test="my-access-identity-missing">
          This cluster has no access identity for portal terminals yet, so terminals and downloads may be refused.
          {{ canManage ? 'Upload one in "Access identity for portal terminals" below.' : 'Ask an administrator to set it up.' }}
        </UiAlert>
        <UiAlert v-else-if="mine.access_identity === 'expired'" kind="error" data-test="my-access-identity-expired">
          This cluster's access identity has expired, so terminals and downloads are refused.
          {{ canManage ? 'Sign in as tangra-access again and replace it below.' : 'Ask an administrator to renew it.' }}
        </UiAlert>
        <p class="text-sm opacity-70">
          Open a terminal from the Resources tab. Access lasts {{ hours(mine.settings.access_ttl_minutes) }} (Teleport may shorten it).
        </p>
        <div v-if="canDownload && mine.can_download" class="flex flex-wrap items-center gap-2">
          <UiButton icon="mdi-download" :loading="downloading" :disabled="!mine.mfa" data-test="my-access-download" @click="download()">Download access for tsh</UiButton>
        </div>
        <div v-if="issued" class="flex flex-col gap-1 text-sm" data-test="my-access-issued">
          <span>Saved <span class="font-mono">{{ issued.filename }}</span>, valid until {{ formatTime(issued.expires_at) }}. Keep it private and delete it when you are done.</span>
          <code class="block overflow-x-auto rounded bg-base-200 p-2 font-mono text-xs" data-test="my-access-command">{{ command }}</code>
        </div>
      </template>
      <div v-if="canManage" class="flex flex-wrap items-end gap-2 border-t border-base-300 pt-3" data-test="access-settings">
        <UiNumberInput id="access-ttl" :model-value="ttl" label="Access lifetime (minutes)" :min="15" :max="720" class="w-56" data-test="access-ttl" @update:model-value="(v: unknown) => (ttl = Number(v) || null)" />
        <UiButton variant="soft" :loading="saving" :disabled="!ttl || ttl < 15 || ttl > 720" data-test="access-ttl-save" @click="saveTTL()">Save</UiButton>
        <span class="text-xs opacity-70">15 to 720 minutes; default 480.</span>
      </div>
    </div>
  </UiCard>
</template>
