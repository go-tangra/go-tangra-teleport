<script setup lang="ts">
// The cluster's access identity (spec 005): the sign-in identity of the
// Teleport user tangra-access that portal terminals and tsh downloads are
// issued with. Shows its state and expiry (clusters:read) and, for
// administrators (clusters:manage), upload/replace/remove and the exact
// tsh login command. The file is read once, sent once and dropped.
import { computed, inject, onMounted, ref } from 'vue'
import { ABILITY_TOKEN } from '@casl/vue'
import type { AnyAbility } from '@casl/ability'
import { UiAlert, UiBadge, UiButton, UiCard, UiFilePicker, useConfirm } from '@go-tangra/ui'
import { explain } from '@/api/client'
import type { AccessIdentity, AccessIdentityState, Cluster } from '@/api/types'
import { MAX_IDENTITY_BYTES } from '@/schemas'
import { accessApi, accessLoginCommand } from '@/stores/access'
import { formatTime } from './status'

const props = defineProps<{ cluster: Cluster }>()
const ability = inject<AnyAbility | null>(ABILITY_TOKEN, null)
const canRead = computed(() => (ability ? ability.can('read', 'TeleportCluster') : true))
const canManage = computed(() => (ability ? ability.can('update', 'TeleportCluster') : true))
const confirm = useConfirm()

const STATE: Record<AccessIdentityState, { label: string; color: 'success' | 'warning' | 'error' | 'neutral' }> = {
  ok: { label: 'valid', color: 'success' },
  expiring: { label: 'expiring soon', color: 'warning' },
  expired: { label: 'expired', color: 'error' },
  missing: { label: 'not set up', color: 'neutral' },
}

const view = ref<AccessIdentity | null>(null)
const error = ref('')
const notice = ref('')
const uploading = ref(false)
const file = ref<File | null>(null)
const fileError = ref('')

const command = computed(() => accessLoginCommand(props.cluster.proxy_addr))

async function load(): Promise<void> {
  error.value = ''
  try {
    view.value = await accessApi.accessIdentity(props.cluster.id)
  } catch (e) {
    error.value = explain(e)
  }
}
onMounted(() => {
  if (canRead.value) void load()
})

async function onFile(f: File | null): Promise<void> {
  file.value = f
  fileError.value = ''
  if (!f) return
  uploading.value = true
  error.value = ''
  notice.value = ''
  try {
    const replacing = !!view.value?.configured
    const v = await accessApi.putAccessIdentity(props.cluster.id, await f.text())
    view.value = v
    notice.value =
      (replacing ? 'Access identity replaced.' : 'Access identity saved.') +
      (v.impersonation_checked === false ? ' No user is provisioned yet, so impersonation could not be tried.' : '') +
      ' Delete the local file.'
  } catch (e) {
    error.value = explain(e)
  } finally {
    uploading.value = false
    file.value = null
  }
}

async function remove(): Promise<void> {
  const ok = await confirm.ask({
    title: 'Remove the access identity?',
    text: 'Portal terminals and tsh downloads stop working on this cluster until a new one is uploaded. Open terminals keep running.',
    confirmLabel: 'Remove',
    danger: true,
  })
  if (!ok) return
  error.value = ''
  notice.value = ''
  try {
    await accessApi.deleteAccessIdentity(props.cluster.id)
    notice.value = 'Access identity removed.'
    await load()
  } catch (e) {
    error.value = explain(e)
  }
}
</script>

<template>
  <UiCard v-if="canRead" title="Access identity for portal terminals" subtitle="The tangra-access sign-in that terminals and tsh downloads are issued with" data-test="access-identity">
    <div class="flex flex-col gap-3">
      <UiAlert v-if="error" kind="error" data-test="access-identity-error">{{ error }}</UiAlert>
      <UiAlert v-if="notice" kind="success" dismissible data-test="access-identity-notice" @close="notice = ''">{{ notice }}</UiAlert>
      <div v-if="view" class="flex flex-wrap items-center gap-2 text-sm">
        <UiBadge :color="STATE[view.state].color" data-test="access-identity-state">{{ STATE[view.state].label }}</UiBadge>
        <template v-if="view.configured">
          <span>Teleport user <span class="font-mono" data-test="access-identity-user">{{ view.teleport_user }}</span></span>
          <span v-if="view.expires_at" data-test="access-identity-expires">{{ view.state === 'expired' ? 'expired' : 'expires' }} {{ formatTime(view.expires_at) }}</span>
        </template>
      </div>
      <UiAlert v-if="view && view.state === 'missing'" kind="info" data-test="access-identity-missing">
        Without it, portal terminals and tsh downloads are refused on this cluster.
      </UiAlert>
      <UiAlert v-else-if="view && view.state === 'expired'" kind="error" data-test="access-identity-expired">
        Portal terminals and tsh downloads are refused until it is replaced.
      </UiAlert>
      <template v-if="canManage">
        <div class="flex flex-col gap-1 text-sm" data-test="access-identity-howto">
          <span>
            On a host with tctl, create the <span class="font-mono">tangra-access</span> role and user once (see the deployment wizard's
            <span class="font-mono">tangra-access-role.yaml</span>), finish its invite with a password and a second factor, then sign in and
            upload the file:
          </span>
          <code class="block overflow-x-auto rounded bg-base-200 p-2 font-mono text-xs" data-test="access-identity-command">{{ command }}</code>
        </div>
        <div class="flex flex-wrap items-end gap-2">
          <UiFilePicker
            id="access-identity-file" :model-value="file" :label="view?.configured ? 'Replace with a new identity file' : 'Upload the identity file'"
            :max-bytes="MAX_IDENTITY_BYTES" :disabled="uploading" hint="At most 64 KiB. It is verified, stored in the secret store and never shown again."
            :error="fileError" data-test="access-identity-upload"
            @update:model-value="onFile" @too-large="fileError = 'The identity file is larger than 64 KiB.'"
          />
          <UiButton v-if="view?.configured" color="error" variant="soft" icon="mdi-delete-outline" data-test="access-identity-remove" @click="remove()">Remove</UiButton>
        </div>
      </template>
    </div>
  </UiCard>
</template>
