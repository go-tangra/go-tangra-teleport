<script setup lang="ts">
// Issue a join token for one resource type and show, once, the install
// command (or config snippet) that enrols the host. The values are held
// only in this component and cleared when the dialog closes; the server
// keeps a fingerprint of the token and cannot show it again.
import { computed, ref, watch } from 'vue'
import { UiAlert, UiButton, UiDialog, UiNumberInput, UiSelect } from '@go-tangra/ui'
import { explain } from '@/api/client'
import { tokensApi } from '@/stores/resources'
import type { Cluster, ResourceKind, TokenCreated } from '@/api/types'
import { formatTime } from '@/pages/clusters/status'

const props = defineProps<{ cluster: Cluster }>()
const open = defineModel<boolean>({ required: true })
const emit = defineEmits<{ issued: [] }>()

const kind = ref<ResourceKind>('node')
const ttl = ref(30)
const busy = ref(false)
const error = ref('')
const issued = ref<TokenCreated | null>(null)
const copied = ref('')

const kinds = [
  { title: 'Server (SSH)', value: 'node' },
  { title: 'Application', value: 'app' },
  { title: 'Database', value: 'db' },
  { title: 'Kubernetes cluster', value: 'kube' },
  { title: 'Windows desktop', value: 'desktop' },
]
const needsConfig = computed(() => issued.value && (issued.value.resource_type === 'kube' || issued.value.resource_type === 'desktop'))

watch(open, (v) => {
  if (!v) {
    issued.value = null // one-time values never outlive the dialog
    copied.value = ''
    error.value = ''
  }
})

async function issue(): Promise<void> {
  busy.value = true
  error.value = ''
  try {
    issued.value = await tokensApi.create(props.cluster.id, { resource_type: kind.value, ttl_minutes: ttl.value })
    emit('issued')
  } catch (e) {
    error.value = explain(e)
  } finally {
    busy.value = false
  }
}

async function copy(what: 'command' | 'config'): Promise<void> {
  if (!issued.value) return
  await navigator.clipboard.writeText(what === 'command' ? issued.value.install_command : issued.value.config_snippet)
  copied.value = what
}
</script>

<template>
  <UiDialog v-model="open" title="Enroll a resource" data-test="enroll-dialog">
    <div class="flex flex-col gap-4">
      <UiAlert v-if="error" kind="error" data-test="enroll-error">{{ error }}</UiAlert>
      <template v-if="!issued">
        <UiSelect v-model="kind" label="Resource type" :options="kinds" :clearable="false" required data-test="enroll-kind" />
        <UiNumberInput v-model="ttl" label="Valid for (minutes)" :min="1" :max="1440" hint="Default 30 minutes, at most 24 hours." data-test="enroll-ttl" />
      </template>
      <template v-else>
        <UiAlert kind="warning" data-test="enroll-once">
          Copy these now: they are shown only once. The token expires {{ formatTime(issued.expires_at) }}.
        </UiAlert>
        <div v-if="!needsConfig">
          <div class="mb-1 font-medium">Run on the host</div>
          <pre class="overflow-x-auto rounded bg-surface-variant p-3 text-sm" data-test="enroll-command">{{ issued.install_command }}</pre>
          <UiButton size="sm" variant="text" icon="mdi-content-copy" data-test="enroll-copy-command" @click="copy('command')">
            {{ copied === 'command' ? 'Copied' : 'Copy command' }}
          </UiButton>
        </div>
        <div>
          <div class="mb-1 font-medium">{{ needsConfig ? 'Save as /etc/teleport.yaml, then run the command below' : 'Or configure the agent' }}</div>
          <pre class="overflow-x-auto rounded bg-surface-variant p-3 text-sm" data-test="enroll-config">{{ issued.config_snippet }}</pre>
          <UiButton size="sm" variant="text" icon="mdi-content-copy" data-test="enroll-copy-config" @click="copy('config')">
            {{ copied === 'config' ? 'Copied' : 'Copy configuration' }}
          </UiButton>
          <pre v-if="needsConfig" class="mt-2 overflow-x-auto rounded bg-surface-variant p-3 text-sm">{{ issued.install_command }}</pre>
        </div>
      </template>
    </div>
    <template #actions>
      <UiButton variant="text" @click="open = false">{{ issued ? 'Done' : 'Cancel' }}</UiButton>
      <UiButton v-if="!issued" color="primary" :loading="busy" data-test="enroll-issue" @click="issue">Issue token</UiButton>
    </template>
  </UiDialog>
</template>
