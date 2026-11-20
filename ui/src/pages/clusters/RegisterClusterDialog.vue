<script setup lang="ts">
// Register a cluster (name, proxy address, identity file) or rotate the
// credential of an existing one (identity file only). The identity file is
// read in the browser, sent once in the request and dropped from the form as
// soon as the dialog closes; the server verifies the cluster before it stores
// anything, so a refusal here means nothing was saved.
import { computed, ref, watch } from 'vue'
import { UiDialog, UiAlert, UiButton, UiInput, UiFilePicker, UiForm } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { explain } from '@/api/client'
import { useClusters } from '@/stores/clusters'
import { registerSchema, rotateSchema, MAX_IDENTITY_BYTES, type RegisterForm, type RotateForm } from '@/schemas'
import type { Cluster } from '@/api/types'

// proxyAddr and displayName prefill a registration (the deployment wizard's handover).
const props = defineProps<{ modelValue: boolean; cluster?: Cluster | null | undefined; proxyAddr?: string | undefined; displayName?: string | undefined }>()
const emit = defineEmits<{ (e: 'update:modelValue', v: boolean): void; (e: 'saved', c: Cluster): void }>()

const store = useClusters()
const rotating = computed(() => !!props.cluster)
const title = computed(() => (props.cluster ? `Rotate credential — ${props.cluster.display_name}` : 'Register cluster'))
const file = ref<File | null>(null)
const fileError = ref('')

const form = useZodForm(rotating.value ? rotateSchema : registerSchema, {
  onSubmit: async (v) => {
    if (props.cluster) return store.rotate(props.cluster.id, { credential_kind: 'identity_file', credential: (v as RotateForm).credential })
    const r = v as RegisterForm
    return store.register({ display_name: r.display_name, proxy_addr: r.proxy_addr, credential_kind: 'identity_file', credential: r.credential })
  },
  onSuccess: (c) => {
    emit('saved', c as Cluster)
    close()
  },
})
const serverError = computed(() => (form.serverError.value ? form.serverError.value : ''))

async function onFile(f: File | null): Promise<void> {
  file.value = f
  fileError.value = ''
  form.values.credential = f ? await f.text() : ''
  form.blur('credential')
}

function close(): void {
  // Drop the identity from memory with the dialog.
  form.reset()
  file.value = null
  fileError.value = ''
  emit('update:modelValue', false)
}
watch(
  () => props.modelValue,
  (open) => {
    if (!open) return form.reset()
    if (!props.cluster && props.proxyAddr) form.values.proxy_addr = props.proxyAddr
    if (!props.cluster && props.displayName) form.values.display_name = props.displayName
  },
)

async function save(): Promise<void> {
  try {
    await form.submit()
  } catch (e) {
    form.setServerError(explain(e))
  }
}
</script>

<template>
  <UiDialog :model-value="modelValue" :title="title" size="lg" persistent data-test="cluster-register" @update:model-value="!$event && close()">
    <UiForm :form="form">
      <div class="flex flex-col gap-4">
        <UiAlert v-if="serverError" kind="error" data-test="cluster-register-error">{{ serverError }}</UiAlert>
        <p class="text-base-content/80 text-sm">
          <template v-if="rotating">Upload a new identity for the same cluster. It is checked against the cluster before it replaces the current one.</template>
          <template v-else>The platform connects with the identity first and saves nothing if that fails. Create the identity with <code>tctl auth sign --format=file</code> for a user holding the <code>tangra-manager</code> role.</template>
        </p>
        <template v-if="!rotating">
          <UiInput v-bind="form.field('display_name')" label="Name" required placeholder="Production" data-test="cluster-name" />
          <UiInput v-bind="form.field('proxy_addr')" label="Proxy address" required placeholder="teleport.example.com:443" hint="The cluster's public proxy, host or host:port (port 443 by default)." data-test="cluster-proxy" />
        </template>
        <UiFilePicker
          id="cluster-identity" :model-value="file" label="Identity file" required :max-bytes="MAX_IDENTITY_BYTES"
          hint="At most 64 KiB. It is stored in the platform's secret store and never shown again."
          :error="fileError || form.errors.value.credential" data-test="cluster-identity"
          @update:model-value="onFile" @too-large="fileError = 'The identity file is larger than 64 KiB.'"
        />
      </div>
    </UiForm>
    <template #actions>
      <UiButton variant="text" data-test="cluster-register-cancel" @click="close">Cancel</UiButton>
      <UiButton :loading="form.submitting.value" icon="mdi-shield-check-outline" data-test="cluster-register-save" @click="save">{{ rotating ? 'Verify and rotate' : 'Verify and register' }}</UiButton>
    </template>
  </UiDialog>
</template>
