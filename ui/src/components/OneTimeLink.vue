<script setup lang="ts">
// A one-time invite or reset link: shown once, copyable, with its expiry.
// The parent holds the URL only while its dialog is open and clears it on
// close; it is never written to a store, the URL or browser storage.
import { UiAlert, UiCopyButton } from '@go-tangra/ui'
import { formatTime } from '@/pages/clusters/status'

defineProps<{ url: string; expiresAt: string; kind: 'invite' | 'reset' }>()
</script>

<template>
  <div class="flex flex-col gap-3" data-test="one-time-link">
    <UiAlert kind="warning">
      This {{ kind === 'invite' ? 'sign-up' : 'reset' }} link is shown once. Copy it now and send it to the user over a trusted channel; it cannot be shown again.
    </UiAlert>
    <div class="bg-base-200 flex items-center gap-2 rounded p-2">
      <code class="grow break-all text-xs" data-test="one-time-url">{{ url }}</code>
      <UiCopyButton :value="url" label="Copy link" />
    </div>
    <p class="text-sm">Expires {{ formatTime(expiresAt) }}.</p>
  </div>
</template>
