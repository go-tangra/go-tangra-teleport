<script setup lang="ts">
// A unified diff of normalized role YAML (server-rendered), coloured per
// line. Rendered as text only: role content is never interpreted as HTML.
import { computed } from 'vue'

const props = defineProps<{ diff: string }>()
type Line = { text: string; kind: 'add' | 'del' | 'hunk' | 'meta' | 'ctx' }
const lines = computed<Line[]>(() =>
  props.diff
    .split('\n')
    .filter((l, i, all) => l !== '' || i < all.length - 1)
    .map((text) => {
      if (text.startsWith('+++') || text.startsWith('---')) return { text, kind: 'meta' }
      if (text.startsWith('@@')) return { text, kind: 'hunk' }
      if (text.startsWith('+')) return { text, kind: 'add' }
      if (text.startsWith('-')) return { text, kind: 'del' }
      return { text, kind: 'ctx' }
    }),
)
const CLASSES: Record<Line['kind'], string> = {
  add: 'bg-success/15 text-success-content',
  del: 'bg-error/15 text-error-content',
  hunk: 'text-info',
  meta: 'text-base-content/60',
  ctx: '',
}
</script>

<template>
  <p v-if="!diff" class="text-sm" data-test="role-diff-empty">No changes.</p>
  <pre v-else class="bg-base-200 max-h-96 overflow-auto rounded p-2 text-xs" data-test="role-diff"><code><span v-for="(l, i) in lines" :key="i" :class="['block whitespace-pre', CLASSES[l.kind]]">{{ l.text }}</span></code></pre>
</template>
