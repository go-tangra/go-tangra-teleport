<script setup lang="ts">
// Picks an active tenant member to provision (GET
// /clusters/{id}/provisioning/members?q=): display name and sign-in login.
// The list is searched as the user types (debounced 250 ms) and loads right
// away; the chosen member stays shown even when a later search no longer
// lists it. The value is the tangra user id.
import { computed, onBeforeUnmount, ref } from 'vue'
import { UiCombobox, type SelectOption } from '@go-tangra/ui'
import { explain } from '@/api/client'
import type { MemberCandidate } from '@/api/types'
import { memberTitle, membersApi } from '@/stores/provisioning'

const props = withDefaults(defineProps<{
  id: string
  clusterId: string
  label: string
  modelValue?: unknown
  error?: string | undefined
  required?: boolean | undefined
}>(), { modelValue: () => '', error: '', required: false })
const emit = defineEmits<{ (e: 'update:modelValue', v: string): void }>()

const found = ref<MemberCandidate[]>([])
const known = new Map<string, MemberCandidate>()
const failure = ref('')
let timer: ReturnType<typeof setTimeout> | null = null
let seq = 0

async function search(q: string): Promise<void> {
  const mine = ++seq
  try {
    const { items } = await membersApi.search(props.clusterId, q)
    if (mine !== seq) return
    for (const m of items) known.set(m.user_id, m)
    found.value = items
    failure.value = ''
  } catch (e) {
    if (mine === seq) failure.value = explain(e)
  }
}
function onSearch(q: string): void {
  if (timer) clearTimeout(timer)
  timer = setTimeout(() => void search(q.trim().slice(0, 100)), 250)
}
onBeforeUnmount(() => { if (timer) clearTimeout(timer) })
void search('')

const value = computed(() => (typeof props.modelValue === 'string' ? props.modelValue : ''))
const options = computed<SelectOption[]>(() => {
  const out = found.value.map((m) => ({ title: memberTitle(m), value: m.user_id }))
  if (value.value && !out.some((o) => o.value === value.value)) {
    const m = known.get(value.value)
    out.unshift({ title: m ? memberTitle(m) : value.value, value: value.value })
  }
  return out
})

function pick(v: unknown): void {
  emit('update:modelValue', typeof v === 'string' ? v : '')
}
</script>

<template>
  <UiCombobox
    :id="id"
    :model-value="value"
    :label="label"
    :options="options"
    :required="required"
    :error="error || failure || undefined"
    placeholder="Search by name or e-mail"
    @search="onSearch"
    @update:model-value="pick"
  />
</template>
