<script setup lang="ts">
// One cluster's health: status and its reason, version and edition, the
// credential's identity and expiry, last successful contact, object counts
// and the read grants the identity lacks (research D3). Actions: check now,
// rotate the credential, edit name and alerts, and remove (with a
// confirmation: the Teleport cluster itself is never changed). Tabs open the
// cluster's users, roles and locks (US2) for callers allowed to read them.
// Teleport-supplied text is rendered as text only.
import { computed, inject, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ABILITY_TOKEN } from '@casl/vue'
import type { AnyAbility } from '@casl/ability'
import { UiPage, UiAlert, UiCard, UiButton, UiBadge, UiKeyValueTable, UiStatGrid, UiStatTile, UiStatusChip, UiSkeleton, UiDialog, UiForm, UiInput, UiNumberInput, UiSwitch, UiTabs, useConfirm, type KeyValue, type TabItem } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { explain } from '@/api/client'
import { useClusters } from '@/stores/clusters'
import { updateSchema } from '@/schemas'
import type { Cluster } from '@/api/types'
import RegisterClusterDialog from './RegisterClusterDialog.vue'
import MyAccessCard from './MyAccessCard.vue'
import AccessIdentityCard from './AccessIdentityCard.vue'
import UsersTab from './tabs/UsersTab.vue'
import RolesTab from './tabs/RolesTab.vue'
import LocksTab from './tabs/LocksTab.vue'
import ResourcesTab from './tabs/ResourcesTab.vue'
import TokensTab from './tabs/TokensTab.vue'
import EventsTab from './tabs/EventsTab.vue'
import SessionsTab from './tabs/SessionsTab.vue'
import ProvisioningTab from './tabs/ProvisioningTab.vue'
import { STATUS_COLORS, STATUS_LABELS, expiryText, formatTime } from './status'

const route = useRoute()
const router = useRouter()
const store = useClusters()
const confirm = useConfirm()
const ability = inject<AnyAbility | null>(ABILITY_TOKEN, null)
const can = (action: string) => (ability ? ability.can(action, 'TeleportCluster') : true)
const canRead = (subject: string) => (ability ? ability.can('read', subject) : true)

const tab = ref('overview')
const tabs = computed<TabItem[]>(() => [
  { key: 'overview', label: 'Overview', icon: 'mdi-pulse' },
  ...(canRead('TeleportUser') ? [{ key: 'users', label: 'Users', icon: 'mdi-account-multiple-outline' }] : []),
  ...(canRead('TeleportRole') ? [{ key: 'roles', label: 'Roles', icon: 'mdi-shield-account' }] : []),
  ...(canRead('TeleportLock') ? [{ key: 'locks', label: 'Locks', icon: 'mdi-lock-outline' }] : []),
  ...(canRead('TeleportResource') ? [{ key: 'resources', label: 'Resources', icon: 'mdi-server-network' }] : []),
  ...(!ability || ability.can('manage', 'TeleportToken') ? [{ key: 'tokens', label: 'Join tokens', icon: 'mdi-key-variant' }] : []),
  ...(canRead('TeleportAudit') ? [{ key: 'events', label: 'Events', icon: 'mdi-file-search-outline' }] : []),
  ...(canRead('TeleportAudit') ? [{ key: 'sessions', label: 'Sessions', icon: 'mdi-play-circle-outline' }] : []),
  ...(canRead('TeleportManagedUser') ? [{ key: 'provisioning', label: 'Provisioning', icon: 'mdi-sync' }] : []),
])

const id = computed(() => String(route.params.id ?? ''))
const cluster = ref<Cluster | null>(null)
const error = ref('')
const notice = ref('')
const checking = ref(false)
const rotating = ref(false)
const editing = ref(false)

async function load(): Promise<void> {
  error.value = ''
  try {
    cluster.value = await store.get(id.value)
  } catch (e) {
    error.value = explain(e)
  }
}
onMounted(() => void load())

async function checkNow(): Promise<void> {
  checking.value = true
  notice.value = ''
  try {
    cluster.value = await store.check(id.value)
    notice.value = 'Health check finished.'
  } catch (e) {
    error.value = explain(e)
  } finally {
    checking.value = false
  }
}

async function remove(): Promise<void> {
  const c = cluster.value
  if (!c) return
  const ok = await confirm.ask({
    title: `Remove ${c.display_name}?`,
    text: 'The registration, its resource links and role mappings and the stored credential are deleted. The Teleport cluster itself is not changed; delete the management user there if you no longer need it.',
    danger: true,
    confirmLabel: 'Remove',
  })
  if (!ok) return
  try {
    await store.remove(c.id)
    void router.push({ name: 'teleport-clusters' })
  } catch (e) {
    error.value = explain(e)
  }
}

const form = useZodForm(updateSchema, {
  onSubmit: (v) => store.update(id.value, { display_name: v.display_name, settings: { offline_threshold_minutes: v.offline_threshold_minutes, alerts_enabled: v.alerts_enabled } }),
  onSuccess: (c) => {
    cluster.value = c as Cluster
    editing.value = false
  },
})
function startEdit(): void {
  const c = cluster.value
  if (!c) return
  form.reset({ display_name: c.display_name, offline_threshold_minutes: c.settings.offline_threshold_minutes, alerts_enabled: c.settings.alerts_enabled })
  editing.value = true
}
async function saveEdit(): Promise<void> {
  try {
    await form.submit()
  } catch (e) {
    form.setServerError(explain(e))
  }
}

const details = computed<KeyValue[]>(() => {
  const c = cluster.value
  if (!c) return []
  return [
    { label: 'Teleport cluster', value: c.cluster_name || '—', copyable: !!c.cluster_name },
    { label: 'Proxy address', value: c.proxy_addr, copyable: true },
    { label: 'Version', value: c.server_version || '—' },
    { label: 'Edition', value: c.edition },
    { label: 'Management identity', value: c.credential_identity || '—' },
    { label: 'Credential expires', value: c.credential_expires_at ? `${formatTime(c.credential_expires_at)} (${expiryText(c)})` : '—' },
    { label: 'Last successful contact', value: formatTime(c.last_contact_at) },
    { label: 'Alerts', value: c.settings.alerts_enabled ? 'on' : 'off' },
  ]
})
const severity = computed(() => {
  const s = cluster.value?.status
  if (s === 'unreachable' || s === 'credential_invalid') return 'error'
  if (s === 'credential_expiring' || s === 'unsupported_version') return 'warning'
  return 'info'
})
</script>

<template>
  <UiPage :title="cluster?.display_name ?? 'Cluster'" subtitle="Teleport cluster health">
    <template #actions>
      <UiButton variant="text" icon="mdi-arrow-left" @click="router.push({ name: 'teleport-clusters' })">Clusters</UiButton>
      <UiButton variant="soft" icon="mdi-pulse" :loading="checking" :disabled="!cluster" data-test="cluster-check" @click="checkNow">Check now</UiButton>
      <UiButton v-if="can('rotate')" variant="soft" icon="mdi-autorenew" :disabled="!cluster" data-test="cluster-rotate" @click="rotating = true">Rotate credential</UiButton>
      <UiButton v-if="can('update')" variant="soft" icon="mdi-pencil" :disabled="!cluster" data-test="cluster-edit" @click="startEdit">Edit</UiButton>
      <UiButton v-if="can('delete')" color="error" variant="soft" icon="mdi-delete-outline" :disabled="!cluster" data-test="cluster-remove" @click="remove">Remove</UiButton>
    </template>
    <UiAlert v-if="error" kind="error" data-test="cluster-error">{{ error }}</UiAlert>
    <UiAlert v-if="notice" kind="success" dismissible @close="notice = ''">{{ notice }}</UiAlert>
    <UiSkeleton v-if="!cluster && !error" kind="card" />
    <UiTabs v-if="cluster" v-model="tab" :tabs="tabs" class="mb-4" data-test="cluster-tabs" />
    <UsersTab v-if="cluster && tab === 'users'" :cluster="cluster" />
    <RolesTab v-else-if="cluster && tab === 'roles'" :cluster="cluster" />
    <LocksTab v-else-if="cluster && tab === 'locks'" :cluster="cluster" />
    <ResourcesTab v-else-if="cluster && tab === 'resources'" :cluster="cluster" />
    <TokensTab v-else-if="cluster && tab === 'tokens'" :cluster="cluster" />
    <EventsTab v-else-if="cluster && tab === 'events'" :cluster="cluster" />
    <SessionsTab v-else-if="cluster && tab === 'sessions'" :cluster="cluster" />
    <ProvisioningTab v-else-if="cluster && tab === 'provisioning'" :cluster="cluster" />
    <div v-else-if="cluster" class="flex flex-col gap-4">
      <UiCard>
        <div class="flex flex-wrap items-center gap-3">
          <UiStatusChip :status="cluster.status" :label="STATUS_LABELS[cluster.status]" :colors="STATUS_COLORS" data-test="cluster-status" />
          <UiBadge v-if="cluster.writes_blocked" color="warning">changes blocked until upgraded</UiBadge>
          <UiBadge :color="cluster.edition === 'enterprise' ? 'accent' : 'neutral'">{{ cluster.edition }}</UiBadge>
        </div>
        <UiAlert v-if="cluster.status_reason" :kind="severity" class="mt-3" data-test="cluster-status-reason">{{ cluster.status_reason }}</UiAlert>
      </UiCard>
      <UiStatGrid :cols="4" data-test="cluster-counts">
        <UiStatTile title="Users" :value="cluster.counts.users" icon="mdi-account-multiple-outline" />
        <UiStatTile title="Roles" :value="cluster.counts.roles" icon="mdi-shield-account" />
        <UiStatTile title="Servers" :value="cluster.counts.nodes" icon="mdi-server" />
        <UiStatTile title="Apps, databases, Kubernetes, desktops" :value="cluster.counts.apps + cluster.counts.dbs + cluster.counts.kube + cluster.counts.desktops" icon="mdi-view-module-outline" />
      </UiStatGrid>
      <UiCard title="Details">
        <UiKeyValueTable :items="details" :columns="2" />
      </UiCard>
      <MyAccessCard :cluster="cluster" />
      <AccessIdentityCard :cluster="cluster" />
      <UiCard title="Missing permissions" subtitle="Read grants of the tangra-manager role this identity lacks">
        <p v-if="cluster.missing_permissions.length === 0" class="text-sm" data-test="cluster-permissions-ok">None — the identity can read everything the module needs.</p>
        <div v-else class="flex flex-wrap gap-2" data-test="cluster-permissions-missing">
          <UiBadge v-for="p in cluster.missing_permissions" :key="p" color="warning"><span class="font-mono">{{ p }}</span></UiBadge>
        </div>
      </UiCard>
    </div>

    <RegisterClusterDialog v-if="cluster" v-model="rotating" :cluster="cluster" @saved="cluster = $event" />
    <UiDialog v-model="editing" title="Edit cluster" data-test="cluster-edit-dialog">
      <UiForm :form="form">
        <div class="flex flex-col gap-4">
          <UiAlert v-if="form.serverError.value" kind="error">{{ form.serverError.value }}</UiAlert>
          <UiInput v-bind="form.field('display_name')" label="Name" required />
          <UiNumberInput v-bind="form.field('offline_threshold_minutes')" label="Resource offline after (minutes)" :min="5" :max="1440" required />
          <UiSwitch v-bind="form.field('alerts_enabled')" label="Notify about outages and credential expiry" />
        </div>
      </UiForm>
      <template #actions>
        <UiButton variant="text" @click="editing = false">Cancel</UiButton>
        <UiButton :loading="form.submitting.value" @click="saveEdit">Save</UiButton>
      </template>
    </UiDialog>
  </UiPage>
</template>
