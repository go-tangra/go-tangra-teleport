<script setup lang="ts">
// The deployment wizard for a new Teleport Community Edition cluster (US6):
// 1. inputs (domain, certificate, version, first administrator) saved as a
//    draft; 2. the DNS, port and host checklist; 3. the generated artifacts
//    to download (rendered by the server, never stored); 4. prerequisite
//    checks run by the server through its SSRF guard; 5. "Register this
//    cluster" opens the registration dialog with the address filled in.
// Nothing is executed on the new host by tangra.
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { UiAlert, UiBadge, UiButton, UiCard, UiDataTable, UiForm, UiInput, UiPage, UiSelect, useConfirm, type Column } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { explain } from '@/api/client'
import { deploymentsApi } from '@/stores/deployments'
import { draftSchema } from '@/schemas'
import type { ArtifactName, Cluster, Draft, DraftCheck, DraftInput } from '@/api/types'
import RegisterClusterDialog from '../clusters/RegisterClusterDialog.vue'
import { formatTime } from '../clusters/status'

const router = useRouter()
const confirm = useConfirm()

const drafts = ref<Draft[]>([])
const draft = ref<Draft | null>(null)
const step = ref(1)
const error = ref('')
const notice = ref('')
const checking = ref(false)
const registering = ref(false)

async function load(): Promise<void> {
  try {
    drafts.value = (await deploymentsApi.list()).items
  } catch (e) {
    error.value = explain(e)
  }
}
onMounted(() => void load())

const STEPS = ['Inputs', 'Checklist', 'Artifacts', 'Checks', 'Register']

// ---- step 1: inputs
const certModes = [
  { title: 'Let’s Encrypt (ACME)', value: 'acme' },
  { title: 'My own certificate', value: 'own_cert' },
]
const form = useZodForm(draftSchema, {
  onSubmit: (v) => {
    const body: DraftInput = v
    return draft.value ? deploymentsApi.update(draft.value.id, { ...body, registered_cluster_id: draft.value.registered_cluster_id }) : deploymentsApi.create(body)
  },
  onSuccess: (d) => {
    draft.value = d as Draft
    step.value = 2
    void load()
  },
})
function startNew(): void {
  draft.value = null
  form.reset({ domain: '', cert_mode: 'acme', acme_email: '', teleport_version: '', admin_username: '', admin_logins: '' })
  step.value = 1
}
function open(d: Draft): void {
  draft.value = d
  form.reset({ domain: d.domain, cert_mode: d.cert_mode, acme_email: d.acme_email ?? '', teleport_version: d.teleport_version,
    admin_username: d.admin_username, admin_logins: d.admin_logins.join(', ') })
  step.value = d.registered_cluster_id ? 5 : 2
}
async function saveInputs(): Promise<void> {
  try {
    await form.submit()
  } catch (e) {
    form.setServerError(explain(e))
  }
}
const acme = computed(() => form.values.cert_mode === 'acme')

// ---- step 3: artifacts
const ARTIFACTS: Record<ArtifactName, string> = {
  'teleport.yaml': 'Teleport configuration (/etc/teleport.yaml)',
  'install.sh': 'Install script pinned to the chosen version',
  'tangra-manager-role.yaml': 'Least-privilege role tangra signs in with',
  'tangra-access-role.yaml': 'Role of the access identity for portal terminals (optional)',
  'setup-commands.txt': 'First administrator, management identity and access identity commands',
  'checklist.md': 'DNS, port and host checklist',
}

// ---- step 4: checks
const CHECK_LABELS: Record<DraftCheck['name'], string> = {
  dns_apex: 'The domain resolves',
  dns_wildcard: 'The wildcard record resolves',
  tls_443: 'Port 443 answers with a valid certificate',
}
const checkColumns: Column<DraftCheck>[] = [
  { key: 'name', label: 'Check', format: (c) => CHECK_LABELS[c.name] },
  { key: 'ok', label: 'Result' },
  { key: 'detail', label: 'Detail' },
  { key: 'checked_at', label: 'Checked', width: 'md', hideOnStack: true, format: (c) => formatTime(c.checked_at) },
]
const allPassed = computed(() => !!draft.value && draft.value.checks.length === 3 && draft.value.checks.every((c) => c.ok))
async function runChecks(): Promise<void> {
  if (!draft.value) return
  checking.value = true
  error.value = ''
  try {
    draft.value = await deploymentsApi.check(draft.value.id)
  } catch (e) {
    error.value = explain(e)
  } finally {
    checking.value = false
  }
}

// ---- step 5: handover to registration
async function onRegistered(c: Cluster): Promise<void> {
  if (!draft.value) return
  const d = draft.value
  try {
    draft.value = await deploymentsApi.update(d.id, {
      domain: d.domain, cert_mode: d.cert_mode, acme_email: d.acme_email, teleport_version: d.teleport_version,
      admin_username: d.admin_username, admin_logins: d.admin_logins, registered_cluster_id: c.id,
    })
  } catch (e) {
    error.value = explain(e)
  }
  void router.push({ name: 'teleport-cluster', params: { id: c.id } })
}

async function remove(d: Draft): Promise<void> {
  const ok = await confirm.ask({ title: 'Delete this draft?', text: `The wizard inputs for ${d.domain} are removed. A deployed cluster is not affected.`, confirmLabel: 'Delete', danger: true })
  if (!ok) return
  try {
    await deploymentsApi.remove(d.id)
    if (draft.value?.id === d.id) startNew()
    notice.value = 'Draft deleted.'
    void load()
  } catch (e) {
    error.value = explain(e)
  }
}

const draftColumns: Column<Draft>[] = [
  { key: 'domain', label: 'Domain' },
  { key: 'teleport_version', label: 'Version', width: 'sm' },
  { key: 'registered_cluster_id', label: 'Registered', width: 'sm', format: (d) => (d.registered_cluster_id ? 'yes' : 'no') },
  { key: 'updated_at', label: 'Updated', width: 'md', hideOnStack: true, format: (d) => formatTime(d.updated_at) },
  { key: 'actions', label: '', width: 'sm' },
]
startNew()
</script>

<template>
  <UiPage title="Deploy a new cluster" subtitle="Guided setup of a Teleport Community Edition cluster">
    <div class="flex flex-col gap-4" data-test="deployment-wizard">
      <UiAlert v-if="error" kind="error" data-test="wizard-error">{{ error }}</UiAlert>
      <UiAlert v-if="notice" kind="success" dismissible @close="notice = ''">{{ notice }}</UiAlert>

      <ol class="flex flex-wrap gap-2" aria-label="Wizard steps">
        <li v-for="(label, i) in STEPS" :key="label">
          <UiButton
            size="sm" :variant="step === i + 1 ? 'soft' : 'text'" :disabled="i > 0 && !draft" :aria-current="step === i + 1 ? 'step' : undefined"
            :data-test="'wizard-step-' + (i + 1)" @click="step = i + 1"
          >
            {{ i + 1 }}. {{ label }}
          </UiButton>
        </li>
      </ol>

      <!-- 1. Inputs -->
      <UiCard v-if="step === 1" title="Cluster inputs" data-test="wizard-inputs">
        <UiForm :form="form">
          <div class="flex flex-col gap-4">
            <UiAlert v-if="form.serverError.value" kind="error">{{ form.serverError.value }}</UiAlert>
            <UiInput v-bind="form.field('domain')" label="Cluster domain" required hint="For example teleport.example.com. Users reach the cluster here." data-test="wizard-domain" />
            <UiSelect v-bind="form.field('cert_mode')" label="Certificate" :options="certModes" :clearable="false" required data-test="wizard-cert" />
            <UiInput v-if="acme" v-bind="form.field('acme_email')" label="ACME contact e-mail" required hint="Let’s Encrypt sends expiry notices here." data-test="wizard-email" />
            <UiInput v-bind="form.field('teleport_version')" label="Teleport version" required hint="The exact release to install, for example 19.1.2." data-test="wizard-version" />
            <UiInput v-bind="form.field('admin_username')" label="First administrator" required data-test="wizard-admin" />
            <UiInput v-bind="form.field('admin_logins')" label="Administrator logins" required hint="Comma-separated host users, for example root, ubuntu." data-test="wizard-logins" />
            <div class="flex justify-end">
              <UiButton :loading="form.submitting.value" data-test="wizard-save" @click="saveInputs">Save and continue</UiButton>
            </div>
          </div>
        </UiForm>
      </UiCard>

      <!-- 2. Checklist -->
      <UiCard v-else-if="step === 2 && draft" title="Before you install" data-test="wizard-checklist">
        <ul class="list-disc pl-6 flex flex-col gap-1">
          <li>A Linux host with systemd, at least 2 vCPU and 1 GB of memory.</li>
          <li>DNS A records for <code>{{ draft.domain }}</code> and <code>*.{{ draft.domain }}</code> pointing to the host.</li>
          <li>TCP port 443 open to all sources.</li>
          <li v-if="draft.cert_mode === 'acme'">Port 443 reachable from the internet so Let’s Encrypt can issue the certificate.</li>
          <li v-else>A certificate for <code>{{ draft.domain }}</code> and <code>*.{{ draft.domain }}</code> in <code>/etc/teleport/tls/</code>.</li>
        </ul>
        <div class="flex justify-end mt-4"><UiButton data-test="wizard-next-2" @click="step = 3">Continue</UiButton></div>
      </UiCard>

      <!-- 3. Artifacts -->
      <UiCard v-else-if="step === 3 && draft" title="Download the artifacts" subtitle="Copy them to the new host and run install.sh as root" data-test="wizard-artifacts">
        <ul class="flex flex-col gap-2">
          <li v-for="a in draft.artifacts" :key="a" class="flex items-center justify-between gap-2">
            <span><code>{{ a }}</code> — {{ ARTIFACTS[a] }}</span>
            <a :href="deploymentsApi.artifactUrl(draft.id, a)" :download="a" :data-test="'wizard-artifact-' + a">Download</a>
          </li>
        </ul>
        <div class="flex justify-end mt-4"><UiButton data-test="wizard-next-3" @click="step = 4">Continue</UiButton></div>
      </UiCard>

      <!-- 4. Checks -->
      <template v-else-if="step === 4 && draft">
        <div class="flex justify-end gap-2">
          <UiButton icon="mdi-lan-connect" :loading="checking" data-test="wizard-run-checks" @click="runChecks">Run checks</UiButton>
          <UiButton variant="soft" :disabled="!allPassed" data-test="wizard-next-4" @click="step = 5">Continue</UiButton>
        </div>
        <UiCard :padded="false">
          <UiDataTable
            :items="draft.checks" :columns="checkColumns" row-key="name" caption="Prerequisite checks"
            empty-title="Not checked yet" empty-text="Run the checks once DNS is set up and Teleport is running." data-test="wizard-checks"
          >
            <template #cell-ok="{ row }">
              <UiBadge :color="row.ok ? 'success' : 'error'" :data-test="'check-' + row.name">{{ row.ok ? 'passed' : 'failed' }}</UiBadge>
            </template>
          </UiDataTable>
        </UiCard>
        <p class="text-sm">Checks run at most once every 10 seconds. Addresses on private, loopback, link-local and metadata networks are refused unless this deployment allows them.</p>
      </template>

      <!-- 5. Register -->
      <UiCard v-else-if="step === 5 && draft" title="Register this cluster" data-test="wizard-register">
        <p v-if="draft.registered_cluster_id">
          This cluster is registered.
          <UiButton variant="text" @click="router.push({ name: 'teleport-cluster', params: { id: draft.registered_cluster_id } })">Open it</UiButton>
        </p>
        <template v-else>
          <p>
            Follow <code>setup-commands.txt</code> to create the first administrator and the <code>tangra-mgmt</code> identity, then register
            the cluster with <code>{{ draft.proxy_addr }}</code> and the <code>tangra-mgmt.identity</code> file.
          </p>
          <div class="flex justify-end mt-4">
            <UiButton icon="mdi-plus-box-outline" data-test="wizard-register-open" @click="registering = true">Register this cluster</UiButton>
          </div>
        </template>
      </UiCard>

      <UiCard title="Drafts" :padded="false">
        <UiDataTable :items="drafts" :columns="draftColumns" row-key="id" caption="Deployment drafts" empty-title="No drafts yet" data-test="wizard-drafts">
          <template #cell-actions="{ row }">
            <div class="flex justify-end gap-1">
              <UiButton size="sm" variant="text" icon="mdi-open-in-new" icon-only label="Open draft" :data-test="'draft-open-' + row.id" @click="open(row)" />
              <UiButton size="sm" variant="text" icon="mdi-delete" icon-only label="Delete draft" :data-test="'draft-remove-' + row.id" @click="remove(row)" />
            </div>
          </template>
        </UiDataTable>
      </UiCard>
      <div class="flex justify-end"><UiButton variant="text" icon="mdi-plus" data-test="wizard-new" @click="startNew">New draft</UiButton></div>
    </div>
    <RegisterClusterDialog v-model="registering" :proxy-addr="draft?.proxy_addr" :display-name="draft?.domain" @saved="onRegistered" />
  </UiPage>
</template>
