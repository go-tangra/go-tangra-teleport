import type { RouteRecordRaw } from 'vue-router'
import '@/main.css'

// Routes mounted by the platform shell under their own error boundary.
// Provisioning is a cluster tab; the deployment wizard has its own page.
export const routes: RouteRecordRaw[] = [
  { path: '/teleport', name: 'teleport-clusters', component: () => import('@/pages/clusters/ClusterList.vue'), meta: { module: 'teleport' } },
  // Spec 003: a recorded SSH session in the portal player (?d=<duration s> when opened from the list).
  { path: '/teleport/clusters/:id/sessions/:sid/play', name: 'teleport-session-play', component: () => import('@/pages/clusters/SessionPlayer.vue'), meta: { module: 'teleport' } },
  // Spec 004: a brokered SSH terminal (?node=<node id>&login=<login>&host=<hostname>).
  { path: '/teleport/clusters/:id/terminal', name: 'teleport-terminal', component: () => import('@/pages/clusters/TerminalPage.vue'), meta: { module: 'teleport' } },
  { path: '/teleport/clusters/:id', name: 'teleport-cluster', component: () => import('@/pages/clusters/ClusterOverview.vue'), meta: { module: 'teleport' } },
  { path: '/teleport/alerts', name: 'teleport-alerts', component: () => import('@/pages/alerts/AlertRules.vue'), meta: { module: 'teleport' } },
  { path: '/teleport/audit', name: 'teleport-audit', component: () => import('@/pages/audit/ModuleAudit.vue'), meta: { module: 'teleport' } },
  { path: '/teleport/deployments', name: 'teleport-deployments', component: () => import('@/pages/deployments/DeploymentWizard.vue'), meta: { module: 'teleport' } },
]
export default routes
