import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { ABILITY_TOKEN } from '@casl/vue'
import { createMongoAbility } from '@casl/ability'
import SessionsTab from '@/pages/clusters/tabs/SessionsTab.vue'
import { auditApi } from '@/stores/audit'
import type { Cluster, TeleportSession } from '@/api/types'

// Spec 003 US3/US4 (FR-007, FR-009): Play only on playable (SSH) sessions
// and only with the sessions:play ability; the Teleport link stays for all.
const cluster = { id: 'c1', display_name: 'prod', proxy_addr: 'tp.example.com:443', cluster_name: 'prod' } as Cluster
const session = (sid: string, kind: TeleportSession['kind'], playable: boolean): TeleportSession => ({
  sid, kind, playable, participants: ['alice'], user: 'alice', target: 'web-1', started_at: '2026-11-23T08:00:00Z', duration_s: 75,
  playback_url: `https://tp.example.com/web/cluster/prod/session/${sid}`,
})

async function render(rules: { action: string; subject: string }[] | null) {
  vi.spyOn(auditApi, 'sessions').mockResolvedValue({ items: [session('ssh-1', 'ssh', true), session('kube-1', 'kube', false), session('ssh-2', 'ssh', false)] })
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { template: '<div />' } },
      { path: '/teleport/clusters/:id/sessions/:sid/play', name: 'teleport-session-play', component: { template: '<div />' } },
    ],
  })
  await router.push('/')
  const provide = rules ? { [ABILITY_TOKEN as symbol]: createMongoAbility(rules) } : {}
  const w = mount(SessionsTab, { props: { cluster }, global: { plugins: [router], provide } })
  await flushPromises()
  return w
}

afterEach(() => vi.restoreAllMocks())

describe('SessionsTab', () => {
  it('offers Play on playable sessions to callers with sessions:play', async () => {
    const w = await render([{ action: 'read', subject: 'TeleportAudit' }, { action: 'play', subject: 'TeleportSession' }])
    const play = w.find('[data-test="session-player-ssh-1"]')
    expect(play.exists()).toBe(true)
    expect(play.attributes('href')).toBe('/teleport/clusters/c1/sessions/ssh-1/play?d=75')
    expect(w.find('[data-test="session-player-kube-1"]').exists()).toBe(false) // not SSH
    expect(w.find('[data-test="session-player-ssh-2"]').exists()).toBe(false) // not playable
    for (const sid of ['ssh-1', 'kube-1', 'ssh-2']) {
      const link = w.find(`[data-test="session-play-${sid}"]`)
      expect(link.exists()).toBe(true)
      expect(link.attributes('target')).toBe('_blank')
      expect(link.attributes('rel')).toContain('noopener')
    }
  })

  it('hides Play without sessions:play but keeps the Teleport links', async () => {
    const w = await render([{ action: 'read', subject: 'TeleportAudit' }])
    expect(w.findAll('[data-test^="session-player-"]')).toHaveLength(0)
    expect(w.findAll('[data-test^="session-play-"]')).toHaveLength(3)
  })
})
