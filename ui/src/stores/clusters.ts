import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, describe } from '@/api/client'
import type { Cluster, Page, RegisterCluster, RotateCredential, UpdateCluster } from '@/api/types'

/** Query values sent to GET /clusters (page/page_size/sort/order). */
export type ListQuery = Record<string, string | number | undefined>

/** Sort fields the cluster list accepts (server Spec clusters.ClusterList). */
export const CLUSTER_SORTABLE = ['display_name', 'status', 'created_at']

/**
 * The tenant's clusters: one server-side page at a time with the total.
 * The identity file goes out once in register/rotate and is never kept here.
 */
export const useClusters = defineStore('teleport-clusters', () => {
  const items = ref<Cluster[]>([])
  const total = ref(0)
  const loading = ref(false)
  const error = ref('')
  const query = ref<ListQuery>({})
  let seq = 0

  /** Loads a page (remembering q); resolves with the page the server returned or null. */
  async function list(q?: ListQuery): Promise<number | null> {
    if (q) query.value = { ...q }
    const mine = ++seq
    loading.value = true
    error.value = ''
    try {
      const res = await api<Page<Cluster>>('GET', 'clusters', undefined, { query: query.value })
      if (mine !== seq) return null
      items.value = res.items ?? []
      total.value = res.total ?? 0
      return res.page ?? null
    } catch (e) {
      if (mine === seq) error.value = describe(e)
      return null
    } finally {
      if (mine === seq) loading.value = false
    }
  }

  function replace(c: Cluster): Cluster {
    items.value = items.value.map((x) => (x.id === c.id ? c : x))
    return c
  }

  const get = (id: string) => api<Cluster>('GET', 'clusters/' + id)
  /** Verifies the cluster first; nothing is stored when that fails. */
  const register = (body: RegisterCluster) => api<Cluster>('POST', 'clusters', body)
  const update = async (id: string, body: UpdateCluster) => replace(await api<Cluster>('PATCH', 'clusters/' + id, body))
  const rotate = async (id: string, body: RotateCredential) => replace(await api<Cluster>('POST', 'clusters/' + id + '/credential', body))
  /** Runs a health check now. */
  const check = async (id: string) => replace(await api<Cluster>('POST', 'clusters/' + id + '/check'))
  /** Removes the registration and its stored credential; Teleport is untouched. */
  const remove = (id: string) => api('DELETE', 'clusters/' + id)

  return { items, total, loading, error, query, list, reload: () => list(), get, register, update, rotate, check, remove }
})
