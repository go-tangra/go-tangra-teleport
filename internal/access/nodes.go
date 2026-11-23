package access

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
)

// Node listing (R10): nodes are listed as the caller's Teleport user, with
// short-lived certificates that never leave the module, so Teleport's own
// RBAC decides what the caller sees. The result (never the certificates)
// is cached per tenant, caller and cluster for nodeCacheTTL.
const (
	listCertTTL  = 5 * time.Minute
	nodeCacheTTL = 60 * time.Second
)

// Node is a node the caller may open a terminal on.
type Node struct {
	Name     string            `json:"name"`
	Hostname string            `json:"hostname"`
	Labels   map[string]string `json:"labels"`
	Logins   []string          `json:"logins"`
}

type nodeEntry struct {
	at    time.Time
	nodes []Node
}

type nodeCache struct {
	mu sync.Mutex
	m  map[string]nodeEntry // tenant|user|cluster
}

func (c *nodeCache) get(key string, now time.Time) ([]Node, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || now.Sub(e.at) >= nodeCacheTTL || now.Before(e.at) {
		return nil, false
	}
	return e.nodes, true
}

func (c *nodeCache) put(key string, now time.Time, nodes []Node) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]nodeEntry{}
	}
	for k, e := range c.m { // keep the cache small
		if now.Sub(e.at) >= nodeCacheTTL {
			delete(c.m, k)
		}
	}
	c.m[key] = nodeEntry{at: now, nodes: nodes}
}

// forget drops every cached listing of a cluster.
func (c *nodeCache) forget(clusterID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.m {
		if len(k) >= len(clusterID) && k[len(k)-len(clusterID):] == clusterID {
			delete(c.m, k)
		}
	}
}

// Nodes lists the nodes the caller's Teleport user can reach
// (access:terminal, MFA: it issues certificates).
func (s *Service) Nodes(ctx context.Context, clusterID string) ([]Node, error) {
	g, err := s.Resolve(ctx, clusterID, authz.AccessTerminal, true)
	if err != nil {
		return nil, err
	}
	key := g.Subject.TenantID + "|" + g.Subject.UserID + "|" + g.Cluster.ID
	if nodes, ok := s.nodes.get(key, s.now()); ok {
		return cloneNodes(nodes), nil
	}
	certs, err := s.Issue(ctx, g, listCertTTL)
	if err != nil {
		return nil, err
	}
	defer certs.Drop()
	res, err := g.Client.ListNodesAs(ctx, certs)
	if err != nil {
		return nil, err
	}
	nodes := make([]Node, 0, len(res))
	for _, r := range res {
		if r.Kind != "" && r.Kind != teleportapi.KindNode {
			continue
		}
		labels := map[string]string{}
		for k, v := range r.Labels {
			labels[k] = v
		}
		nodes = append(nodes, Node{Name: r.Name, Hostname: r.Hostname, Labels: labels, Logins: nonNil(certs.Logins)})
	}
	slices.SortFunc(nodes, func(a, b Node) int {
		if a.Hostname != b.Hostname {
			return compare(a.Hostname, b.Hostname)
		}
		return compare(a.Name, b.Name)
	})
	s.nodes.put(key, s.now(), nodes)
	return cloneNodes(nodes), nil
}

func compare(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cloneNodes(in []Node) []Node {
	out := make([]Node, len(in))
	for i, n := range in {
		out[i] = n
		out[i].Logins = slices.Clone(n.Logins)
		out[i].Labels = make(map[string]string, len(n.Labels))
		for k, v := range n.Labels {
			out[i].Labels[k] = v
		}
	}
	return out
}
