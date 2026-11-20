// Package enrolltest is an in-memory inventory TeleportJoinDeliveryService
// for the enrollment tests: hosts per tenant, refusals by host, joins whose
// state the test moves with Set, and an outage switch.
package enrolltest

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	inventoryv1 "github.com/go-tangra/go-tangra-inventory/sdk/v4/api/proto/inventory/v1"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/enroll"
)

// Inventory is the fake. The zero value is not usable: call New.
type Inventory struct {
	mu      sync.Mutex
	hosts   map[string]map[string]*inventoryv1.TeleportJoinTarget // tenant → host id → host
	refuse  map[string]string                                     // host id → reason token
	joins   map[string]*inventoryv1.TeleportJoin                  // enrollment id → join
	order   []string
	down    bool
	calls   map[string]int
	lastReq *inventoryv1.CreateTeleportJoinRequest
}

var _ inventoryv1.TeleportJoinDeliveryServiceClient = (*Inventory)(nil)

// New builds an empty fake.
func New() *Inventory {
	return &Inventory{hosts: map[string]map[string]*inventoryv1.TeleportJoinTarget{}, refuse: map[string]string{},
		joins: map[string]*inventoryv1.TeleportJoin{}, calls: map[string]int{}}
}

// Dial is an enroll.Inventory returning the fake.
func (f *Inventory) Dial() enroll.Inventory {
	return func(context.Context) (inventoryv1.TeleportJoinDeliveryServiceClient, error) { return f, nil }
}

// AddHost adds a host of tenant (Capability defaults to enabled).
func (f *Inventory) AddHost(tenant string, h *inventoryv1.TeleportJoinTarget) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if h.Capability == "" {
		h.Capability = "enabled"
	}
	if f.hosts[tenant] == nil {
		f.hosts[tenant] = map[string]*inventoryv1.TeleportJoinTarget{}
	}
	f.hosts[tenant][h.HostId] = h
}

// Refuse makes CreateTeleportJoin refuse host with reason.
func (f *Inventory) Refuse(host, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refuse[host] = reason
}

// SetDown switches the outage on or off.
func (f *Inventory) SetDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
}

// Set moves a join to state (with reason and node uuid).
func (f *Inventory) Set(enrollmentID string, st inventoryv1.TeleportJoinState, reason, node string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if j, ok := f.joins[enrollmentID]; ok {
		j.State, j.Reason, j.NodeHostUuid = st, reason, node
	}
}

// Forget drops a join (inventory no longer knows it).
func (f *Inventory) Forget(enrollmentID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.joins, enrollmentID)
}

// Join returns a copy of a join (nil when unknown).
func (f *Inventory) Join(enrollmentID string) *inventoryv1.TeleportJoin {
	f.mu.Lock()
	defer f.mu.Unlock()
	if j, ok := f.joins[enrollmentID]; ok {
		return clone(j)
	}
	return nil
}

// Calls returns how often method was called.
func (f *Inventory) Calls(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[method]
}

// LastCreate returns the last CreateTeleportJoin request.
func (f *Inventory) LastCreate() *inventoryv1.CreateTeleportJoinRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastReq
}

func (f *Inventory) enter(method string) error {
	f.calls[method]++
	if f.down {
		return status.Error(codes.Unavailable, "inventory down")
	}
	return nil
}

// CreateTeleportJoin implements the service.
func (f *Inventory) CreateTeleportJoin(_ context.Context, in *inventoryv1.CreateTeleportJoinRequest, _ ...grpc.CallOption) (*inventoryv1.TeleportJoin, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("CreateTeleportJoin"); err != nil {
		return nil, err
	}
	f.lastReq = in
	if j, ok := f.joins[in.EnrollmentId]; ok {
		c := clone(j)
		c.Created = false
		return c, nil
	}
	h, ok := f.hosts[in.TenantId][in.HostId]
	if !ok {
		return nil, status.Error(codes.NotFound, "host not found")
	}
	if r := f.refuse[in.HostId]; r != "" {
		return nil, status.Error(codes.FailedPrecondition, r)
	}
	for _, id := range f.order {
		o := f.joins[id]
		if o != nil && o.HostId == in.HostId && o.ClusterId == in.ClusterId && active(o.State) {
			o.State = inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_SUPERSEDED
		}
	}
	st := inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_PENDING
	if h.AgentOnline {
		st = inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_DELIVERED
	}
	now := time.Now().Unix()
	j := &inventoryv1.TeleportJoin{ItemId: "item-" + in.EnrollmentId[:8], EnrollmentId: in.EnrollmentId, TenantId: in.TenantId,
		HostId: in.HostId, Hostname: h.Hostname, ClusterId: in.ClusterId, State: st, AgentOnline: h.AgentOnline,
		CreatedAt: now, UpdatedAt: now, ExpiresAt: in.ExpiresAt, Created: true}
	f.joins[in.EnrollmentId] = j
	f.order = append(f.order, in.EnrollmentId)
	return clone(j), nil
}

func clone(j *inventoryv1.TeleportJoin) *inventoryv1.TeleportJoin {
	return proto.Clone(j).(*inventoryv1.TeleportJoin)
}

func active(st inventoryv1.TeleportJoinState) bool {
	switch st {
	case inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_PENDING, inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_DELIVERED,
		inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_FETCHED, inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_INSTALLING:
		return true
	}
	return false
}

// GetTeleportJoins implements the service.
func (f *Inventory) GetTeleportJoins(_ context.Context, in *inventoryv1.GetTeleportJoinsRequest, _ ...grpc.CallOption) (*inventoryv1.GetTeleportJoinsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("GetTeleportJoins"); err != nil {
		return nil, err
	}
	out := &inventoryv1.GetTeleportJoinsResponse{}
	for _, id := range in.EnrollmentIds {
		if j, ok := f.joins[id]; ok && j.TenantId == in.TenantId {
			out.Items = append(out.Items, clone(j))
		}
	}
	return out, nil
}

// CancelTeleportJoin implements the service.
func (f *Inventory) CancelTeleportJoin(_ context.Context, in *inventoryv1.CancelTeleportJoinRequest, _ ...grpc.CallOption) (*inventoryv1.TeleportJoin, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("CancelTeleportJoin"); err != nil {
		return nil, err
	}
	j, ok := f.joins[in.EnrollmentId]
	if !ok || j.TenantId != in.TenantId {
		return nil, status.Error(codes.NotFound, "not found")
	}
	if active(j.State) {
		j.State = inventoryv1.TeleportJoinState_TELEPORT_JOIN_STATE_CANCELLED
	}
	return clone(j), nil
}

// ListTeleportJoinTargets implements the service.
func (f *Inventory) ListTeleportJoinTargets(_ context.Context, in *inventoryv1.ListTeleportJoinTargetsRequest, _ ...grpc.CallOption) (*inventoryv1.ListTeleportJoinTargetsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.enter("ListTeleportJoinTargets"); err != nil {
		return nil, err
	}
	out := &inventoryv1.ListTeleportJoinTargetsResponse{}
	limit := int(in.Limit)
	if limit <= 0 {
		limit = 50
	}
	match := func(h *inventoryv1.TeleportJoinTarget) bool {
		if len(in.HostIds) > 0 {
			for _, id := range in.HostIds {
				if id == h.HostId {
					return true
				}
			}
			return false
		}
		return strings.Contains(strings.ToLower(h.Hostname), strings.ToLower(in.Query))
	}
	hosts := make([]*inventoryv1.TeleportJoinTarget, 0, len(f.hosts[in.TenantId]))
	for _, h := range f.hosts[in.TenantId] {
		hosts = append(hosts, h)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Hostname < hosts[j].Hostname })
	for _, h := range hosts {
		if !match(h) {
			continue
		}
		if len(out.Hosts) == limit {
			out.Truncated = true
			break
		}
		out.Hosts = append(out.Hosts, h)
	}
	return out, nil
}
