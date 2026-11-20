// Package events publishes Teleport-module lifecycle events to the shared
// platform event bus (platform:events:<tenant>, contracts/events-and-tasks.md):
// other modules and the module's own SSE stream react to cluster, user, role,
// lock, token, resource and provisioning changes. Payloads carry identifiers
// only — never identity files, role YAML, invite links or token values
// (FR-025). Each type has one fixed payload struct (PayloadFor), so a secret
// cannot be added to a payload without changing this package and its test.
package events

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/stream"
)

// Event types published to platform:events:<tenant>.
const (
	ClusterRegistered    = "teleport.cluster.registered"
	ClusterUpdated       = "teleport.cluster.updated"
	ClusterRemoved       = "teleport.cluster.removed"
	ClusterStatusChanged = "teleport.cluster.status_changed"
	CredentialExpiring   = "teleport.credential.expiring" // #nosec G101 -- a name, not a credential
	CredentialRotated    = "teleport.credential.rotated"  // #nosec G101 -- a name, not a credential
	UserCreated          = "teleport.user.created"
	UserUpdated          = "teleport.user.updated"
	UserDeleted          = "teleport.user.deleted"
	RoleChanged          = "teleport.role.changed"
	RoleDeleted          = "teleport.role.deleted"
	LockCreated          = "teleport.lock.created"
	LockRemoved          = "teleport.lock.removed"
	TokenCreated         = "teleport.token.created"
	TokenRevoked         = "teleport.token.revoked"
	ResourceOnline       = "teleport.resource.online"
	ResourceOffline      = "teleport.resource.offline"
	ResourceFlagged      = "teleport.resource.flagged"
	ResourceLinked       = "teleport.resource.linked"
	ResourceUnlinked     = "teleport.resource.unlinked"
	ProvisioningChanged  = "teleport.provisioning.changed"
)

// Types lists every event type the module publishes (contract order).
var Types = []string{
	ClusterRegistered, ClusterUpdated, ClusterRemoved, ClusterStatusChanged,
	CredentialExpiring, CredentialRotated,
	UserCreated, UserUpdated, UserDeleted,
	RoleChanged, RoleDeleted,
	LockCreated, LockRemoved,
	TokenCreated, TokenRevoked,
	ResourceOnline, ResourceOffline, ResourceFlagged,
	ResourceLinked, ResourceUnlinked,
	ProvisioningChanged,
}

// Cluster is the body of teleport.cluster.registered/updated/removed.
type Cluster struct {
	ClusterID string `json:"cluster_id"`
}

// ClusterStatus is the body of teleport.cluster.status_changed.
type ClusterStatus struct {
	ClusterID string `json:"cluster_id"`
	Status    string `json:"status"`
}

// Credential is the body of teleport.credential.expiring/rotated.
type Credential struct {
	ClusterID string    `json:"cluster_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// User is the body of teleport.user.*.
type User struct {
	ClusterID string `json:"cluster_id"`
	Username  string `json:"username"`
}

// Role is the body of teleport.role.*.
type Role struct {
	ClusterID string `json:"cluster_id"`
	Role      string `json:"role"`
}

// Lock is the body of teleport.lock.*.
type Lock struct {
	ClusterID  string `json:"cluster_id"`
	LockName   string `json:"lock_name"`
	TargetKind string `json:"target_kind"`
}

// Token is the body of teleport.token.* (the token id, never its value).
type Token struct {
	ClusterID    string `json:"cluster_id"`
	TokenID      string `json:"token_id"`
	ResourceType string `json:"resource_type"`
}

// Resource is the body of teleport.resource.online/offline/flagged.
type Resource struct {
	ClusterID  string `json:"cluster_id"`
	ResourceID string `json:"resource_id"`
	Kind       string `json:"kind"`
}

// Link is the body of teleport.resource.linked/unlinked.
type Link struct {
	ResourceID   string `json:"resource_id"`
	TargetModule string `json:"target_module"`
	TargetID     string `json:"target_id"`
}

// Provisioning is the body of teleport.provisioning.changed.
type Provisioning struct {
	ClusterID    string `json:"cluster_id"`
	TangraUserID string `json:"tangra_user_id"`
	State        string `json:"state"`
}

// PayloadFor maps each type to its payload struct (zero value).
var PayloadFor = map[string]any{
	ClusterRegistered: Cluster{}, ClusterUpdated: Cluster{}, ClusterRemoved: Cluster{},
	ClusterStatusChanged: ClusterStatus{},
	CredentialExpiring:   Credential{}, CredentialRotated: Credential{},
	UserCreated: User{}, UserUpdated: User{}, UserDeleted: User{},
	RoleChanged: Role{}, RoleDeleted: Role{},
	LockCreated: Lock{}, LockRemoved: Lock{},
	TokenCreated: Token{}, TokenRevoked: Token{},
	ResourceOnline: Resource{}, ResourceOffline: Resource{}, ResourceFlagged: Resource{},
	ResourceLinked: Link{}, ResourceUnlinked: Link{},
	ProvisioningChanged: Provisioning{},
}

// Publisher emits a realtime event to all of a tenant's subscribers.
type Publisher interface {
	Publish(ctx context.Context, tenantID, eventType string, payload any)
}

// HubPublisher publishes through the stream hub (nil hub is a no-op).
type HubPublisher struct{ Hub *stream.Hub }

// Publish broadcasts eventType to every subscriber of tenantID; publishing is
// best effort and never fails the caller's operation.
func (p HubPublisher) Publish(ctx context.Context, tenantID, eventType string, payload any) {
	if p.Hub == nil {
		return
	}
	_, _ = p.Hub.PublishID(ctx, tenantID, nil, true, eventType, payload, true)
}

// Emit publishes through pub when it is non-nil and eventType is in the
// vocabulary (an unknown type is a programming error and is dropped).
func Emit(ctx context.Context, pub Publisher, tenantID, eventType string, payload any) {
	if pub == nil || !slices.Contains(Types, eventType) {
		return
	}
	pub.Publish(ctx, tenantID, eventType, payload)
}

// Recorded is one captured event (Recorder).
type Recorded struct {
	TenantID string
	Type     string
	Payload  any
}

// Recorder is an in-memory Publisher for tests (safe for concurrent
// publishers; read Events only once they are done, or use All).
type Recorder struct {
	mu     sync.Mutex
	Events []Recorded
}

// Publish implements Publisher.
func (r *Recorder) Publish(_ context.Context, tenantID, eventType string, p any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Events = append(r.Events, Recorded{TenantID: tenantID, Type: eventType, Payload: p})
}

// All returns a copy of the recorded events.
func (r *Recorder) All() []Recorded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.Events)
}

// OfType returns the recorded events of one type.
func (r *Recorder) OfType(eventType string) []Recorded {
	var out []Recorded
	for _, e := range r.All() {
		if e.Type == eventType {
			out = append(out, e)
		}
	}
	return out
}

var (
	_ Publisher = HubPublisher{}
	_ Publisher = (*Recorder)(nil)
)
