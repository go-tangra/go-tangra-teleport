package events

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/stream"
)

const tn = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

// contractTypes is the published-event table of contracts/events-and-tasks.md.
var contractTypes = []string{
	"teleport.cluster.registered", "teleport.cluster.updated", "teleport.cluster.removed", "teleport.cluster.status_changed",
	"teleport.credential.expiring", "teleport.credential.rotated",
	"teleport.user.created", "teleport.user.updated", "teleport.user.deleted",
	"teleport.role.changed", "teleport.role.deleted",
	"teleport.lock.created", "teleport.lock.removed",
	"teleport.token.created", "teleport.token.revoked",
	"teleport.resource.online", "teleport.resource.offline", "teleport.resource.flagged",
	"teleport.resource.linked", "teleport.resource.unlinked",
	"teleport.provisioning.changed",
}

func TestTypesMatchContract(t *testing.T) {
	if !reflect.DeepEqual(Types, contractTypes) {
		t.Fatalf("Types = %v", Types)
	}
	for _, ty := range Types {
		if _, ok := PayloadFor[ty]; !ok {
			t.Errorf("%s has no payload type", ty)
		}
	}
}

// Payloads carry identifiers only: every JSON field is in the contract's
// allowed set and none names secret material.
func TestPayloadsAreIDsOnly(t *testing.T) {
	allowed := map[string]bool{"cluster_id": true, "status": true, "expires_at": true, "username": true, "role": true,
		"lock_name": true, "target_kind": true, "token_id": true, "resource_type": true, "resource_id": true, "kind": true,
		"target_module": true, "target_id": true, "tangra_user_id": true, "state": true}
	for ty, p := range PayloadFor {
		rt := reflect.TypeOf(p)
		for i := range rt.NumField() {
			tag := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]
			if !allowed[tag] {
				t.Errorf("%s: field %q not allowed", ty, tag)
			}
		}
	}
}

func TestEmitAndRecorder(t *testing.T) {
	ctx := context.Background()
	Emit(ctx, nil, tn, ClusterRegistered, Cluster{ClusterID: "c1"}) // nil publisher is a no-op
	r := &Recorder{}
	Emit(ctx, r, tn, ClusterRegistered, Cluster{ClusterID: "c1"})
	Emit(ctx, r, tn, CredentialExpiring, Credential{ClusterID: "c1", ExpiresAt: time.Unix(0, 0).UTC()})
	if len(r.Events) != 2 || r.Events[0].Type != ClusterRegistered || r.Events[0].TenantID != tn {
		t.Fatalf("recorded %+v", r.Events)
	}
	if got := r.OfType(CredentialExpiring); len(got) != 1 {
		t.Fatal("OfType")
	}
	b, _ := json.Marshal(r.Events[1].Payload)
	if string(b) != `{"cluster_id":"c1","expires_at":"1970-01-01T00:00:00Z"}` {
		t.Fatal(string(b))
	}
	// A type outside the vocabulary is refused at the edge, never published.
	Emit(ctx, r, tn, "teleport.cluster.exploded", Cluster{ClusterID: "c1"})
	if len(r.Events) != 2 {
		t.Fatal("unknown type published")
	}
}

func TestHubPublisher(t *testing.T) {
	ctx := context.Background()
	HubPublisher{}.Publish(ctx, tn, ClusterRegistered, Cluster{ClusterID: "c1"}) // nil hub is a no-op
	hub := stream.NewHub(stream.NewMemory(), stream.Config{}, nil)
	defer hub.Close()
	sub, err := hub.Subscribe(ctx, tn, "u1", "")
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	HubPublisher{Hub: hub}.Publish(ctx, tn, ClusterRegistered, Cluster{ClusterID: "c1"})
	select {
	case ev := <-sub.Events():
		if ev.Type != ClusterRegistered || !strings.Contains(ev.Data, `"cluster_id":"c1"`) {
			t.Fatalf("event %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
	}
}
