package security

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/provisioning"
)

const memberID = "018f3a2b-0000-7000-8000-0000000000b1"

var member = provisioning.Member{UserID: memberID, Login: "bob", Roles: []string{"operator"}}

func (f *fixture) mapping(t *testing.T, base string) string {
	t.Helper()
	code, m := f.do(t, "POST", base+"/mappings", "admin-a", map[string]any{"subject_kind": "module_role", "subject_ref": "operator",
		"teleport_roles": []string{"access"}, "logins": []string{"ubuntu"}})
	if code != http.StatusCreated {
		t.Fatalf("mapping: %d %v", code, m)
	}
	return m["id"].(string)
}

// SR-006: a removal that auth does not confirm (a forged or stale hint:
// the listing drops the member, auth says they are still a member with the
// mapped role) changes nothing.
func TestForgedMembershipRemovalChangesNothing(t *testing.T) {
	f := newFixture(t)
	base := "/clusters/" + f.cluster(t, "admin-a")
	f.mapping(t, base)
	f.auth.Set(member)
	if code, s := f.do(t, "POST", base+"/provisioning/sync", "admin-a", nil); code != http.StatusOK || s["created"] != 1.0 {
		t.Fatalf("sync: %d %v", code, s)
	}
	f.auth.SetListed()
	for range 3 {
		f.Advance(8 * 24 * time.Hour)
		if code, s := f.do(t, "POST", base+"/provisioning/sync", "admin-a", nil); code != http.StatusOK || s["locked"] != 0.0 || s["deleted"] != 0.0 {
			t.Fatalf("forged removal: %d %v", code, s)
		}
	}
	if len(f.Teleport.Locks) != 0 || f.Teleport.Calls("DeleteUser") != 0 {
		t.Fatal("an unverified removal locked or deleted the user")
	}
	// The purge task re-verifies as well.
	if s, _ := f.provisioning().PurgeDeprovisioned(context.Background(), ct.TenantA); s.Deleted != 0 {
		t.Fatalf("purge %+v", s)
	}
}

func (f *fixture) provisioning() *provisioning.Service {
	return f.deps.Provisioning
}

// SR-005: an operator reads mappings but cannot change them, provision or
// sync; a viewer neither.
func TestOperatorCannotManageMappings(t *testing.T) {
	f := newFixture(t)
	base := "/clusters/" + f.cluster(t, "admin-a")
	mid := f.mapping(t, base)
	f.auth.Set(member)
	for _, token := range []string{"operator-a", "viewer-a"} {
		for _, c := range []route{
			{"POST", base + "/mappings", map[string]any{"subject_kind": "group", "subject_ref": "ops", "teleport_roles": []string{"editor"}}},
			{"PUT", base + "/mappings/" + mid, map[string]any{"teleport_roles": []string{"editor"}}},
			{"DELETE", base + "/mappings/" + mid, nil},
			{"POST", base + "/managed-users", map[string]any{"tangra_user_id": memberID}},
			{"POST", base + "/provisioning/sync", nil},
			{"GET", base + "/provisioning/members?q=bob", nil},
		} {
			if code, m := f.do(t, c.method, c.path, token, c.body); code != http.StatusForbidden || m["reason"] != "forbidden" {
				t.Errorf("%s %s %s: %d %v", token, c.method, c.path, code, m)
			}
		}
		if code, _ := f.do(t, "GET", base+"/mappings", token, nil); code != http.StatusOK {
			t.Errorf("%s cannot read mappings: %d", token, code)
		}
	}
	if f.Teleport.Calls("CreateUser") != 0 {
		t.Fatal("a refused caller provisioned")
	}
	// Another tenant's cluster is not found.
	theirs := "/clusters/" + f.cluster(t, "admin-b")
	if code, _ := f.do(t, "POST", theirs+"/provisioning/sync", "admin-a", nil); code != http.StatusNotFound {
		t.Fatalf("cross-tenant sync: %d", code)
	}
	if code, _ := f.do(t, "GET", theirs+"/provisioning/members", "admin-a", nil); code != http.StatusNotFound {
		t.Fatalf("cross-tenant member search: %d", code)
	}
}

// A mapping may only name Teleport roles that exist on the cluster.
func TestMappingToUnknownRoleIsRejected(t *testing.T) {
	f := newFixture(t)
	base := "/clusters/" + f.cluster(t, "admin-a")
	code, m := f.do(t, "POST", base+"/mappings", "admin-a", map[string]any{"subject_kind": "group", "subject_ref": "ops",
		"teleport_roles": []string{"access", "root-everything"}})
	detail, _ := m["detail"].(map[string]any)
	if code != http.StatusUnprocessableEntity || detail["field"] != "teleport_roles" {
		t.Fatalf("unknown role: %d %v", code, m)
	}
	mid := f.mapping(t, base)
	if code, _ := f.do(t, "PUT", base+"/mappings/"+mid, "admin-a", map[string]any{"teleport_roles": []string{"root-everything"}}); code != http.StatusUnprocessableEntity {
		t.Fatalf("update to unknown role: %d", code)
	}
}

// SR-002: the invite link goes only to the notification module; it is in no
// response, log line, event or audit row — on success, rollback and retry.
func TestInviteURLOnlyInTheNotification(t *testing.T) {
	f := newFixture(t)
	base := "/clusters/" + f.cluster(t, "admin-a")
	f.mapping(t, base)
	f.auth.Set(member, provisioning.Member{UserID: "018f3a2b-0000-7000-8000-0000000000c1", Login: "carol", Roles: []string{"operator"}})
	f.Notify.SetErr(notify.ErrNotDelivered) // the first invites fail: users rolled back
	f.do(t, "POST", base+"/managed-users", "admin-a", map[string]any{"tangra_user_id": memberID})
	f.do(t, "POST", base+"/provisioning/sync", "admin-a", nil)
	f.Notify.SetErr(nil)
	f.do(t, "POST", base+"/managed-users", "admin-a", map[string]any{"tangra_user_id": memberID})
	f.do(t, "POST", base+"/provisioning/sync", "admin-a", nil)
	f.do(t, "GET", base+"/managed-users", "viewer-a", nil)
	urls := f.Teleport.IssuedURLs()
	if len(urls) != 5 {
		t.Fatalf("issued %d invite links", len(urls))
	}
	sent := f.Notify.OfTemplate(notify.TemplateInvite)
	if len(sent) != 2 {
		t.Fatalf("%d invites delivered", len(sent))
	}
	for _, m := range sent {
		if !strings.HasPrefix(m.Vars["invite_url"], "https://") {
			t.Fatalf("invite without its link: %v", m.Vars["teleport_username"])
		}
	}
	f.Audit.Flush(context.Background())
	channels := map[string]string{"responses": strings.Join(f.responses, "\n"), "logs": f.logs.String()}
	b, _ := json.Marshal(f.Events.All())
	channels["events"] = string(b)
	b, _ = json.Marshal(f.Repo.Audit())
	channels["audit"] = string(b)
	for name, out := range channels {
		for _, u := range urls {
			if strings.Contains(out, u) || strings.Contains(out, u[strings.LastIndex(u, "/")+1:]) {
				t.Errorf("%s carry an invite link", name)
			}
		}
	}
	if !strings.Contains(channels["audit"], "teleport.provision.create") || !strings.Contains(channels["logs"], "provisioning step failed") {
		t.Fatal("the provisioning paths were not exercised")
	}
}
