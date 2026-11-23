package access_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/types"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/access"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/users"
)

// Fixed people of the access tests (portal user ids).
const (
	alice = "aaaaaaaa-aaaa-7aaa-8aaa-aaaaaaaaaaaa" // provisioned on the cluster
	bob   = "bbbbbbbb-bbbb-7bbb-8bbb-bbbbbbbbbbbb" // provisioned too (another person)
	carol = "cccccccc-cccc-7ccc-8ccc-cccccccccccc" // not provisioned
)

type env struct {
	*ct.Env
	svc     *access.Service
	cluster string
	logs    *bytes.Buffer
}

func labels(tenant, user string) map[string]string {
	return map[string]string{users.LabelManaged: "true", users.LabelTenant: tenant, users.LabelUser: user}
}

// managed adds an active managed user for tangra user id with its Teleport user.
func (e *env) managed(t *testing.T, tangraID, name string, lbl map[string]string) repo.ManagedUser {
	t.Helper()
	m := repo.ManagedUser{ID: store.NewID(), TenantID: ct.TenantA, ClusterID: e.cluster, TangraUserID: tangraID, TeleportUsername: name,
		State: repo.UserActive, AppliedRoles: []string{"access"}, AppliedLogins: []string{"deploy"}, CreatedAt: time.Now()}
	if err := e.Repo.CreateManagedUser(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	e.Teleport.Users = append(e.Teleport.Users, teleportapi.User{Name: name, Roles: []string{"access"}, Logins: []string{"deploy"}, Labels: lbl})
	return m
}

func newEnv(t *testing.T) *env {
	t.Helper()
	var logs bytes.Buffer
	e := &env{Env: ct.New(t, slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), logs: &logs}
	for _, u := range []string{alice, bob, carol} {
		e.Perms[u] = []string{authz.AccessTerminal, authz.AccessDownload, authz.ClustersRead}
	}
	e.cluster = e.Register(t, ct.TenantA, "prod").ID
	e.managed(t, alice, "tangra-alice", labels(ct.TenantA, alice))
	e.managed(t, bob, "tangra-bob", labels(ct.TenantA, bob))
	e.Teleport.Users = append(e.Teleport.Users, teleportapi.User{Name: "admin", Roles: []string{"editor"}, Logins: []string{"root"}})
	e.Teleport.Resources = append(e.Teleport.Resources, teleportapi.Resource{Kind: teleportapi.KindNode, Name: "node-1", Hostname: "web-1",
		Labels: map[string]string{"env": "prod"}})
	e.svc = &access.Service{Clusters: e.Service, Repo: e.Repo, Audit: e.Audit, Log: slog.New(slog.NewJSONHandler(&logs, nil)), Now: e.Now}
	return e
}

// mfa is a signed-in portal user whose session used a second factor.
func mfa(tenant, user string) context.Context {
	return authz.WithSubjects(context.Background(), authz.User(tenant, user, nil).WithAMR([]string{"pwd", "otp"}))
}

func pwdOnly(tenant, user string) context.Context {
	return authz.WithSubjects(context.Background(), authz.User(tenant, user, nil).WithAMR([]string{"pwd"}))
}

// R2 / FR-001: the caller resolves only to their own managed user; the
// request never names a Teleport user.
func TestResolveBindsTheCallerToTheirOwnManagedUser(t *testing.T) {
	e := newEnv(t)
	g, err := e.svc.Resolve(mfa(ct.TenantA, alice), e.cluster, authz.AccessTerminal, true)
	if err != nil {
		t.Fatal(err)
	}
	if g.User.Name != "tangra-alice" || g.Managed.TangraUserID != alice || g.Cluster.ID != e.cluster {
		t.Fatalf("grant %+v", g)
	}
	g, err = e.svc.Resolve(mfa(ct.TenantA, bob), e.cluster, authz.AccessTerminal, true)
	if err != nil || g.User.Name != "tangra-bob" {
		t.Fatalf("bob %+v %v", g, err)
	}
	if _, err := e.svc.Resolve(mfa(ct.TenantA, carol), e.cluster, authz.AccessTerminal, true); !errors.Is(err, access.ErrNotProvisioned) {
		t.Fatalf("carol: %v", err)
	}
	// Another tenant's caller does not see the cluster at all.
	e.Perms["outsider"] = authz.Permissions
	if _, err := e.svc.Resolve(mfa(ct.TenantB, "outsider"), e.cluster, authz.AccessTerminal, true); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("other tenant: %v", err)
	}
	// Without the permission: forbidden, before anything is looked up.
	e.Perms[alice] = nil
	if _, err := e.svc.Resolve(mfa(ct.TenantA, alice), e.cluster, authz.AccessTerminal, true); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("no permission: %v", err)
	}
	// A non-human caller never gets access, whatever it may do otherwise.
	sys := authz.WithSubjects(context.Background(), authz.System(ct.TenantA))
	if _, err := e.svc.Resolve(sys, e.cluster, authz.AccessTerminal, false); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("system: %v", err)
	}
}

// The tenant and tangra user labels on the Teleport user must name the
// caller; a managed row pointing at someone else's or a local user is refused.
func TestResolveChecksLabels(t *testing.T) {
	e := newEnv(t)
	for name, lbl := range map[string]map[string]string{
		"tangra-carol-1": labels(ct.TenantB, carol),                               // another tenant
		"tangra-carol-2": labels(ct.TenantA, alice),                               // another person
		"tangra-carol-3": {users.LabelTenant: ct.TenantA, users.LabelUser: carol}, // not managed
		"tangra-carol-4": {users.LabelManaged: "false", users.LabelTenant: ct.TenantA, users.LabelUser: carol},
	} {
		e2 := newEnv(t)
		e2.managed(t, carol, name, lbl)
		if _, err := e2.svc.Resolve(mfa(ct.TenantA, carol), e2.cluster, authz.AccessTerminal, true); !errors.Is(err, access.ErrNotProvisioned) ||
			access.Reason(err) != "not_provisioned" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A row naming the local administrator is refused even if Teleport would
	// allow it: the labels do not name the caller.
	m := repo.ManagedUser{ID: store.NewID(), TenantID: ct.TenantA, ClusterID: e.cluster, TangraUserID: carol, TeleportUsername: "admin",
		State: repo.UserActive, CreatedAt: time.Now()}
	if err := e.Repo.CreateManagedUser(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Resolve(mfa(ct.TenantA, carol), e.cluster, authz.AccessTerminal, true); !errors.Is(err, access.ErrNotProvisioned) {
		t.Fatalf("admin row: %v", err)
	}
	// The Teleport user is gone.
	e.Teleport.Users = e.Teleport.Users[:0]
	if _, err := e.svc.Resolve(mfa(ct.TenantA, alice), e.cluster, authz.AccessTerminal, true); !errors.Is(err, access.ErrNotProvisioned) {
		t.Fatalf("deleted user: %v", err)
	}
}

func TestResolveRefusesInactiveAndLockedUsers(t *testing.T) {
	e := newEnv(t)
	rows, _ := e.Repo.ListManagedUsers(context.Background(), ct.TenantA, e.cluster)
	for _, r := range rows {
		if r.TangraUserID == alice {
			r.State = repo.UserLockedPendingDeletion
			if _, err := e.Repo.UpdateManagedUser(context.Background(), r); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := e.svc.Resolve(mfa(ct.TenantA, alice), e.cluster, authz.AccessTerminal, true); !errors.Is(err, access.ErrNotProvisioned) {
		t.Fatalf("pending deletion: %v", err)
	}
	e.Teleport.Locks = []teleportapi.Lock{{Name: "l1", TargetKind: "user", Target: "tangra-bob"}}
	if _, err := e.svc.Resolve(mfa(ct.TenantA, bob), e.cluster, authz.AccessTerminal, true); !errors.Is(err, access.ErrLocked) ||
		access.Reason(err) != "user_locked" {
		t.Fatalf("locked: %v", err)
	}
}

// R3 / FR-012: MFA is required for issuance; my-access only reports it.
func TestMFARequired(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.Resolve(pwdOnly(ct.TenantA, alice), e.cluster, authz.AccessTerminal, true); !errors.Is(err, access.ErrMFARequired) ||
		access.Reason(err) != "mfa_required" {
		t.Fatalf("pwd only: %v", err)
	}
	if _, err := e.svc.Download(pwdOnly(ct.TenantA, alice), e.cluster, 0); !errors.Is(err, access.ErrMFARequired) {
		t.Fatalf("download pwd only: %v", err)
	}
	my, err := e.svc.Mine(pwdOnly(ct.TenantA, alice), e.cluster)
	if err != nil || my.MFA || my.TeleportUser != "tangra-alice" {
		t.Fatalf("my access %+v %v", my, err)
	}
	if len(e.Teleport.IssuedCerts()) != 0 {
		t.Fatal("certificates issued without MFA")
	}
	my, err = e.svc.Mine(mfa(ct.TenantA, alice), e.cluster)
	if err != nil || !my.MFA || !my.CanDownload || !my.CanTerminal || my.Settings.AccessTTLMinutes != repo.DefaultAccessTTLMinutes ||
		my.ProxyAddr != ct.ProxyAddr || strings.Join(my.Logins, ",") != "deploy" {
		t.Fatalf("my access %+v %v", my, err)
	}
}

// R1 / FR-019: Teleport refusing the impersonation is reported as the
// role update needed; R9 / FR-014: per-session MFA roles are not usable.
func TestIssueRefusals(t *testing.T) {
	e := newEnv(t)
	e.Teleport.ImpersonationDenied = true
	if _, err := e.svc.Download(mfa(ct.TenantA, alice), e.cluster, 0); !errors.Is(err, access.ErrRoleOutdated) ||
		access.Reason(err) != "management_role_outdated" {
		t.Fatalf("outdated role: %v", err)
	}
	e.Teleport.ImpersonationDenied = false

	role, _ := types.NewRole("strict", types.RoleSpecV6{Options: types.RoleOptions{RequireMFAType: types.RequireMFAType_SESSION}})
	if _, err := e.Teleport.CreateRole(context.Background(), role.(*types.RoleV6)); err != nil {
		t.Fatal(err)
	}
	for i := range e.Teleport.Users {
		if e.Teleport.Users[i].Name == "tangra-alice" {
			e.Teleport.Users[i].Roles = []string{"access", "strict"}
		}
	}
	if _, err := e.svc.Download(mfa(ct.TenantA, alice), e.cluster, 0); !errors.Is(err, access.ErrSessionMFARequired) ||
		access.Reason(err) != "session_mfa_required" {
		t.Fatalf("session mfa role: %v", err)
	}
	e.Teleport.ClusterSessionMFA = true
	if _, err := e.svc.Download(mfa(ct.TenantA, bob), e.cluster, 0); !errors.Is(err, access.ErrSessionMFARequired) {
		t.Fatalf("session mfa cluster: %v", err)
	}
	if len(e.Teleport.IssuedCerts()) != 0 {
		t.Fatal("certificates issued for a per-session MFA role")
	}
}

// R4 / FR-003: the lifetime is the cluster setting, a request may only
// shorten it, and the expiry reported is the certificate's.
func TestLifetime(t *testing.T) {
	e := newEnv(t)
	ctx := mfa(ct.TenantA, alice)
	d, err := e.svc.Download(ctx, e.cluster, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.Teleport.IssuedCerts(); len(got) != 1 || got[0].TTL != 8*time.Hour || got[0].User != "tangra-alice" {
		t.Fatalf("issued %+v", got)
	}
	admin := mfa(ct.TenantA, ct.Admin)
	if _, err := e.svc.PutSettings(admin, e.cluster, 60); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Download(ctx, e.cluster, 600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Download(ctx, e.cluster, 30); err != nil {
		t.Fatal(err)
	}
	got := e.Teleport.IssuedCerts()
	if got[1].TTL != time.Hour || got[2].TTL != 30*time.Minute {
		t.Fatalf("issued %+v", got)
	}
	// Teleport may cap it further: the expiry reported is the certificate's.
	e.Teleport.MaxCertTTL = 20 * time.Minute
	d, err = e.svc.Download(ctx, e.cluster, 0)
	if err != nil || time.Until(d.Expires) > 21*time.Minute || d.User != "tangra-alice" {
		t.Fatalf("capped %+v %v", d.Expires, err)
	}
	for _, bad := range []int{14, 721, -1} {
		if _, err := e.svc.PutSettings(admin, e.cluster, bad); !errors.Is(err, access.ErrInvalid) {
			t.Errorf("setting %d: %v", bad, err)
		}
		if bad != -1 {
			if _, err := e.svc.Download(ctx, e.cluster, bad); !errors.Is(err, access.ErrInvalid) {
				t.Errorf("ttl %d: %v", bad, err)
			}
		}
	}
	// Settings need clusters:manage.
	if _, err := e.svc.PutSettings(ctx, e.cluster, 60); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("settings as alice: %v", err)
	}
}
