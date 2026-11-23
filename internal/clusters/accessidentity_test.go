package clusters_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/authz"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/clusters"
	ct "github.com/go-tangra/go-tangra-teleport/v4/internal/clusters/clusterstest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/events"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/notify"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/secrets"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/teleportapi/identitytest"
)

// withManagedUser adds an active managed user (and its labelled Teleport
// user) to the cluster, so the upload's dry issuance runs.
func withManagedUser(t *testing.T, e *ct.Env, clusterID string) {
	t.Helper()
	if err := e.Repo.CreateManagedUser(context.Background(), repo.ManagedUser{ID: store.NewID(), TenantID: ct.TenantA, ClusterID: clusterID,
		TangraUserID: "aaaaaaaa-aaaa-7aaa-8aaa-aaaaaaaaaaaa", TeleportUsername: "tangra-alice", State: repo.UserActive, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	e.Teleport.Users = append(e.Teleport.Users, teleportapi.User{Name: "tangra-alice", Roles: []string{"access"},
		Labels: map[string]string{"tangra.io/managed": "true"}})
}

func putAccess(e *ct.Env, ctx context.Context, id, raw string) (clusters.AccessIdentityView, error) {
	return e.Service.PutAccessIdentity(ctx, id, clusters.AccessIdentityInput{Credential: clusters.NewCredential([]byte(raw))})
}

// US1-1, FR-002/003: a sign-in identity is verified, stored in the secret
// store and shown without the identity; the dry issuance ran through the
// access identity, not the management one.
func TestPutAccessIdentityVerifiesThenStores(t *testing.T) {
	e := ct.New(t, nil)
	v := e.Register(t, ct.TenantA, "prod")
	withManagedUser(t, e, v.ID)
	if got, err := e.Service.AccessIdentity(viewer, v.ID); err != nil || got.Configured || got.State != clusters.AccessStateMissing {
		t.Fatalf("before upload: %+v %v", got, err)
	}
	if _, err := putAccess(e, viewer, v.ID, e.AccessIdentity(t, 90*24*time.Hour, "")); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer uploaded: %v", err)
	}
	raw := e.AccessIdentity(t, 90*24*time.Hour, "")
	got, err := putAccess(e, admin, v.ID, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Configured || got.TeleportUser != ct.AccessUser || got.State != clusters.AccessStateOK || got.ExpiresAt == nil ||
		got.ImpersonationChecked == nil || !*got.ImpersonationChecked || got.UpdatedBy == "" {
		t.Fatalf("view %+v", got)
	}
	issues := e.Teleport.IssuedCerts()
	if len(issues) != 1 || !issues[0].Access || issues[0].User != "tangra-alice" || issues[0].TTL != time.Minute {
		t.Fatalf("dry issuance %+v", issues)
	}
	if e.Secrets.Len() != 2 { // management credential + access identity
		t.Fatalf("secrets %d", e.Secrets.Len())
	}
	a, err := e.Repo.GetAccessIdentity(context.Background(), ct.TenantA, v.ID)
	if err != nil || !strings.Contains(a.CredentialRef, "teleport-access-"+v.ID) {
		t.Fatalf("stored %+v %v", a, err)
	}
	if st, err := e.Service.AccessIdentity(viewer, v.ID); err != nil || st.State != clusters.AccessStateOK || st.ImpersonationChecked != nil {
		t.Fatalf("status %+v %v", st, err)
	}
	if !slices.Contains(e.AuditRows(), "teleport.access_identity.upload:success") {
		t.Fatalf("audit %v", e.AuditRows())
	}

	// Replace: the previous secret goes, the pool connection is dropped.
	if _, err := e.Service.AccessClient(context.Background(), stored(t, e, v.ID)); err != nil {
		t.Fatal(err)
	}
	if e.AccessPool.Len() != 1 {
		t.Fatalf("access pool %d", e.AccessPool.Len())
	}
	if _, err := putAccess(e, admin, v.ID, e.AccessIdentity(t, 60*24*time.Hour, "")); err != nil {
		t.Fatal(err)
	}
	if e.Secrets.Len() != 2 || e.AccessPool.Len() != 0 || e.Pool.Len() > 1 {
		t.Fatalf("after replace: secrets %d access pool %d", e.Secrets.Len(), e.AccessPool.Len())
	}
	if !slices.Contains(e.AuditRows(), "teleport.access_identity.replace:success") {
		t.Fatalf("audit %v", e.AuditRows())
	}

	// Remove.
	if err := e.Service.DeleteAccessIdentity(viewer, v.ID); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("viewer removed: %v", err)
	}
	if err := e.Service.DeleteAccessIdentity(admin, v.ID); err != nil {
		t.Fatal(err)
	}
	if e.Secrets.Len() != 1 {
		t.Fatalf("secrets after remove %d", e.Secrets.Len())
	}
	if err := e.Service.DeleteAccessIdentity(admin, v.ID); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("second remove: %v", err)
	}
	if _, err := e.Service.AccessClient(context.Background(), stored(t, e, v.ID)); !errors.Is(err, clusters.ErrAccessIdentityMissing) {
		t.Fatalf("client after remove: %v", err)
	}
	if !slices.Contains(e.AuditRows(), "teleport.access_identity.delete:success") {
		t.Fatalf("audit %v", e.AuditRows())
	}
}

// US1-2/3/4: refusals store nothing and are audited with their reason.
func TestPutAccessIdentityRefusals(t *testing.T) {
	e := ct.New(t, nil)
	v := e.Register(t, ct.TenantA, "prod")
	other := identitytest.New(t, identitytest.Options{Cluster: "other.example.com", User: ct.AccessUser})
	for _, c := range []struct {
		name   string
		raw    string
		setup  func()
		want   error
		reason string
	}{
		{"tctl auth sign identity", e.AccessIdentity(t, 30*24*time.Hour, "f00.prod.example.com"), nil, clusters.ErrNotSignIn, "access_identity_not_sign_in"},
		{"another cluster", other, nil, clusters.ErrInvalid, "validation_failed"},
		{"expired", e.AccessIdentity(t, -time.Hour, ""), nil, teleportapi.ErrCredentialInvalid, "credential_invalid"},
		{"empty", "  ", nil, clusters.ErrInvalid, "validation_failed"},
		{"cannot impersonate", e.AccessIdentity(t, 30*24*time.Hour, ""), func() {
			withManagedUser(t, e, v.ID)
			e.Teleport.AccessImpersonationDenied = true
		}, clusters.ErrCannotImpersonate, "access_identity_cannot_impersonate"},
		{"secret store down", e.AccessIdentity(t, 30*24*time.Hour, ""), func() {
			e.Teleport.AccessImpersonationDenied = false
			e.Secrets.SetErr(secrets.ErrUnavailable)
		}, secrets.ErrUnavailable, "dependency_unavailable"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.setup != nil {
				c.setup()
			}
			_, err := putAccess(e, admin, v.ID, c.raw)
			if !errors.Is(err, c.want) || clusters.ReasonOf(err) != c.reason {
				t.Fatalf("err %v reason %q", err, clusters.ReasonOf(err))
			}
			if _, gerr := e.Repo.GetAccessIdentity(context.Background(), ct.TenantA, v.ID); !errors.Is(gerr, repo.ErrNotFound) {
				t.Fatal("stored after a refusal")
			}
			if !slices.Contains(e.AuditRows(), "teleport.access_identity.upload:failure") {
				t.Fatal("refusal not audited")
			}
		})
	}
	e.Secrets.SetErr(nil)
	if e.Secrets.Len() != 1 {
		t.Fatalf("secrets %d", e.Secrets.Len())
	}
	// Another tenant's cluster is not found.
	if _, err := putAccess(e, ct.As(ct.TenantB, ct.Admin), v.ID, e.AccessIdentity(t, time.Hour, "")); !errors.Is(err, repo.ErrNotFound) {
		t.Fatalf("other tenant: %v", err)
	}
}

// No managed user yet: the dry issuance is skipped and the view says so.
func TestPutAccessIdentityWithoutManagedUser(t *testing.T) {
	e := ct.New(t, nil)
	v := e.Register(t, ct.TenantA, "prod")
	got, err := putAccess(e, admin, v.ID, e.AccessIdentity(t, 30*24*time.Hour, ""))
	if err != nil || got.ImpersonationChecked == nil || *got.ImpersonationChecked {
		t.Fatalf("%+v %v", got, err)
	}
	if len(e.Teleport.IssuedCerts()) != 0 {
		t.Fatal("issued without a managed user")
	}
}

// FR-005: an expired access identity is refused without dialling.
func TestAccessClientExpired(t *testing.T) {
	e := ct.New(t, nil)
	v := e.Register(t, ct.TenantA, "prod")
	if _, err := putAccess(e, admin, v.ID, e.AccessIdentity(t, 2*time.Hour, "")); err != nil {
		t.Fatal(err)
	}
	cl, err := e.Service.AccessClient(context.Background(), stored(t, e, v.ID))
	if err != nil || cl == nil || e.AccessPoolDials() != 1 {
		t.Fatalf("client %v dials %d", err, e.AccessPoolDials())
	}
	e.Advance(3 * time.Hour)
	if _, err := e.Service.AccessClient(context.Background(), stored(t, e, v.ID)); !errors.Is(err, clusters.ErrAccessIdentityExpired) ||
		clusters.ReasonOf(err) != "access_identity_expired" {
		t.Fatalf("expired: %v", err)
	}
	if st, _ := e.Service.AccessIdentity(viewer, v.ID); st.State != clusters.AccessStateExpired {
		t.Fatalf("state %s", st.State)
	}
	if e.AccessPoolDials() != 1 || e.AccessPool.Len() != 0 {
		t.Fatalf("dials %d pool %d", e.AccessPoolDials(), e.AccessPool.Len())
	}
}

// US3 / FR-007: each expiry stage of the access identity is announced once
// (event and notification), with the management credential's thresholds,
// and the cluster status is left to the management credential.
func TestAccessIdentityExpiryAlerts(t *testing.T) {
	e := ct.New(t, nil)
	v := e.Register(t, ct.TenantA, "prod")
	if err := e.Repo.CreateAlertRule(context.Background(), repo.AlertRule{ID: "018f3a2b-0000-7000-8000-0000000000b1", TenantID: ct.TenantA,
		Name: "expiry", ConditionKind: repo.ConditionCredentialExpiring, Recipients: repo.Recipients{UserIDs: []string{"ops-1"}}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := putAccess(e, admin, v.ID, e.AccessIdentity(t, 20*24*time.Hour, "")); err != nil {
		t.Fatal(err)
	}
	accessEvents := func() int {
		n := 0
		for _, ev := range e.Events.OfType(events.CredentialExpiring) {
			if p, ok := ev.Payload.(events.Credential); ok && p.Kind == clusters.CredentialAccessIdentity {
				n++
			}
		}
		return n
	}
	accessMails := func() int {
		n := 0
		for _, m := range e.Notify.OfTemplate(notify.TemplateCredentialExpiring) {
			if m.Vars["credential"] == clusters.CredentialAccessIdentity && m.Vars["status_reason"] != "" {
				n++
			}
		}
		return n
	}
	check := func() repo.Cluster {
		t.Helper()
		c, err := e.Service.CheckCredential(context.Background(), stored(t, e, v.ID))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	check()
	if accessEvents() != 0 {
		t.Fatal("announced while fresh")
	}
	e.Advance(16 * 24 * time.Hour) // 4 days left: within 25% of 20 days
	check()
	check()
	if accessEvents() != 1 || accessMails() != 1 {
		t.Fatalf("warn stage: events %d mails %d", accessEvents(), accessMails())
	}
	e.Advance(3*24*time.Hour + time.Hour) // under a day left
	if _, err := e.Service.Check(admin, v.ID); err != nil {
		t.Fatal(err)
	}
	if accessEvents() != 2 || accessMails() != 2 {
		t.Fatalf("day stage: events %d mails %d", accessEvents(), accessMails())
	}
	e.Advance(24 * time.Hour)
	if c := check(); c.Status != repo.StatusConnected {
		t.Fatalf("cluster status changed by the access identity: %s", c.Status)
	}
	if accessEvents() != 3 || accessMails() != 3 {
		t.Fatalf("expired stage: events %d mails %d", accessEvents(), accessMails())
	}
}

// The access identity's secret goes with the cluster.
func TestRemoveDeletesTheAccessIdentity(t *testing.T) {
	e := ct.New(t, nil)
	v := e.Register(t, ct.TenantA, "prod")
	if _, err := putAccess(e, admin, v.ID, e.AccessIdentity(t, 30*24*time.Hour, "")); err != nil {
		t.Fatal(err)
	}
	if err := e.Service.Remove(admin, v.ID); err != nil {
		t.Fatal(err)
	}
	if e.Secrets.Len() != 0 {
		t.Fatalf("secrets %d", e.Secrets.Len())
	}
	w := e.Register(t, ct.TenantA, "prod2")
	if _, err := putAccess(e, admin, w.ID, e.AccessIdentity(t, 30*24*time.Hour, "")); err != nil {
		t.Fatal(err)
	}
	if n, err := e.Service.PurgeTenant(context.Background(), ct.TenantA); err != nil || n != 1 || e.Secrets.Len() != 0 {
		t.Fatalf("purge %d %v secrets %d", n, err, e.Secrets.Len())
	}
}
