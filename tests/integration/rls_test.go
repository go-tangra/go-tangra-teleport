//go:build integration

// Package integration holds the database- and container-backed tests. This
// file proves row-level security (T018): with every table populated for two
// tenants, tenant A sees none of tenant B's rows in any table, the app role
// with no scope reads nothing, a cross-tenant insert is refused by WITH CHECK,
// and the system scope (app.system) sees every row. Run with:
//
//	go test -tags integration ./tests/integration/
package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repodb"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repotest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
)

// populate writes one row per table for the tenant.
func populate(t *testing.T, db *repodb.DB, tenant string) {
	t.Helper()
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	c := repotest.NewCluster(tenant, "c-"+tenant[len(tenant)-4:])
	must(db.CreateCluster(ctx, c))
	must(db.CreateJoinToken(ctx, repo.JoinToken{ID: store.NewID(), TenantID: tenant, ClusterID: c.ID, TokenHash: []byte{1},
		ResourceType: "node", ExpiresAt: now.Add(time.Hour), CreatedAt: now}))
	s, err := db.UpsertSnapshot(ctx, repotest.NewSnapshot(tenant, c.ID, "n1"))
	must(err)
	must(db.CreateLink(ctx, repo.ResourceLink{ID: store.NewID(), TenantID: tenant, SnapshotID: s.ID, TargetModule: repo.TargetInventory,
		TargetID: store.NewID(), Match: repo.MatchConfirmed, MatchedOn: repo.MatchedOnHostname, CreatedAt: now}))
	must(db.CreateMapping(ctx, repo.RoleMapping{ID: store.NewID(), TenantID: tenant, ClusterID: c.ID, SubjectKind: repo.SubjectModuleRole,
		SubjectRef: "operator", TeleportRoles: []string{"access"}, CreatedAt: now, UpdatedAt: now}))
	must(db.CreateManagedUser(ctx, repo.ManagedUser{ID: store.NewID(), TenantID: tenant, ClusterID: c.ID, TangraUserID: store.NewID(),
		TeleportUsername: "alice", State: repo.UserActive, CreatedAt: now}))
	r := repotest.NewRule(tenant, c.ID)
	must(db.CreateAlertRule(ctx, r))
	must(db.PutAlertCursor(ctx, repo.AlertCursor{ClusterID: c.ID, TenantID: tenant, UpdatedAt: now}))
	must(db.RecordDelivery(ctx, repo.AlertDelivery{ID: store.NewID(), TenantID: tenant, RuleID: r.ID, ClusterID: c.ID, WindowKey: "w",
		DeliveredAt: now}))
	must(db.CreateDraft(ctx, repo.DeploymentDraft{ID: store.NewID(), TenantID: tenant, Domain: "t.example.com", CertMode: repo.CertACME,
		TeleportVersion: "18.0.0", AdminUsername: "admin", CreatedAt: now, UpdatedAt: now}))
	must(db.AppendAudit(ctx, repo.AuditRow{Time: now, TenantID: tenant, ActorKind: "user", ActorID: "u", Action: "teleport.cluster.register",
		TargetKind: "cluster", TargetName: c.DisplayName, Outcome: "success"}))
}

func count(t *testing.T, st *store.Store, scope store.Scope, table string) int {
	t.Helper()
	var n int
	err := st.Tx(context.Background(), scope, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM `+table).Scan(&n)
	})
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestRowLevelSecurity(t *testing.T) {
	env := repotest.StartDB(t)
	ctx := context.Background()
	st, err := store.Open(ctx, env.AppDSN, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	db := repodb.New(st)
	populate(t, db, repotest.TenantA)
	populate(t, db, repotest.TenantB)

	for _, table := range repotest.Tables {
		if n := count(t, st, store.Scope{TenantID: repotest.TenantA}, table); n != 1 {
			t.Errorf("tenant A sees %d rows in %s, want only its own 1", n, table)
		}
		if n := count(t, st, store.Scope{TenantID: repotest.TenantB}, table); n != 1 {
			t.Errorf("tenant B sees %d rows in %s, want only its own 1", n, table)
		}
		if n := count(t, st, store.Scope{System: true}, table); n != 2 {
			t.Errorf("system scope sees %d rows in %s, want 2", n, table)
		}
	}

	// The app role outside any scope reads nothing.
	conn, err := pgx.Connect(ctx, env.AppDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	for _, table := range repotest.Tables {
		var n int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n); err == nil && n != 0 {
			t.Errorf("unscoped app role read %d rows of %s", n, table)
		}
	}

	// WITH CHECK refuses writing another tenant's row.
	err = st.Tx(ctx, store.Scope{TenantID: repotest.TenantB}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cluster (id, tenant_id, display_name, proxy_addr, credential_ref, credential_kind, status)
 VALUES ($1, $2, 'x', 'p.example.com:443', 'file:x', 'identity_file', 'pending')`, store.NewID(), repotest.TenantA)
		return err
	})
	if err == nil {
		t.Fatal("cross-tenant insert admitted")
	}

	// The app role cannot rewrite or erase audit history.
	err = st.Tx(ctx, store.Scope{System: true}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM audit_event`)
		return err
	})
	if err == nil {
		t.Fatal("app role deleted audit rows")
	}
}
