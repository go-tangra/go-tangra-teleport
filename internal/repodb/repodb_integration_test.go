//go:build integration

// Package repodb integration test: runs the repo conformance suite against a
// real TimescaleDB (testcontainers) and adds the checks only a database can
// make: the composite (tenant_id, id) foreign keys refuse a child row that
// names another tenant's parent, and a malformed id maps to not-found instead
// of a driver error. Run with:
//
//	go test -tags integration ./internal/repodb/
//
// It skips cleanly when Docker/testcontainers is unavailable; set
// TELEPORT_IT_ADMIN_DSN to use an existing TimescaleDB server instead.
package repodb_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repodb"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/repotest"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
)

func TestRepoDB(t *testing.T) {
	env := repotest.StartDB(t)
	ctx := context.Background()
	st, err := store.Open(ctx, env.AppDSN, 4)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(st.Close)
	db := repodb.New(st)
	admin, err := pgx.Connect(ctx, env.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(ctx) })

	t.Run("conformance", func(t *testing.T) {
		repotest.Run(t, func(t *testing.T) repo.Store { repotest.Truncate(t, admin); return db })
	})

	t.Run("composite foreign key refuses a cross-tenant parent", func(t *testing.T) {
		repotest.Truncate(t, admin)
		c := repotest.NewCluster(repotest.TenantA, "a")
		if err := db.CreateCluster(ctx, c); err != nil {
			t.Fatal(err)
		}
		// Raw insert under tenant B naming A's cluster: RLS admits the row
		// (tenant_id = B) but the (tenant_id, cluster_id) key has no parent.
		err := st.Tx(ctx, store.Scope{TenantID: repotest.TenantB}, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO join_token (id, tenant_id, cluster_id, token_hash, resource_type, expires_at, created_by)
 VALUES ($1, $2, $3, '\x00', 'node', $4, 'u')`, store.NewID(), repotest.TenantB, c.ID, time.Now().Add(time.Hour))
			return err
		})
		if err == nil {
			t.Fatal("cross-tenant child row admitted")
		}
	})

	t.Run("malformed ids are not found", func(t *testing.T) {
		if _, err := db.GetCluster(ctx, repotest.TenantA, "not-a-uuid"); !errors.Is(err, repo.ErrNotFound) {
			t.Fatalf("malformed id: %v", err)
		}
		if _, err := db.ListClusters(ctx, "not-a-uuid"); !errors.Is(err, repo.ErrNotFound) {
			t.Fatalf("malformed tenant: %v", err)
		}
	})
}
