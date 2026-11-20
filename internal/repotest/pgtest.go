//go:build integration

package repotest

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
)

// DBEnv names a migrated throwaway database: AdminDSN is the migration
// (owner) role, AppDSN the NOBYPASSRLS teleport_app role.
type DBEnv struct{ AdminDSN, AppDSN string }

// Tables lists every module table, children first (for TRUNCATE).
var Tables = []string{
	"audit_event", "alert_delivery", "alert_cursor", "alert_rule", "deployment_draft", "managed_user",
	"role_mapping", "resource_link", "resource_snapshot", "join_token", "cluster",
}

// StartDB starts a TimescaleDB container (or, with TELEPORT_IT_ADMIN_DSN set,
// creates a throwaway database on that server), creates the teleport_app role
// and applies the migrations twice (idempotence). It skips cleanly when
// neither Docker nor the DSN is available.
func StartDB(t *testing.T) DBEnv {
	t.Helper()
	ctx := context.Background()
	var env DBEnv
	if admin := os.Getenv("TELEPORT_IT_ADMIN_DSN"); admin != "" {
		env = existingDB(t, admin)
	} else {
		c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image: "timescale/timescaledb:latest-pg16", ExposedPorts: []string{"5432/tcp"},
				Env:        map[string]string{"POSTGRES_PASSWORD": "test", "POSTGRES_DB": "teleport"},
				WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
			}, Started: true,
		})
		if err != nil {
			t.Skipf("testcontainers unavailable: %v", err)
		}
		t.Cleanup(func() { _ = c.Terminate(ctx) })
		host, _ := c.Host(ctx)
		port, _ := c.MappedPort(ctx, "5432/tcp")
		env = DBEnv{
			AdminDSN: "postgres://postgres:test@" + host + ":" + port.Port() + "/teleport?sslmode=disable",
			AppDSN:   "postgres://teleport_app:app@" + host + ":" + port.Port() + "/teleport?sslmode=disable",
		}
		conn, err := pgx.Connect(ctx, env.AdminDSN)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, "CREATE ROLE teleport_app LOGIN PASSWORD 'app' NOBYPASSRLS"); err != nil {
			t.Fatal(err)
		}
		_ = conn.Close(ctx)
	}
	if err := store.Migrate(ctx, env.AdminDSN); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := store.Migrate(ctx, env.AdminDSN); err != nil {
		t.Fatalf("migrate idempotent: %v", err)
	}
	return env
}

// existingDB prepares a throwaway database on the server named by admin.
func existingDB(t *testing.T, admin string) DBEnv {
	t.Helper()
	ctx := context.Background()
	cfg, err := pgx.ParseConfig(admin)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Skipf("TELEPORT_IT_ADMIN_DSN unreachable: %v", err)
	}
	var roleExists bool
	_ = conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'teleport_app')").Scan(&roleExists)
	if roleExists {
		_ = conn.Close(ctx)
		t.Skip("role teleport_app already exists on this server; refusing to reuse it")
	}
	name := "teleport_it_" + strings.ReplaceAll(store.NewID()[:13], "-", "")
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "CREATE ROLE teleport_app LOGIN PASSWORD 'app' NOBYPASSRLS"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		_, _ = conn.Exec(ctx, "DROP ROLE IF EXISTS teleport_app")
		_ = conn.Close(ctx)
	})
	host := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	env := DBEnv{
		AdminDSN: fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", cfg.User, cfg.Password, host, name),
		AppDSN:   "postgres://teleport_app:app@" + host + "/" + name + "?sslmode=disable",
	}
	db, err := pgx.Connect(ctx, env.AdminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close(ctx) }()
	if _, err := db.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS timescaledb"); err != nil {
		t.Skipf("timescaledb unavailable: %v", err)
	}
	return env
}

// Truncate empties every module table through the admin connection.
func Truncate(t *testing.T, admin *pgx.Conn) {
	t.Helper()
	if _, err := admin.Exec(context.Background(), "TRUNCATE "+strings.Join(Tables, ", ")+" CASCADE"); err != nil {
		t.Fatal(err)
	}
}
