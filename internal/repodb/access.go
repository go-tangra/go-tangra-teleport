package repodb

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

// GetAccessSettings implements repo.Store (defaults when no row).
func (d *DB) GetAccessSettings(ctx context.Context, tenantID, clusterID string) (repo.AccessSettings, error) {
	out := repo.AccessSettings{ClusterID: clusterID, TenantID: tenantID, AccessTTLMinutes: repo.DefaultAccessTTLMinutes}
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		var a repo.AccessSettings
		err := tx.QueryRow(ctx, `SELECT cluster_id, tenant_id, access_ttl_minutes, updated_at, updated_by FROM cluster_access_settings
 WHERE cluster_id = $1`, clusterID).Scan(&a.ClusterID, &a.TenantID, &a.AccessTTLMinutes, &a.UpdatedAt, &a.UpdatedBy)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return mapErr(err)
		}
		out = a
		return nil
	})
	return out, err
}

// PutAccessSettings implements repo.Store. The foreign key on (tenant_id,
// cluster_id) refuses another tenant's cluster (ErrNotFound); the upsert
// never takes over another tenant's row.
func (d *DB) PutAccessSettings(ctx context.Context, a repo.AccessSettings) error {
	return d.tenant(ctx, a.TenantID, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cluster WHERE id = $1)`, a.ClusterID).Scan(&exists); err != nil {
			return mapErr(err)
		}
		if !exists {
			return repo.ErrNotFound
		}
		return affected(tx.Exec(ctx, `INSERT INTO cluster_access_settings (cluster_id, tenant_id, access_ttl_minutes, updated_at, updated_by)
 VALUES ($1,$2,$3,$4,$5) ON CONFLICT (cluster_id) DO UPDATE SET access_ttl_minutes=EXCLUDED.access_ttl_minutes,
 updated_at=EXCLUDED.updated_at, updated_by=EXCLUDED.updated_by WHERE cluster_access_settings.tenant_id = EXCLUDED.tenant_id`,
			a.ClusterID, a.TenantID, a.AccessTTLMinutes, orNow(a.UpdatedAt), a.UpdatedBy))
	})
}
