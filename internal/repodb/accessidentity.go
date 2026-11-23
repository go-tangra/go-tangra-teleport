package repodb

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

// GetAccessIdentity implements repo.Store.
func (d *DB) GetAccessIdentity(ctx context.Context, tenantID, clusterID string) (repo.AccessIdentity, error) {
	if !isUUID(clusterID) {
		return repo.AccessIdentity{}, repo.ErrNotFound
	}
	var a repo.AccessIdentity
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		var issued *time.Time
		err := tx.QueryRow(ctx, `SELECT cluster_id, tenant_id, credential_ref, teleport_user, issued_at, expires_at, updated_at, updated_by
 FROM cluster_access_identity WHERE cluster_id = $1`, clusterID).Scan(&a.ClusterID, &a.TenantID, &a.CredentialRef, &a.TeleportUser,
			&issued, &a.ExpiresAt, &a.UpdatedAt, &a.UpdatedBy)
		if err != nil {
			return mapErr(err)
		}
		a.IssuedAt = fromNullTime(issued)
		return nil
	})
	return a, err
}

// PutAccessIdentity implements repo.Store (the foreign key refuses another
// tenant's cluster; the upsert never takes over another tenant's row).
func (d *DB) PutAccessIdentity(ctx context.Context, a repo.AccessIdentity) error {
	if !isUUID(a.ClusterID) {
		return repo.ErrNotFound
	}
	return d.tenant(ctx, a.TenantID, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cluster WHERE id = $1)`, a.ClusterID).Scan(&exists); err != nil {
			return mapErr(err)
		}
		if !exists {
			return repo.ErrNotFound
		}
		return affected(tx.Exec(ctx, `INSERT INTO cluster_access_identity (cluster_id, tenant_id, credential_ref, teleport_user, issued_at,
 expires_at, updated_at, updated_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (cluster_id) DO UPDATE SET
 credential_ref=EXCLUDED.credential_ref, teleport_user=EXCLUDED.teleport_user, issued_at=EXCLUDED.issued_at,
 expires_at=EXCLUDED.expires_at, updated_at=EXCLUDED.updated_at, updated_by=EXCLUDED.updated_by
 WHERE cluster_access_identity.tenant_id = EXCLUDED.tenant_id`,
			a.ClusterID, a.TenantID, a.CredentialRef, a.TeleportUser, nullTime(a.IssuedAt), a.ExpiresAt, orNow(a.UpdatedAt), a.UpdatedBy))
	})
}

// DeleteAccessIdentity implements repo.Store.
func (d *DB) DeleteAccessIdentity(ctx context.Context, tenantID, clusterID string) error {
	if !isUUID(clusterID) {
		return repo.ErrNotFound
	}
	return d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		return affected(tx.Exec(ctx, `DELETE FROM cluster_access_identity WHERE cluster_id = $1`, clusterID))
	})
}
