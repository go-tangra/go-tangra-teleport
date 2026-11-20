package repodb

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

const userCols = `id, tenant_id, cluster_id, tangra_user_id, teleport_username, state, applied_roles, applied_logins, lock_name,
 deprovision_after, last_synced_at, created_at`

func scanUser(sc scanner) (repo.ManagedUser, error) {
	var u repo.ManagedUser
	var lock *string
	var deprov, synced *time.Time
	err := sc.Scan(&u.ID, &u.TenantID, &u.ClusterID, &u.TangraUserID, &u.TeleportUsername, &u.State, &u.AppliedRoles, &u.AppliedLogins,
		&lock, &deprov, &synced, &u.CreatedAt)
	u.LockName, u.DeprovisionAfter, u.LastSyncedAt = deref(lock), fromNullTime(deprov), fromNullTime(synced)
	u.AppliedRoles, u.AppliedLogins = strs(u.AppliedRoles), strs(u.AppliedLogins)
	return u, err
}

// CreateManagedUser implements repo.Store.
func (d *DB) CreateManagedUser(ctx context.Context, u repo.ManagedUser) error {
	return d.tenant(ctx, u.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO managed_user (`+userCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			u.ID, u.TenantID, u.ClusterID, u.TangraUserID, u.TeleportUsername, u.State, strs(u.AppliedRoles), strs(u.AppliedLogins),
			nullText(u.LockName), nullTime(u.DeprovisionAfter), nullTime(u.LastSyncedAt), orNow(u.CreatedAt))
		return mapErr(err)
	})
}

// GetManagedUser implements repo.Store.
func (d *DB) GetManagedUser(ctx context.Context, tenantID, id string) (repo.ManagedUser, error) {
	var out repo.ManagedUser
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		u, err := scanUser(tx.QueryRow(ctx, `SELECT `+userCols+` FROM managed_user WHERE id = $1`, id))
		out = u
		return mapErr(err)
	})
	return out, err
}

// ListManagedUsers implements repo.Store (by Teleport username).
func (d *DB) ListManagedUsers(ctx context.Context, tenantID, clusterID string) ([]repo.ManagedUser, error) {
	var out []repo.ManagedUser
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+userCols+` FROM managed_user WHERE cluster_id = $1 ORDER BY teleport_username COLLATE "C"`, clusterID)
		if err != nil {
			return mapErr(err)
		}
		defer rows.Close()
		for rows.Next() {
			u, err := scanUser(rows)
			if err != nil {
				return err
			}
			out = append(out, u)
		}
		return rows.Err()
	})
	return out, err
}

// UpdateManagedUser implements repo.Store (state and applied sets).
func (d *DB) UpdateManagedUser(ctx context.Context, u repo.ManagedUser) (repo.ManagedUser, error) {
	var out repo.ManagedUser
	err := d.tenant(ctx, u.TenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanUser(tx.QueryRow(ctx, `UPDATE managed_user SET state=$2, applied_roles=$3, applied_logins=$4, lock_name=$5,
 deprovision_after=$6, last_synced_at=$7 WHERE id=$1 RETURNING `+userCols,
			u.ID, u.State, strs(u.AppliedRoles), strs(u.AppliedLogins), nullText(u.LockName), nullTime(u.DeprovisionAfter),
			nullTime(u.LastSyncedAt)))
		return mapErr(err)
	})
	return out, err
}

// DeleteManagedUser implements repo.Store.
func (d *DB) DeleteManagedUser(ctx context.Context, tenantID, id string) error {
	return d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		return affected(tx.Exec(ctx, `DELETE FROM managed_user WHERE id = $1`, id))
	})
}
