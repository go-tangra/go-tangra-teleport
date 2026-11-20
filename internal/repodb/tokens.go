package repodb

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

const tokenCols = `id, tenant_id, cluster_id, token_hash, resource_type, expires_at, revoked_at, created_by, created_at` // #nosec G101 -- a name, not a credential

func scanToken(sc scanner) (repo.JoinToken, error) {
	var t repo.JoinToken
	var revoked *time.Time
	err := sc.Scan(&t.ID, &t.TenantID, &t.ClusterID, &t.TokenHash, &t.ResourceType, &t.ExpiresAt, &revoked, &t.CreatedBy, &t.CreatedAt)
	t.RevokedAt = fromNullTime(revoked)
	return t, err
}

// CreateJoinToken implements repo.Store.
func (d *DB) CreateJoinToken(ctx context.Context, t repo.JoinToken) error {
	return d.tenant(ctx, t.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO join_token (`+tokenCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			t.ID, t.TenantID, t.ClusterID, t.TokenHash, t.ResourceType, t.ExpiresAt, nullTime(t.RevokedAt), t.CreatedBy, orNow(t.CreatedAt))
		return mapErr(err)
	})
}

// GetJoinToken implements repo.Store.
func (d *DB) GetJoinToken(ctx context.Context, tenantID, id string) (repo.JoinToken, error) {
	var out repo.JoinToken
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		t, err := scanToken(tx.QueryRow(ctx, `SELECT `+tokenCols+` FROM join_token WHERE id = $1`, id))
		out = t
		return mapErr(err)
	})
	return out, err
}

// ListJoinTokens implements repo.Store (newest first).
func (d *DB) ListJoinTokens(ctx context.Context, tenantID, clusterID string) ([]repo.JoinToken, error) {
	var out []repo.JoinToken
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+tokenCols+` FROM join_token WHERE cluster_id = $1 ORDER BY created_at DESC, id DESC`, clusterID)
		if err != nil {
			return mapErr(err)
		}
		defer rows.Close()
		for rows.Next() {
			t, err := scanToken(rows)
			if err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

// RevokeJoinToken implements repo.Store.
func (d *DB) RevokeJoinToken(ctx context.Context, tenantID, id string, at time.Time) error {
	return d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		return affected(tx.Exec(ctx, `UPDATE join_token SET revoked_at = $2 WHERE id = $1`, id, at))
	})
}

// PruneJoinTokens implements repo.Store (system scope).
func (d *DB) PruneJoinTokens(ctx context.Context, before time.Time) (int, error) {
	var n int
	err := d.system(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM join_token WHERE expires_at < $1`, before)
		n = int(tag.RowsAffected())
		return err
	})
	return n, err
}

// PruneTenantJoinTokens implements repo.Store (tenant scope: RLS plus the
// explicit predicate).
func (d *DB) PruneTenantJoinTokens(ctx context.Context, tenantID string, before time.Time) (int, error) {
	var n int
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM join_token WHERE tenant_id = $1 AND expires_at < $2`, tenantID, before)
		n = int(tag.RowsAffected())
		return err
	})
	return n, err
}
