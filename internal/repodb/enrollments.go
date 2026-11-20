package repodb

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

// Spec 002: inventory-agent enrollments (no token is ever stored).

const enrollCols = `id, tenant_id, cluster_id, host_id, hostname, state, reason, item_id, renders, node_host_uuid, link_id, expires_at, created_by, created_at, updated_at`

func scanEnrollment(sc scanner) (repo.Enrollment, error) {
	var e repo.Enrollment
	err := sc.Scan(&e.ID, &e.TenantID, &e.ClusterID, &e.HostID, &e.Hostname, &e.State, &e.Reason, &e.ItemID, &e.Renders,
		&e.NodeHostUUID, &e.LinkID, &e.ExpiresAt, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt)
	return e, err
}

func collectEnrollments(rows pgx.Rows) ([]repo.Enrollment, error) {
	defer rows.Close()
	var out []repo.Enrollment
	for rows.Next() {
		e, err := scanEnrollment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CreateEnrollment implements repo.Store.
func (d *DB) CreateEnrollment(ctx context.Context, e repo.Enrollment) error {
	if !isUUID(e.HostID) {
		return repo.ErrNotFound
	}
	return d.tenant(ctx, e.TenantID, func(tx pgx.Tx) error {
		created := orNow(e.CreatedAt)
		updated := e.UpdatedAt
		if updated.IsZero() {
			updated = created
		}
		_, err := tx.Exec(ctx, `INSERT INTO enrollment (`+enrollCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
			e.ID, e.TenantID, e.ClusterID, e.HostID, e.Hostname, e.State, e.Reason, e.ItemID, e.Renders, e.NodeHostUUID, e.LinkID,
			e.ExpiresAt, e.CreatedBy, created, updated)
		return mapErr(err)
	})
}

// GetEnrollment implements repo.Store.
func (d *DB) GetEnrollment(ctx context.Context, tenantID, id string) (repo.Enrollment, error) {
	var out repo.Enrollment
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		e, err := scanEnrollment(tx.QueryRow(ctx, `SELECT `+enrollCols+` FROM enrollment WHERE id = $1`, id))
		out = e
		return mapErr(err)
	})
	return out, err
}

// ListEnrollments implements repo.Store (newest first).
func (d *DB) ListEnrollments(ctx context.Context, tenantID, clusterID string) ([]repo.Enrollment, error) {
	var out []repo.Enrollment
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+enrollCols+` FROM enrollment WHERE cluster_id = $1 ORDER BY created_at DESC, id DESC`, clusterID)
		if err != nil {
			return mapErr(err)
		}
		out, err = collectEnrollments(rows)
		return err
	})
	return out, err
}

// UpdateEnrollment implements repo.Store.
func (d *DB) UpdateEnrollment(ctx context.Context, e repo.Enrollment) (repo.Enrollment, error) {
	var out repo.Enrollment
	err := d.tenant(ctx, e.TenantID, func(tx pgx.Tx) error {
		u, err := scanEnrollment(tx.QueryRow(ctx, `UPDATE enrollment SET state = $2, reason = $3, item_id = $4, node_host_uuid = $5,
 link_id = $6, updated_at = now() WHERE id = $1 RETURNING `+enrollCols, e.ID, e.State, e.Reason, e.ItemID, e.NodeHostUUID, e.LinkID))
		out = u
		return mapErr(err)
	})
	return out, err
}

// AddEnrollmentRender implements repo.Store.
func (d *DB) AddEnrollmentRender(ctx context.Context, tenantID, id string, max int) (repo.Enrollment, error) {
	var out repo.Enrollment
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		u, err := scanEnrollment(tx.QueryRow(ctx, `UPDATE enrollment SET renders = renders + 1, updated_at = now()
 WHERE id = $1 AND renders < $2 RETURNING `+enrollCols, id, max))
		if err == nil {
			out = u
			return nil
		}
		if err := mapErr(err); err != repo.ErrNotFound {
			return err
		}
		// No row updated: absent (not found) or out of renders (conflict).
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM enrollment WHERE id = $1`, id).Scan(&n); err != nil {
			return mapErr(err)
		}
		if n == 0 {
			return repo.ErrNotFound
		}
		return repo.ErrConflict
	})
	return out, err
}

// ListActiveEnrollments implements repo.Store (system scope).
func (d *DB) ListActiveEnrollments(ctx context.Context, limit int) ([]repo.Enrollment, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	var out []repo.Enrollment
	err := d.system(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+enrollCols+` FROM enrollment
 WHERE state IN ('pending','delivered','fetched','installing')
    OR (state = 'joined' AND link_id = '' AND expires_at > now()) ORDER BY updated_at, id LIMIT $1`, limit)
		if err != nil {
			return mapErr(err)
		}
		out, err = collectEnrollments(rows)
		return err
	})
	return out, err
}
