package repodb

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

const mappingCols = `id, tenant_id, cluster_id, subject_kind, subject_ref, teleport_roles, logins, created_by, created_at, updated_at`

func scanMapping(sc scanner) (repo.RoleMapping, error) {
	var m repo.RoleMapping
	err := sc.Scan(&m.ID, &m.TenantID, &m.ClusterID, &m.SubjectKind, &m.SubjectRef, &m.TeleportRoles, &m.Logins, &m.CreatedBy,
		&m.CreatedAt, &m.UpdatedAt)
	m.TeleportRoles, m.Logins = strs(m.TeleportRoles), strs(m.Logins)
	return m, err
}

// CreateMapping implements repo.Store.
func (d *DB) CreateMapping(ctx context.Context, m repo.RoleMapping) error {
	return d.tenant(ctx, m.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO role_mapping (`+mappingCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			m.ID, m.TenantID, m.ClusterID, m.SubjectKind, m.SubjectRef, strs(m.TeleportRoles), strs(m.Logins), m.CreatedBy,
			orNow(m.CreatedAt), orNow(m.UpdatedAt))
		return mapErr(err)
	})
}

// GetMapping implements repo.Store.
func (d *DB) GetMapping(ctx context.Context, tenantID, id string) (repo.RoleMapping, error) {
	var out repo.RoleMapping
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		m, err := scanMapping(tx.QueryRow(ctx, `SELECT `+mappingCols+` FROM role_mapping WHERE id = $1`, id))
		out = m
		return mapErr(err)
	})
	return out, err
}

// ListMappings implements repo.Store.
func (d *DB) ListMappings(ctx context.Context, tenantID, clusterID string) ([]repo.RoleMapping, error) {
	var out []repo.RoleMapping
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+mappingCols+` FROM role_mapping WHERE cluster_id = $1 ORDER BY id`, clusterID)
		if err != nil {
			return mapErr(err)
		}
		defer rows.Close()
		for rows.Next() {
			m, err := scanMapping(rows)
			if err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// UpdateMapping implements repo.Store (roles and logins).
func (d *DB) UpdateMapping(ctx context.Context, m repo.RoleMapping) (repo.RoleMapping, error) {
	var out repo.RoleMapping
	err := d.tenant(ctx, m.TenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanMapping(tx.QueryRow(ctx, `UPDATE role_mapping SET teleport_roles=$2, logins=$3,
 updated_at=greatest(now(), updated_at + interval '1 microsecond') WHERE id=$1 RETURNING `+mappingCols,
			m.ID, strs(m.TeleportRoles), strs(m.Logins)))
		return mapErr(err)
	})
	return out, err
}

// DeleteMapping implements repo.Store.
func (d *DB) DeleteMapping(ctx context.Context, tenantID, id string) error {
	return d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		return affected(tx.Exec(ctx, `DELETE FROM role_mapping WHERE id = $1`, id))
	})
}
