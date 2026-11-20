package repodb

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

const draftCols = `id, tenant_id, domain, cert_mode, acme_email, teleport_version, admin_username, admin_logins, checks,
 registered_cluster_id, created_by, created_at, updated_at`

func scanDraft(sc scanner) (repo.DeploymentDraft, error) {
	var d repo.DeploymentDraft
	var checks []byte
	var cluster *string
	err := sc.Scan(&d.ID, &d.TenantID, &d.Domain, &d.CertMode, &d.ACMEEmail, &d.TeleportVersion, &d.AdminUsername, &d.AdminLogins,
		&checks, &cluster, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return d, err
	}
	d.AdminLogins, d.RegisteredClusterID = strs(d.AdminLogins), deref(cluster)
	d.Checks = []repo.DraftCheck{}
	_ = json.Unmarshal(checks, &d.Checks)
	return d, nil
}

func checksOf(c []repo.DraftCheck) []byte {
	if c == nil {
		c = []repo.DraftCheck{}
	}
	return jsonb(c)
}

// CreateDraft implements repo.Store.
func (d *DB) CreateDraft(ctx context.Context, x repo.DeploymentDraft) error {
	return d.tenant(ctx, x.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO deployment_draft (`+draftCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			x.ID, x.TenantID, x.Domain, x.CertMode, x.ACMEEmail, x.TeleportVersion, x.AdminUsername, strs(x.AdminLogins), checksOf(x.Checks),
			nullUUID(x.RegisteredClusterID), x.CreatedBy, orNow(x.CreatedAt), orNow(x.UpdatedAt))
		return mapErr(err)
	})
}

// GetDraft implements repo.Store.
func (d *DB) GetDraft(ctx context.Context, tenantID, id string) (repo.DeploymentDraft, error) {
	var out repo.DeploymentDraft
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		x, err := scanDraft(tx.QueryRow(ctx, `SELECT `+draftCols+` FROM deployment_draft WHERE id = $1`, id))
		out = x
		return mapErr(err)
	})
	return out, err
}

// ListDrafts implements repo.Store (newest first).
func (d *DB) ListDrafts(ctx context.Context, tenantID string) ([]repo.DeploymentDraft, error) {
	var out []repo.DeploymentDraft
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+draftCols+` FROM deployment_draft ORDER BY created_at DESC, id DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			x, err := scanDraft(rows)
			if err != nil {
				return err
			}
			out = append(out, x)
		}
		return rows.Err()
	})
	return out, err
}

// UpdateDraft implements repo.Store (every field but the owner and creation).
func (d *DB) UpdateDraft(ctx context.Context, x repo.DeploymentDraft) (repo.DeploymentDraft, error) {
	var out repo.DeploymentDraft
	err := d.tenant(ctx, x.TenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanDraft(tx.QueryRow(ctx, `UPDATE deployment_draft SET domain=$2, cert_mode=$3, acme_email=$4, teleport_version=$5,
 admin_username=$6, admin_logins=$7, checks=$8, registered_cluster_id=$9,
 updated_at=greatest(now(), updated_at + interval '1 microsecond') WHERE id=$1 RETURNING `+draftCols,
			x.ID, x.Domain, x.CertMode, x.ACMEEmail, x.TeleportVersion, x.AdminUsername, strs(x.AdminLogins), checksOf(x.Checks),
			nullUUID(x.RegisteredClusterID)))
		return mapErr(err)
	})
	return out, err
}

// DeleteDraft implements repo.Store.
func (d *DB) DeleteDraft(ctx context.Context, tenantID, id string) error {
	return d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		return affected(tx.Exec(ctx, `DELETE FROM deployment_draft WHERE id = $1`, id))
	})
}
