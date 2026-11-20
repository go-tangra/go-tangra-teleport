package repodb

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

const clusterCols = `id, tenant_id, display_name, proxy_addr, cluster_name, edition, server_version, credential_ref,
 credential_kind, credential_identity, credential_issued_at, credential_expires_at, status, status_reason, missing_permissions, last_contact_at,
 counts, settings, created_by, created_at, updated_at`

func scanCluster(sc scanner) (repo.Cluster, error) {
	var c repo.Cluster
	var issued, exp, contact *time.Time
	var counts, settings []byte
	err := sc.Scan(&c.ID, &c.TenantID, &c.DisplayName, &c.ProxyAddr, &c.ClusterName, &c.Edition, &c.ServerVersion, &c.CredentialRef,
		&c.CredentialKind, &c.CredentialIdentity, &issued, &exp, &c.Status, &c.StatusReason, &c.MissingPermissions, &contact,
		&counts, &settings, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return c, err
	}
	c.CredentialIssuedAt, c.CredentialExpiresAt, c.LastContactAt = fromNullTime(issued), fromNullTime(exp), fromNullTime(contact)
	c.MissingPermissions = strs(c.MissingPermissions)
	_ = json.Unmarshal(counts, &c.Counts)
	_ = json.Unmarshal(settings, &c.Settings)
	return c, nil
}

// CreateCluster implements repo.Store.
func (d *DB) CreateCluster(ctx context.Context, c repo.Cluster) error {
	return d.tenant(ctx, c.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO cluster (`+clusterCols+`)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
			c.ID, c.TenantID, c.DisplayName, c.ProxyAddr, c.ClusterName, c.Edition, c.ServerVersion, c.CredentialRef,
			c.CredentialKind, c.CredentialIdentity, nullTime(c.CredentialIssuedAt), nullTime(c.CredentialExpiresAt), c.Status, c.StatusReason, strs(c.MissingPermissions),
			nullTime(c.LastContactAt), jsonb(c.Counts), jsonb(c.Settings), c.CreatedBy, orNow(c.CreatedAt), orNow(c.UpdatedAt))
		return mapErr(err)
	})
}

// GetCluster implements repo.Store.
func (d *DB) GetCluster(ctx context.Context, tenantID, id string) (repo.Cluster, error) {
	var out repo.Cluster
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		c, err := scanCluster(tx.QueryRow(ctx, `SELECT `+clusterCols+` FROM cluster WHERE id = $1`, id))
		out = c
		return mapErr(err)
	})
	return out, err
}

func collectClusters(rows pgx.Rows) ([]repo.Cluster, error) {
	defer rows.Close()
	var out []repo.Cluster
	for rows.Next() {
		c, err := scanCluster(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListClusters implements repo.Store.
func (d *DB) ListClusters(ctx context.Context, tenantID string) ([]repo.Cluster, error) {
	var out []repo.Cluster
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+clusterCols+` FROM cluster ORDER BY display_name COLLATE "C", id`)
		if err != nil {
			return err
		}
		out, err = collectClusters(rows)
		return err
	})
	return out, err
}

// UpdateCluster implements repo.Store.
func (d *DB) UpdateCluster(ctx context.Context, c repo.Cluster) (repo.Cluster, error) {
	var out repo.Cluster
	err := d.tenant(ctx, c.TenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `UPDATE cluster SET display_name=$2, proxy_addr=$3, cluster_name=$4, edition=$5, server_version=$6,
 credential_ref=$7, credential_kind=$8, credential_identity=$9, credential_expires_at=$10, status=$11, status_reason=$12,
 missing_permissions=$13, last_contact_at=$14, counts=$15, settings=$16, credential_issued_at=$17,
 updated_at=greatest(now(), updated_at + interval '1 microsecond')
 WHERE id=$1 RETURNING `+clusterCols,
			c.ID, c.DisplayName, c.ProxyAddr, c.ClusterName, c.Edition, c.ServerVersion, c.CredentialRef, c.CredentialKind,
			c.CredentialIdentity, nullTime(c.CredentialExpiresAt), c.Status, c.StatusReason, strs(c.MissingPermissions),
			nullTime(c.LastContactAt), jsonb(c.Counts), jsonb(c.Settings), nullTime(c.CredentialIssuedAt))
		var err error
		out, err = scanCluster(row)
		return mapErr(err)
	})
	return out, err
}

// DeleteCluster implements repo.Store (the schema cascades).
func (d *DB) DeleteCluster(ctx context.Context, tenantID, id string) error {
	return d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		return affected(tx.Exec(ctx, `DELETE FROM cluster WHERE id = $1`, id))
	})
}

// AllClusters implements repo.Store (system scope).
func (d *DB) AllClusters(ctx context.Context) ([]repo.Cluster, error) {
	var out []repo.Cluster
	err := d.system(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+clusterCols+` FROM cluster ORDER BY id`)
		if err != nil {
			return err
		}
		out, err = collectClusters(rows)
		return err
	})
	return out, err
}
