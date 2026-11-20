package repodb

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

const linkCols = `id, tenant_id, snapshot_id, target_module, target_id, match, matched_on, created_at`

func scanLink(sc scanner) (repo.ResourceLink, error) {
	var l repo.ResourceLink
	err := sc.Scan(&l.ID, &l.TenantID, &l.SnapshotID, &l.TargetModule, &l.TargetID, &l.Match, &l.MatchedOn, &l.CreatedAt)
	return l, err
}

// CreateLink implements repo.Store.
func (d *DB) CreateLink(ctx context.Context, l repo.ResourceLink) error {
	return d.tenant(ctx, l.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO resource_link (`+linkCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			l.ID, l.TenantID, l.SnapshotID, l.TargetModule, l.TargetID, l.Match, l.MatchedOn, orNow(l.CreatedAt))
		return mapErr(err)
	})
}

// GetLink implements repo.Store.
func (d *DB) GetLink(ctx context.Context, tenantID, id string) (repo.ResourceLink, error) {
	var out repo.ResourceLink
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		l, err := scanLink(tx.QueryRow(ctx, `SELECT `+linkCols+` FROM resource_link WHERE id = $1`, id))
		out = l
		return mapErr(err)
	})
	return out, err
}

// ListLinks implements repo.Store.
func (d *DB) ListLinks(ctx context.Context, tenantID, snapshotID string) ([]repo.ResourceLink, error) {
	var out []repo.ResourceLink
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+linkCols+` FROM resource_link WHERE snapshot_id = $1 ORDER BY id`, snapshotID)
		if err != nil {
			return mapErr(err)
		}
		defer rows.Close()
		for rows.Next() {
			l, err := scanLink(rows)
			if err != nil {
				return err
			}
			out = append(out, l)
		}
		return rows.Err()
	})
	return out, err
}

// UpdateLink implements repo.Store (match and matched_on only).
func (d *DB) UpdateLink(ctx context.Context, l repo.ResourceLink) (repo.ResourceLink, error) {
	var out repo.ResourceLink
	err := d.tenant(ctx, l.TenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanLink(tx.QueryRow(ctx, `UPDATE resource_link SET match=$2, matched_on=$3 WHERE id=$1 RETURNING `+linkCols,
			l.ID, l.Match, l.MatchedOn))
		return mapErr(err)
	})
	return out, err
}

// DeleteLink implements repo.Store.
func (d *DB) DeleteLink(ctx context.Context, tenantID, id string) error {
	return d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		return affected(tx.Exec(ctx, `DELETE FROM resource_link WHERE id = $1`, id))
	})
}

func (d *DB) queryLinks(ctx context.Context, tenantID, q string, args ...any) ([]repo.ResourceLink, error) {
	var out []repo.ResourceLink
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return mapErr(err)
		}
		defer rows.Close()
		for rows.Next() {
			l, err := scanLink(rows)
			if err != nil {
				return err
			}
			out = append(out, l)
		}
		return rows.Err()
	})
	return out, err
}

// ListClusterLinks implements repo.Store.
func (d *DB) ListClusterLinks(ctx context.Context, tenantID, clusterID string) ([]repo.ResourceLink, error) {
	return d.queryLinks(ctx, tenantID, `SELECT l.`+strings.ReplaceAll(linkCols, ", ", ", l.")+` FROM resource_link l
 JOIN resource_snapshot s ON s.id = l.snapshot_id WHERE s.cluster_id = $1 ORDER BY l.id`, clusterID)
}

// ListLinksByTarget implements repo.Store.
func (d *DB) ListLinksByTarget(ctx context.Context, tenantID, targetModule string, targetIDs []string) ([]repo.ResourceLink, error) {
	if len(targetIDs) == 0 {
		return nil, nil
	}
	return d.queryLinks(ctx, tenantID, `SELECT `+linkCols+` FROM resource_link WHERE target_module = $1 AND target_id = ANY($2)
 ORDER BY id`, targetModule, targetIDs)
}
