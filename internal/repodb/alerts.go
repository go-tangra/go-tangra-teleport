package repodb

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
)

const ruleCols = `id, tenant_id, cluster_id, name, condition_kind, event_types, threshold_count, window_minutes, recipients, enabled,
 created_by, created_at, updated_at`

func scanRule(sc scanner) (repo.AlertRule, error) {
	var r repo.AlertRule
	var cluster *string
	var recipients []byte
	err := sc.Scan(&r.ID, &r.TenantID, &cluster, &r.Name, &r.ConditionKind, &r.EventTypes, &r.ThresholdCount, &r.WindowMinutes,
		&recipients, &r.Enabled, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return r, err
	}
	r.ClusterID, r.EventTypes = deref(cluster), strs(r.EventTypes)
	_ = json.Unmarshal(recipients, &r.Recipients)
	return r, nil
}

// CreateAlertRule implements repo.Store.
func (d *DB) CreateAlertRule(ctx context.Context, r repo.AlertRule) error {
	return d.tenant(ctx, r.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO alert_rule (`+ruleCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			r.ID, r.TenantID, nullUUID(r.ClusterID), r.Name, r.ConditionKind, strs(r.EventTypes), r.ThresholdCount, r.WindowMinutes,
			jsonb(r.Recipients), r.Enabled, r.CreatedBy, orNow(r.CreatedAt), orNow(r.UpdatedAt))
		return mapErr(err)
	})
}

// GetAlertRule implements repo.Store.
func (d *DB) GetAlertRule(ctx context.Context, tenantID, id string) (repo.AlertRule, error) {
	var out repo.AlertRule
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		r, err := scanRule(tx.QueryRow(ctx, `SELECT `+ruleCols+` FROM alert_rule WHERE id = $1`, id))
		out = r
		return mapErr(err)
	})
	return out, err
}

// ListAlertRules implements repo.Store (by name, then id).
func (d *DB) ListAlertRules(ctx context.Context, tenantID string) ([]repo.AlertRule, error) {
	var out []repo.AlertRule
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+ruleCols+` FROM alert_rule ORDER BY name COLLATE "C", id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRule(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// UpdateAlertRule implements repo.Store (every field but the cluster).
func (d *DB) UpdateAlertRule(ctx context.Context, r repo.AlertRule) (repo.AlertRule, error) {
	var out repo.AlertRule
	err := d.tenant(ctx, r.TenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanRule(tx.QueryRow(ctx, `UPDATE alert_rule SET name=$2, condition_kind=$3, event_types=$4, threshold_count=$5,
 window_minutes=$6, recipients=$7, enabled=$8, updated_at=greatest(now(), updated_at + interval '1 microsecond')
 WHERE id=$1 RETURNING `+ruleCols,
			r.ID, r.Name, r.ConditionKind, strs(r.EventTypes), r.ThresholdCount, r.WindowMinutes, jsonb(r.Recipients), r.Enabled))
		return mapErr(err)
	})
	return out, err
}

// DeleteAlertRule implements repo.Store (deliveries cascade).
func (d *DB) DeleteAlertRule(ctx context.Context, tenantID, id string) error {
	return d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		return affected(tx.Exec(ctx, `DELETE FROM alert_rule WHERE id = $1`, id))
	})
}

// GetAlertCursor implements repo.Store.
func (d *DB) GetAlertCursor(ctx context.Context, tenantID, clusterID string) (repo.AlertCursor, error) {
	var c repo.AlertCursor
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		var last *time.Time
		err := tx.QueryRow(ctx, `SELECT cluster_id, tenant_id, last_event_time, last_event_id, updated_at FROM alert_cursor
 WHERE cluster_id = $1`, clusterID).Scan(&c.ClusterID, &c.TenantID, &last, &c.LastEventID, &c.UpdatedAt)
		c.LastEventTime = fromNullTime(last)
		return mapErr(err)
	})
	return c, err
}

// PutAlertCursor implements repo.Store.
func (d *DB) PutAlertCursor(ctx context.Context, c repo.AlertCursor) error {
	return d.tenant(ctx, c.TenantID, func(tx pgx.Tx) error {
		return affected(tx.Exec(ctx, `INSERT INTO alert_cursor (cluster_id, tenant_id, last_event_time, last_event_id, updated_at)
 VALUES ($1,$2,$3,$4,$5) ON CONFLICT (cluster_id) DO UPDATE SET last_event_time=EXCLUDED.last_event_time,
 last_event_id=EXCLUDED.last_event_id, updated_at=EXCLUDED.updated_at WHERE alert_cursor.tenant_id = EXCLUDED.tenant_id`,
			c.ClusterID, c.TenantID, nullTime(c.LastEventTime), c.LastEventID, orNow(c.UpdatedAt)))
	})
}

// RecordDelivery implements repo.Store.
func (d *DB) RecordDelivery(ctx context.Context, x repo.AlertDelivery) error {
	return d.tenant(ctx, x.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO alert_delivery (id, tenant_id, rule_id, cluster_id, window_key, delivered_at)
 VALUES ($1,$2,$3,$4,$5,$6)`, x.ID, x.TenantID, x.RuleID, x.ClusterID, x.WindowKey, orNow(x.DeliveredAt))
		return mapErr(err)
	})
}

// ReleaseDelivery implements repo.Store.
func (d *DB) ReleaseDelivery(ctx context.Context, tenantID, ruleID, clusterID, windowKey string) error {
	return d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		return affected(tx.Exec(ctx, `DELETE FROM alert_delivery WHERE rule_id = $1 AND cluster_id = $2 AND window_key = $3`,
			ruleID, clusterID, windowKey))
	})
}

// PruneTenantDeliveries implements repo.Store (tenant scope: RLS plus the
// explicit predicate).
func (d *DB) PruneTenantDeliveries(ctx context.Context, tenantID string, before time.Time) (int, error) {
	var n int
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM alert_delivery WHERE tenant_id = $1 AND delivered_at < $2`, tenantID, before)
		n = int(tag.RowsAffected())
		return err
	})
	return n, err
}

// PruneDeliveries implements repo.Store (system scope).
func (d *DB) PruneDeliveries(ctx context.Context, before time.Time) (int, error) {
	var n int
	err := d.system(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM alert_delivery WHERE delivered_at < $1`, before)
		n = int(tag.RowsAffected())
		return err
	})
	return n, err
}
