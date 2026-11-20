package repodb

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
)

const snapshotCols = `id, tenant_id, cluster_id, kind, teleport_name, hostname, addr, labels, agent_version, online,
 last_seen_at, offline_since, flagged_at`

func scanSnapshot(sc scanner) (repo.ResourceSnapshot, error) {
	var s repo.ResourceSnapshot
	var host, addr *string
	var labels []byte
	var seen, offline, flagged *time.Time
	err := sc.Scan(&s.ID, &s.TenantID, &s.ClusterID, &s.Kind, &s.TeleportName, &host, &addr, &labels, &s.AgentVersion, &s.Online,
		&seen, &offline, &flagged)
	if err != nil {
		return s, err
	}
	s.Hostname, s.Addr = deref(host), deref(addr)
	s.LastSeenAt, s.OfflineSince, s.FlaggedAt = fromNullTime(seen), fromNullTime(offline), fromNullTime(flagged)
	s.Labels = map[string]string{}
	_ = json.Unmarshal(labels, &s.Labels)
	return s, nil
}

func labelsOf(m map[string]string) []byte {
	if m == nil {
		m = map[string]string{}
	}
	return jsonb(m)
}

// UpsertSnapshot implements repo.Store: (cluster, kind, teleport_name) is the
// key and the existing id is kept. The conflict update is limited to the
// caller's tenant (it can never touch another tenant's row; RLS also hides it).
func (d *DB) UpsertSnapshot(ctx context.Context, s repo.ResourceSnapshot) (repo.ResourceSnapshot, error) {
	var out repo.ResourceSnapshot
	id := s.ID
	if id == "" {
		id = store.NewID()
	}
	err := d.tenant(ctx, s.TenantID, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `INSERT INTO resource_snapshot (`+snapshotCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
 ON CONFLICT (cluster_id, kind, teleport_name) DO UPDATE SET hostname=EXCLUDED.hostname, addr=EXCLUDED.addr, labels=EXCLUDED.labels,
 agent_version=EXCLUDED.agent_version, online=EXCLUDED.online, last_seen_at=EXCLUDED.last_seen_at,
 offline_since=EXCLUDED.offline_since, flagged_at=EXCLUDED.flagged_at
 WHERE resource_snapshot.tenant_id = EXCLUDED.tenant_id
 RETURNING `+snapshotCols,
			id, s.TenantID, s.ClusterID, s.Kind, s.TeleportName, nullText(s.Hostname), nullText(s.Addr), labelsOf(s.Labels), s.AgentVersion,
			s.Online, nullTime(s.LastSeenAt), nullTime(s.OfflineSince), nullTime(s.FlaggedAt))
		var err error
		out, err = scanSnapshot(row)
		return mapErr(err)
	})
	return out, err
}

// GetSnapshot implements repo.Store.
func (d *DB) GetSnapshot(ctx context.Context, tenantID, id string) (repo.ResourceSnapshot, error) {
	var out repo.ResourceSnapshot
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		s, err := scanSnapshot(tx.QueryRow(ctx, `SELECT `+snapshotCols+` FROM resource_snapshot WHERE id = $1`, id))
		out = s
		return mapErr(err)
	})
	return out, err
}

// ListSnapshots implements repo.Store (by kind, then name).
func (d *DB) ListSnapshots(ctx context.Context, tenantID, clusterID string) ([]repo.ResourceSnapshot, error) {
	var out []repo.ResourceSnapshot
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+snapshotCols+` FROM resource_snapshot WHERE cluster_id = $1
 ORDER BY kind, teleport_name COLLATE "C"`, clusterID)
		if err != nil {
			return mapErr(err)
		}
		defer rows.Close()
		for rows.Next() {
			s, err := scanSnapshot(rows)
			if err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}

// DeleteSnapshot implements repo.Store (links cascade).
func (d *DB) DeleteSnapshot(ctx context.Context, tenantID, id string) error {
	return d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		return affected(tx.Exec(ctx, `DELETE FROM resource_snapshot WHERE id = $1`, id))
	})
}

// FindSnapshots implements repo.Store: hostname (case-insensitive) or the
// host part of addr ("ip", "ip:port" or "[ip]:port").
func (d *DB) FindSnapshots(ctx context.Context, tenantID, hostname, ip string) ([]repo.ResourceSnapshot, error) {
	var out []repo.ResourceSnapshot
	if hostname == "" && ip == "" {
		return out, nil
	}
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+snapshotCols+` FROM resource_snapshot
 WHERE ($1 <> '' AND lower(hostname) = lower($1))
    OR ($2 <> '' AND (addr = $2 OR starts_with(addr, $2 || ':') OR starts_with(addr, '[' || $2 || ']:')))
 ORDER BY cluster_id, kind, teleport_name COLLATE "C" LIMIT 500`, hostname, ip)
		if err != nil {
			return mapErr(err)
		}
		defer rows.Close()
		for rows.Next() {
			s, err := scanSnapshot(rows)
			if err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}
