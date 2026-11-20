// Package repodb binds repo.Store to TimescaleDB via *store.Store, one file
// per entity. Tenant-scoped calls run in a tenant transaction (RLS); worker
// listings, retention prunes and audit appends run under the system-scope pin.
// Unique violations map to repo.ErrConflict; foreign-key violations on writes
// (a missing or cross-tenant parent — the composite (tenant_id, id) keys) and
// malformed ids map to repo.ErrNotFound.
package repodb

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/go-tangra/go-tangra-teleport/v4/internal/repo"
	"github.com/go-tangra/go-tangra-teleport/v4/internal/store"
)

// DB implements repo.Store over *store.Store.
type DB struct{ St *store.Store }

var _ repo.Store = (*DB)(nil)

// New wraps the store.
func New(st *store.Store) *DB { return &DB{St: st} }

func (d *DB) tenant(ctx context.Context, tid string, fn func(tx pgx.Tx) error) error {
	if !isUUID(tid) {
		return repo.ErrNotFound
	}
	return d.St.Tx(ctx, store.Scope{TenantID: tid}, fn)
}

func (d *DB) system(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return d.St.Tx(ctx, store.Scope{System: true}, fn)
}

type scanner interface{ Scan(dest ...any) error }

// mapErr maps store errors: no row / malformed id → ErrNotFound, unique
// violation → ErrConflict, foreign-key violation → ErrNotFound. A
// row-level-security violation (an upsert whose conflicting row belongs to
// another tenant) is ErrNotFound too: another tenant's rows do not exist for
// the caller.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return repo.ErrNotFound
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "23505":
			return repo.ErrConflict
		case "23503", "22P02", "42501": // foreign_key_violation, invalid_text_representation, RLS (insufficient_privilege)
			return repo.ErrNotFound
		}
	}
	return err
}

func affected(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return repo.ErrNotFound
	}
	return nil
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func isUUID(s string) bool { return uuidRE.MatchString(s) }

func strs(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func orNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t
}

// nullTime maps the zero time to NULL.
func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func fromNullTime(p *time.Time) time.Time {
	if p == nil {
		return time.Time{}
	}
	return *p
}

// nullUUID maps "" to NULL.
func nullUUID(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nullText(s string) *string { return nullUUID(s) }

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func jsonb(v any) []byte {
	b, _ := json.Marshal(v) // plain structs and maps: marshalling cannot fail
	return b
}

// AppendAudit implements repo.Store (system scope; platform events use the nil tenant).
func (d *DB) AppendAudit(ctx context.Context, row repo.AuditRow) error {
	var detail []byte
	if row.Detail != nil {
		detail = jsonb(row.Detail)
	}
	tenant := row.TenantID
	if tenant == "" {
		tenant = repo.NilTenant
	}
	id := row.ID
	if id == "" {
		id = store.NewID()
	}
	return d.system(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO audit_event (id, time, tenant_id, actor_kind, actor_id, cluster_id, action, target_kind,
 target_name, outcome, reason, correlation_id, detail) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			id, orNow(row.Time), tenant, row.ActorKind, row.ActorID, nullUUID(row.ClusterID), row.Action, row.TargetKind,
			row.TargetName, row.Outcome, row.Reason, row.CorrelationID, detail)
		return mapErr(err)
	})
}

// ListAudit implements repo.Store.
func (d *DB) ListAudit(ctx context.Context, tenantID string, q repo.AuditQuery) ([]repo.AuditRow, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{tenantID}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args))))
	}
	if q.ClusterID != "" {
		add("cluster_id = ?", q.ClusterID)
	}
	if q.Action != "" {
		add("action = ?", q.Action)
	}
	if q.Outcome != "" {
		add("outcome = ?", q.Outcome)
	}
	if !q.From.IsZero() {
		add("time >= ?", q.From)
	}
	if !q.To.IsZero() {
		add("time <= ?", q.To)
	}
	dir := "DESC"
	if q.Ascending {
		dir = "ASC"
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	cond := strings.Join(where, " AND ")
	var out []repo.AuditRow
	total := 0
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE `+cond, args...).Scan(&total); err != nil {
			return mapErr(err)
		}
		rows, err := tx.Query(ctx, `SELECT id, time, tenant_id, actor_kind, actor_id, cluster_id, action, target_kind, target_name,
 outcome, reason, correlation_id, detail FROM audit_event WHERE `+cond+` ORDER BY time `+dir+`, id `+dir+
			` LIMIT `+strconv.Itoa(limit)+` OFFSET `+strconv.Itoa(max(q.Offset, 0)), args...)
		if err != nil {
			return mapErr(err)
		}
		defer rows.Close()
		for rows.Next() {
			var r repo.AuditRow
			var cluster *string
			var detail []byte
			if err := rows.Scan(&r.ID, &r.Time, &r.TenantID, &r.ActorKind, &r.ActorID, &cluster, &r.Action, &r.TargetKind, &r.TargetName,
				&r.Outcome, &r.Reason, &r.CorrelationID, &detail); err != nil {
				return err
			}
			r.ClusterID = deref(cluster)
			if len(detail) > 0 {
				_ = json.Unmarshal(detail, &r.Detail)
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, total, err
}
