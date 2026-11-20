-- +goose Up
-- The Teleport module's tables (data-model.md). Teleport-owned objects (users,
-- roles, locks, tokens, resources, audit events, sessions) are NOT stored:
-- they are read live from the cluster. No column holds a secret value:
-- credentials are warden references only (cluster.credential_ref).
--
-- Every tenant table carries tenant_id and is protected by row-level security
-- on app.tenant_id (set per transaction by internal/store); trusted system
-- paths (workers, retention prunes, audit writer) set app.system='on'.
-- teleport_app is NOBYPASSRLS. Child rows reference their parent through
-- (tenant_id, id) composite foreign keys so the database refuses a link across
-- tenants (FK checks bypass RLS). Deleting a cluster cascades to everything
-- that hangs off it; a deployment draft only loses its registered cluster.
-- The audit_event hypertable is append-only for the application role.

CREATE TABLE cluster (
  id                    uuid PRIMARY KEY,
  tenant_id             uuid NOT NULL,
  display_name          text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 64),
  proxy_addr            text NOT NULL CHECK (char_length(proxy_addr) BETWEEN 1 AND 300),
  cluster_name          text NOT NULL DEFAULT '' CHECK (char_length(cluster_name) <= 253),
  edition               text NOT NULL DEFAULT 'unknown' CHECK (edition IN ('community','enterprise','unknown')),
  server_version        text NOT NULL DEFAULT '' CHECK (char_length(server_version) <= 64),
  credential_ref        text NOT NULL CHECK (credential_ref LIKE 'warden:_%' OR credential_ref LIKE 'file:_%'),
  credential_kind       text NOT NULL DEFAULT 'identity_file' CHECK (credential_kind IN ('identity_file')),
  credential_identity   text NOT NULL DEFAULT '' CHECK (char_length(credential_identity) <= 256),
  credential_expires_at timestamptz,
  status                text NOT NULL DEFAULT 'connected'
                        CHECK (status IN ('connected','unreachable','credential_expiring','credential_invalid','unsupported_version')),
  status_reason         text NOT NULL DEFAULT '' CHECK (char_length(status_reason) <= 512),
  missing_permissions   text[] NOT NULL DEFAULT '{}',
  last_contact_at       timestamptz,
  counts                jsonb NOT NULL DEFAULT '{}',
  settings              jsonb NOT NULL DEFAULT '{}',
  created_by            text NOT NULL DEFAULT '',
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, display_name),
  UNIQUE (tenant_id, id)
);

-- Join-token metadata: the token value is returned once and discarded.
CREATE TABLE join_token (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL,
  cluster_id    uuid NOT NULL,
  token_hash    bytea NOT NULL,
  resource_type text NOT NULL CHECK (resource_type IN ('node','app','db','kube','desktop')),
  expires_at    timestamptz NOT NULL,
  revoked_at    timestamptz,
  created_by    text NOT NULL DEFAULT '',
  created_at    timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, cluster_id) REFERENCES cluster (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX join_token_cluster ON join_token (tenant_id, cluster_id, created_at DESC);
CREATE INDEX join_token_expiry ON join_token (expires_at);

CREATE TABLE resource_snapshot (
  id             uuid PRIMARY KEY,
  tenant_id      uuid NOT NULL,
  cluster_id     uuid NOT NULL,
  kind           text NOT NULL CHECK (kind IN ('node','app','db','kube','desktop')),
  teleport_name  text NOT NULL CHECK (char_length(teleport_name) BETWEEN 1 AND 512),
  hostname       text,
  addr           text,
  labels         jsonb NOT NULL DEFAULT '{}',
  agent_version  text NOT NULL DEFAULT '',
  online         boolean NOT NULL DEFAULT true,
  last_seen_at   timestamptz,
  offline_since  timestamptz,
  flagged_at     timestamptz,
  UNIQUE (cluster_id, kind, teleport_name),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, cluster_id) REFERENCES cluster (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE resource_link (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL,
  snapshot_id   uuid NOT NULL,
  target_module text NOT NULL CHECK (target_module IN ('inventory','asset')),
  target_id     text NOT NULL CHECK (char_length(target_id) BETWEEN 1 AND 128),
  match         text NOT NULL CHECK (match IN ('auto','confirmed','candidate')),
  matched_on    text NOT NULL CHECK (matched_on IN ('hostname','ip')),
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (snapshot_id, target_module, target_id),
  FOREIGN KEY (tenant_id, snapshot_id) REFERENCES resource_snapshot (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX resource_link_target ON resource_link (tenant_id, target_module, target_id);

CREATE TABLE role_mapping (
  id             uuid PRIMARY KEY,
  tenant_id      uuid NOT NULL,
  cluster_id     uuid NOT NULL,
  subject_kind   text NOT NULL CHECK (subject_kind IN ('module_role','group')),
  subject_ref    text NOT NULL CHECK (char_length(subject_ref) BETWEEN 1 AND 128),
  teleport_roles text[] NOT NULL CHECK (cardinality(teleport_roles) BETWEEN 1 AND 16),
  logins         text[] NOT NULL DEFAULT '{}' CHECK (cardinality(logins) <= 32),
  created_by     text NOT NULL DEFAULT '',
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cluster_id, subject_kind, subject_ref),
  FOREIGN KEY (tenant_id, cluster_id) REFERENCES cluster (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE managed_user (
  id                uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL,
  cluster_id        uuid NOT NULL,
  tangra_user_id    uuid NOT NULL,
  teleport_username text NOT NULL CHECK (char_length(teleport_username) BETWEEN 1 AND 256),
  state             text NOT NULL CHECK (state IN ('provisioning','active','locked_pending_deletion','error')),
  applied_roles     text[] NOT NULL DEFAULT '{}',
  applied_logins    text[] NOT NULL DEFAULT '{}',
  lock_name         text,
  deprovision_after timestamptz,
  last_synced_at    timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (cluster_id, tangra_user_id),
  UNIQUE (cluster_id, teleport_username),
  FOREIGN KEY (tenant_id, cluster_id) REFERENCES cluster (tenant_id, id) ON DELETE CASCADE
);

-- cluster_id NULL = every cluster of the tenant (MATCH SIMPLE skips the FK).
CREATE TABLE alert_rule (
  id              uuid PRIMARY KEY,
  tenant_id       uuid NOT NULL,
  cluster_id      uuid,
  name            text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
  condition_kind  text NOT NULL CHECK (condition_kind IN ('teleport_event','cluster_unreachable','credential_expiring','resource_offline')),
  event_types     text[] NOT NULL DEFAULT '{}',
  threshold_count integer NOT NULL DEFAULT 0 CHECK (threshold_count = 0 OR threshold_count BETWEEN 1 AND 1000),
  window_minutes  integer NOT NULL DEFAULT 0 CHECK (window_minutes = 0 OR window_minutes BETWEEN 1 AND 1440),
  recipients      jsonb NOT NULL DEFAULT '{}',
  enabled         boolean NOT NULL DEFAULT true,
  created_by      text NOT NULL DEFAULT '',
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, cluster_id) REFERENCES cluster (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE alert_cursor (
  cluster_id      uuid PRIMARY KEY,
  tenant_id       uuid NOT NULL,
  last_event_time timestamptz,
  last_event_id   text NOT NULL DEFAULT '',
  updated_at      timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, cluster_id) REFERENCES cluster (tenant_id, id) ON DELETE CASCADE
);

CREATE TABLE alert_delivery (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL,
  rule_id      uuid NOT NULL,
  cluster_id   uuid NOT NULL,
  window_key   text NOT NULL CHECK (char_length(window_key) BETWEEN 1 AND 128),
  delivered_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (rule_id, cluster_id, window_key),
  FOREIGN KEY (tenant_id, rule_id) REFERENCES alert_rule (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, cluster_id) REFERENCES cluster (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX alert_delivery_age ON alert_delivery (delivered_at);

CREATE TABLE deployment_draft (
  id                    uuid PRIMARY KEY,
  tenant_id             uuid NOT NULL,
  domain                text NOT NULL CHECK (char_length(domain) BETWEEN 1 AND 253),
  cert_mode             text NOT NULL CHECK (cert_mode IN ('acme','own_cert')),
  acme_email            text NOT NULL DEFAULT '',
  teleport_version      text NOT NULL CHECK (teleport_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
  admin_username        text NOT NULL DEFAULT '',
  admin_logins          text[] NOT NULL DEFAULT '{}',
  checks                jsonb NOT NULL DEFAULT '[]',
  registered_cluster_id uuid,
  created_by            text NOT NULL DEFAULT '',
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, registered_cluster_id) REFERENCES cluster (tenant_id, id) ON DELETE SET NULL (registered_cluster_id)
);

-- Append-only audit hypertable partitioned by its timestamp. A hypertable
-- carries no PRIMARY KEY excluding the partition column, so ids are
-- app-generated uuid v7. Platform-scope events use the nil tenant. Detail is
-- redacted jsonb: never credentials, token values, invite links or role YAML
-- (role changes record before/after SHA-256 hashes).
CREATE TABLE audit_event (
  id             uuid NOT NULL,
  time           timestamptz NOT NULL DEFAULT now(),
  tenant_id      uuid NOT NULL,
  actor_kind     text NOT NULL CHECK (actor_kind IN ('user','module','worker','system')),
  actor_id       text NOT NULL DEFAULT '',
  cluster_id     uuid,
  action         text NOT NULL CHECK (action LIKE 'teleport.%'),
  target_kind    text NOT NULL DEFAULT '',
  target_name    text NOT NULL DEFAULT '',
  outcome        text NOT NULL CHECK (outcome IN ('success','failure','unknown')),
  reason         text NOT NULL DEFAULT '',
  correlation_id text NOT NULL DEFAULT '',
  detail         jsonb
);
SELECT create_hypertable('audit_event', 'time', if_not_exists => TRUE, migrate_data => TRUE);
CREATE INDEX audit_event_tenant ON audit_event (tenant_id, time DESC);
CREATE INDEX audit_event_cluster ON audit_event (tenant_id, cluster_id, time DESC);

-- Row-level security. NULLIF keeps the uuid cast valid on a pooled connection
-- where a previous transaction-local setting reset app.tenant_id to ''.
-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'cluster','join_token','resource_snapshot','resource_link','role_mapping','managed_user',
    'alert_rule','alert_cursor','alert_delivery','deployment_draft','audit_event'
  ]
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format($p$CREATE POLICY tenant_isolation ON %I USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid OR current_setting('app.system', true) = 'on') WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid OR current_setting('app.system', true) = 'on')$p$, t);
    IF t = 'audit_event' THEN
      EXECUTE format('GRANT SELECT, INSERT ON %I TO teleport_app', t);
    ELSE
      EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO teleport_app', t);
    END IF;
  END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS audit_event;
DROP TABLE IF EXISTS deployment_draft;
DROP TABLE IF EXISTS alert_delivery;
DROP TABLE IF EXISTS alert_cursor;
DROP TABLE IF EXISTS alert_rule;
DROP TABLE IF EXISTS managed_user;
DROP TABLE IF EXISTS role_mapping;
DROP TABLE IF EXISTS resource_link;
DROP TABLE IF EXISTS resource_snapshot;
DROP TABLE IF EXISTS join_token;
DROP TABLE IF EXISTS cluster;
