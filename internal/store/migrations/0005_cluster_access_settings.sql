-- +goose Up
-- Spec 004 (R4): per-cluster brokered-access settings. Nothing issued is
-- stored: certificates and keys live in memory only. A cluster without a
-- row uses the default lifetime (480 minutes).
CREATE TABLE cluster_access_settings (
  cluster_id         uuid PRIMARY KEY,
  tenant_id          uuid NOT NULL,
  access_ttl_minutes integer NOT NULL DEFAULT 480 CHECK (access_ttl_minutes BETWEEN 15 AND 720),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  updated_by         text NOT NULL DEFAULT '' CHECK (char_length(updated_by) <= 256),
  FOREIGN KEY (tenant_id, cluster_id) REFERENCES cluster (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE cluster_access_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE cluster_access_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON cluster_access_settings
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid OR current_setting('app.system', true) = 'on')
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid OR current_setting('app.system', true) = 'on');
GRANT SELECT, INSERT, UPDATE, DELETE ON cluster_access_settings TO teleport_app;

-- +goose Down
DROP TABLE IF EXISTS cluster_access_settings;
