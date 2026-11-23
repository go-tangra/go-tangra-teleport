-- +goose Up
-- Spec 005: the per-cluster access identity brokered access issues
-- certificates with (a sign-in identity of tangra-access). The identity
-- itself is in the secret store; only its reference and public metadata are
-- here. The row cascades with the cluster; the module removes the secret.
CREATE TABLE cluster_access_identity (
  cluster_id     uuid PRIMARY KEY,
  tenant_id      uuid NOT NULL,
  credential_ref text NOT NULL CHECK (char_length(credential_ref) BETWEEN 1 AND 512),
  teleport_user  text NOT NULL CHECK (char_length(teleport_user) BETWEEN 1 AND 256),
  issued_at      timestamptz,
  expires_at     timestamptz NOT NULL,
  updated_at     timestamptz NOT NULL DEFAULT now(),
  updated_by     text NOT NULL DEFAULT '' CHECK (char_length(updated_by) <= 256),
  FOREIGN KEY (tenant_id, cluster_id) REFERENCES cluster (tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE cluster_access_identity ENABLE ROW LEVEL SECURITY;
ALTER TABLE cluster_access_identity FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON cluster_access_identity
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid OR current_setting('app.system', true) = 'on')
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid OR current_setting('app.system', true) = 'on');
GRANT SELECT, INSERT, UPDATE, DELETE ON cluster_access_identity TO teleport_app;

-- +goose Down
DROP TABLE IF EXISTS cluster_access_identity;
