-- +goose Up
-- Spec 002: inventory hosts enrolled as Teleport SSH nodes through their
-- inventory agent. No join token is stored; it is minted when the agent
-- fetches the material (renders counts those, at most 5).
CREATE TABLE enrollment (
  id             uuid PRIMARY KEY,
  tenant_id      uuid NOT NULL,
  cluster_id     uuid NOT NULL,
  host_id        uuid NOT NULL,
  hostname       text NOT NULL DEFAULT '' CHECK (char_length(hostname) <= 255),
  state          text NOT NULL CHECK (state IN ('pending','delivered','fetched','installing','joined','failed','unsupported','superseded','expired','cancelled')),
  reason         text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 64),
  item_id        text NOT NULL DEFAULT '' CHECK (char_length(item_id) <= 64),
  renders        integer NOT NULL DEFAULT 0 CHECK (renders >= 0),
  node_host_uuid text NOT NULL DEFAULT '' CHECK (char_length(node_host_uuid) <= 64),
  link_id        text NOT NULL DEFAULT '' CHECK (char_length(link_id) <= 64),
  expires_at     timestamptz NOT NULL,
  created_by     text NOT NULL DEFAULT '',
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, cluster_id) REFERENCES cluster (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX enrollment_cluster ON enrollment (tenant_id, cluster_id, created_at DESC);
CREATE INDEX enrollment_active ON enrollment (updated_at) WHERE state IN ('pending','delivered','fetched','installing','joined');

ALTER TABLE enrollment ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON enrollment
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid OR current_setting('app.system', true) = 'on')
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid OR current_setting('app.system', true) = 'on');
GRANT SELECT, INSERT, UPDATE, DELETE ON enrollment TO teleport_app;

-- +goose Down
DROP TABLE IF EXISTS enrollment;
