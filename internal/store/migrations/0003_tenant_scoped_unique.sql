-- +goose Up
-- Lead the child-table unique keys with tenant_id. Postgres checks unique
-- indexes before the (end-of-statement) composite foreign keys, so a row that
-- names another tenant's cluster or snapshot used to fail as a duplicate:
-- a conflict that revealed the other tenant's row existed. With tenant_id in
-- the key the insert reaches the foreign key and fails as not found (SR-001).
ALTER TABLE resource_link DROP CONSTRAINT resource_link_snapshot_id_target_module_target_id_key;
ALTER TABLE resource_link ADD CONSTRAINT resource_link_tenant_target_key
  UNIQUE (tenant_id, snapshot_id, target_module, target_id);

ALTER TABLE role_mapping DROP CONSTRAINT role_mapping_cluster_id_subject_kind_subject_ref_key;
ALTER TABLE role_mapping ADD CONSTRAINT role_mapping_tenant_subject_key
  UNIQUE (tenant_id, cluster_id, subject_kind, subject_ref);

ALTER TABLE managed_user DROP CONSTRAINT managed_user_cluster_id_tangra_user_id_key;
ALTER TABLE managed_user ADD CONSTRAINT managed_user_tenant_user_key
  UNIQUE (tenant_id, cluster_id, tangra_user_id);
ALTER TABLE managed_user DROP CONSTRAINT managed_user_cluster_id_teleport_username_key;
ALTER TABLE managed_user ADD CONSTRAINT managed_user_tenant_username_key
  UNIQUE (tenant_id, cluster_id, teleport_username);

-- +goose Down
ALTER TABLE managed_user DROP CONSTRAINT managed_user_tenant_username_key;
ALTER TABLE managed_user ADD CONSTRAINT managed_user_cluster_id_teleport_username_key
  UNIQUE (cluster_id, teleport_username);
ALTER TABLE managed_user DROP CONSTRAINT managed_user_tenant_user_key;
ALTER TABLE managed_user ADD CONSTRAINT managed_user_cluster_id_tangra_user_id_key
  UNIQUE (cluster_id, tangra_user_id);

ALTER TABLE role_mapping DROP CONSTRAINT role_mapping_tenant_subject_key;
ALTER TABLE role_mapping ADD CONSTRAINT role_mapping_cluster_id_subject_kind_subject_ref_key
  UNIQUE (cluster_id, subject_kind, subject_ref);

ALTER TABLE resource_link DROP CONSTRAINT resource_link_tenant_target_key;
ALTER TABLE resource_link ADD CONSTRAINT resource_link_snapshot_id_target_module_target_id_key
  UNIQUE (snapshot_id, target_module, target_id);
