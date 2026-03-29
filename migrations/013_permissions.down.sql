-- Rollback 013: Permissions and Role Permissions

DELETE FROM permissions WHERE id LIKE 'a0000000-0000-0000-0000-000000000%';
DROP INDEX IF EXISTS idx_role_permissions_permission_id;
DROP INDEX IF EXISTS idx_role_permissions_role_id;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
