-- Rollback 021: Access Request and Approval Workflow Tables

DROP INDEX IF EXISTS idx_approval_policies_resource;
DROP INDEX IF EXISTS idx_request_approvals_approver;
DROP INDEX IF EXISTS idx_request_approvals_request;
DROP INDEX IF EXISTS idx_access_requests_status;
DROP INDEX IF EXISTS idx_access_requests_requester;
DROP TABLE IF EXISTS approval_policies;
DROP TABLE IF EXISTS access_request_approvals;
DROP TABLE IF EXISTS access_requests;
