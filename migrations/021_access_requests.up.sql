-- Migration 021: Access Request and Approval Workflow Tables

CREATE TABLE IF NOT EXISTS access_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_id UUID NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID NOT NULL,
    resource_name VARCHAR(255),
    justification TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    priority VARCHAR(20) DEFAULT 'normal',
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS access_request_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL,
    approver_id UUID NOT NULL,
    step_order INTEGER DEFAULT 1,
    decision VARCHAR(50) DEFAULT 'pending',
    comments TEXT,
    decided_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS approval_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    approval_steps JSONB NOT NULL DEFAULT '[]',
    auto_approve_conditions JSONB,
    max_wait_hours INTEGER DEFAULT 72,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_access_requests_requester ON access_requests(requester_id);
CREATE INDEX IF NOT EXISTS idx_access_requests_status ON access_requests(status);
CREATE INDEX IF NOT EXISTS idx_request_approvals_request ON access_request_approvals(request_id);
CREATE INDEX IF NOT EXISTS idx_request_approvals_approver ON access_request_approvals(approver_id, decision);
CREATE INDEX IF NOT EXISTS idx_approval_policies_resource ON approval_policies(resource_type, resource_id);
