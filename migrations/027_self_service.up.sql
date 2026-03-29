-- Migration 027: Self-Service Portal Tables

CREATE TABLE IF NOT EXISTS group_join_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    group_id UUID NOT NULL,
    justification TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    reviewed_by UUID,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    review_comments TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, group_id)
);

CREATE TABLE IF NOT EXISTS user_application_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    application_id UUID NOT NULL,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, application_id)
);

CREATE INDEX IF NOT EXISTS idx_group_requests_user ON group_join_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_group_requests_status ON group_join_requests(status);
CREATE INDEX IF NOT EXISTS idx_user_app_assignments_user ON user_application_assignments(user_id);
