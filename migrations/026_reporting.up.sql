-- Migration 026: Advanced Reporting Tables

CREATE TABLE IF NOT EXISTS scheduled_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    report_type VARCHAR(50) NOT NULL,
    framework VARCHAR(100),
    parameters JSONB DEFAULT '{}',
    schedule VARCHAR(100) NOT NULL,
    format VARCHAR(10) DEFAULT 'csv',
    enabled BOOLEAN DEFAULT true,
    recipients TEXT[],
    last_run_at TIMESTAMP WITH TIME ZONE,
    next_run_at TIMESTAMP WITH TIME ZONE,
    created_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS report_exports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID,
    scheduled_report_id UUID,
    name VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    framework VARCHAR(100),
    format VARCHAR(10) NOT NULL,
    status VARCHAR(50) DEFAULT 'generating',
    file_path VARCHAR(500),
    file_size BIGINT,
    row_count INTEGER,
    error_message TEXT,
    generated_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_report_exports_org ON report_exports(org_id);
CREATE INDEX IF NOT EXISTS idx_scheduled_reports_org ON scheduled_reports(org_id);
