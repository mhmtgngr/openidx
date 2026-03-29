-- Migration: Compliance Reports Table
-- Description: Creates table for storing generated compliance reports (FR-M010)
--              Supports SOC2, HIPAA, GDPR, ISO 27001 compliance reporting

CREATE TABLE IF NOT EXISTS compliance_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_type VARCHAR(50) NOT NULL, -- soc2, hipaa, gdpr, iso27001, pci_dss
    report_name TEXT NOT NULL,
    description TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending, generating, completed, failed
    generated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    date_range_start TIMESTAMP WITH TIME ZONE NOT NULL,
    date_range_end TIMESTAMP WITH TIME ZONE NOT NULL,
    report_data JSONB,
    file_url TEXT,
    file_size_bytes BIGINT,
    format VARCHAR(20) DEFAULT 'json', -- json, pdf, csv
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_compliance_reports_type ON compliance_reports(report_type);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_status ON compliance_reports(status);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_created_by ON compliance_reports(generated_by);
CREATE INDEX IF NOT EXISTS idx_compliance_reports_date_range ON compliance_reports(date_range_start, date_range_end);

COMMENT ON TABLE compliance_reports IS 'Generated compliance reports for various regulatory frameworks (FR-M010)';
