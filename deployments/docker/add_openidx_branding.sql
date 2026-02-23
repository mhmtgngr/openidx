-- Add OpenIDX organization and branding for openidx.tdv.org domain

-- Create organization for openidx.tdv.org
INSERT INTO organizations (id, name, slug, domain, plan, status, max_users, max_applications)
VALUES (
    '01234567-89ab-cdef-0123-456789abcdef',
    'OpenIDX',
    'openidx',
    'openidx.tdv.org',
    'enterprise',
    'active',
    999999,
    999999
)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    slug = EXCLUDED.slug,
    domain = EXCLUDED.domain,
    updated_at = NOW();

-- Create branding for openidx.tdv.org
INSERT INTO tenant_branding (org_id, logo_url, primary_color, secondary_color, background_color,
                             login_page_title, portal_title, powered_by_visible)
VALUES (
    '01234567-89ab-cdef-0123-456789abcdef',
    '',
    '#1e40af',
    '#3b82f6',
    '#f8fafc',
    'OpenIDX Sign In',
    'OpenIDX Portal',
    true
)
ON CONFLICT (org_id) DO UPDATE SET
    logo_url = EXCLUDED.logo_url,
    primary_color = EXCLUDED.primary_color,
    secondary_color = EXCLUDED.secondary_color,
    background_color = EXCLUDED.background_color,
    login_page_title = EXCLUDED.login_page_title,
    portal_title = EXCLUDED.portal_title,
    powered_by_visible = EXCLUDED.powered_by_visible,
    updated_at = NOW();
