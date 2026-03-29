-- Migration 001: Initial Schema
-- Description: Core tables for users, groups, and roles

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    enabled BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE,
    -- Password policy fields
    password_changed_at TIMESTAMP WITH TIME ZONE,
    password_must_change BOOLEAN DEFAULT false,
    -- Account lockout fields
    failed_login_count INTEGER DEFAULT 0,
    last_failed_login_at TIMESTAMP WITH TIME ZONE,
    locked_until TIMESTAMP WITH TIME ZONE
);

-- Groups table
CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    parent_id UUID REFERENCES groups(id),
    allow_self_join BOOLEAN DEFAULT false,
    require_approval BOOLEAN DEFAULT false,
    max_members INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Group memberships
CREATE TABLE IF NOT EXISTS group_memberships (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, group_id)
);

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    is_composite BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Composite roles (role hierarchy)
CREATE TABLE IF NOT EXISTS composite_roles (
    parent_role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    child_role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (parent_role_id, child_role_id)
);

-- User roles (many-to-many relationship)
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by UUID REFERENCES users(id),
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);
