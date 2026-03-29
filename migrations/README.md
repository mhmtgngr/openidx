# Database Migration System

This directory contains versioned database migrations for OpenIDX.

## Overview

The migration system provides:
- Versioned schema migrations with up/down SQL
- Automatic migration tracking via `schema_migrations` table
- CLI tool for manual migration control
- Optional auto-migration on service startup

## Migration Files

Each migration has two files:
- `XXX_name.up.sql` - Applies the migration
- `XXX_name.down.sql` - Rolls back the migration

Where `XXX` is a zero-padded 3-digit version number (e.g., 001, 002).

## Current Migrations

| Version | Name | Description |
|---------|------|-------------|
| 001 | initial_schema | Core tables: users, groups, roles |
| 002 | oauth_oidc | OAuth 2.0 / OIDC tables |
| 003 | scim | SCIM 2.0 provisioning |
| 004 | governance | Access reviews and policies |
| 005 | mfa | Multi-factor authentication (TOTP, WebAuthn, Push) |
| 006 | sessions | Session management |
| 007 | applications | Application management |
| 008 | audit_compliance | Audit and compliance tables |
| 009 | indexes | Performance indexes |
| 010 | seed_data | Initial seed data (admin user, roles) |
| 011 | identity_providers | External IdP integration (OIDC/SAML) |
| 012 | provisioning_rules | Provisioning rules and password reset |
| 013 | permissions | Permissions and role permissions |
| 014 | system_settings | System configuration |
| 015 | directory_integrations | LDAP/Azure AD/Google integration |
| 016 | proxy_routes | Zero Trust Access Proxy |
| 017 | openziti | OpenZiti integration |
| 018 | directory_sync | Directory sync state and logs |
| 019 | conditional_access | Risk-based authentication |
| 020 | api_keys_webhooks | API keys, webhooks, invitations |
| 021 | access_requests | Access request workflow |
| 022 | security_alerts | Security alerts and threat detection |
| 023 | password_management | Password history and credential rotation |
| 024 | session_enhancements | Enhanced session fields |
| 025 | multitenancy | Organization support |
| 026 | reporting | Scheduled reports |
| 027 | self_service | Self-service portal |
| 028 | notifications | Notification system |
| 029 | ziti_enhanced | OpenZiti posture checks and policy sync |

## CLI Usage

```bash
# Run all pending migrations
go run cmd/migrate/main.go up

# Run migrations up to specific version
go run cmd/migrate/main.go up 10

# Rollback last migration
go run cmd/migrate/main.go down

# Rollback to specific version
go run cmd/migrate/main.go down 5

# Show migration status
go run cmd/migrate/main.go status

# Show current version
go run cmd/migrate/main.go version
```

## Environment Variables

- `DATABASE_URL` - PostgreSQL connection string (required)

## Auto-Migration on Startup

Services can automatically run migrations on startup when configured:

```yaml
# config.yaml
auto_migrate: true
```

Or via environment variable:
```bash
export AUTO_MIGRATE=true
```

## Creating New Migrations

1. Create numbered up/down files in `migrations/`:
   ```
   migrations/030_new_feature.up.sql
   migrations/030_new_feature.down.sql
   ```

2. Add migration to `internal/migrations/loader.go`:
   ```go
   {
       Version: 30,
       Name: "new_feature",
       Description: "Add new feature tables",
       UpSQL: newFeatureUp,
       DownSQL: newFeatureDown,
   },
   ```

3. Add SQL content to `internal/migrations/sql.go`:
   ```go
   const (
       newFeatureUp = `-- SQL to apply migration`
       newFeatureDown = `-- SQL to rollback migration`
   )
   ```

## Tables

### schema_migrations
Tracks applied migrations:
- `version` - Migration version number
- `name` - Migration name
- `description` - Migration description
- `applied_at` - When migration was applied
- `duration_ms` - Time taken to apply

### schema_migration_lock
Prevents concurrent migrations:
- `id` - Lock identifier (always 1)
- `locked` - Whether lock is held
- `locked_at` - When lock was acquired
- `locked_by` - Process holding the lock

## Migration Locking

The system uses advisory locks via `schema_migration_lock` table to prevent
concurrent migrations. Only one process can run migrations at a time.

## Error Handling

- Migrations run in transactions
- Failed migrations are rolled back automatically
- Lock is released even on failure
- Detailed error messages logged
