# OpenIDX Production Deployment Guide

Deploying OpenIDX Zero Trust Access Platform on openidx.tdv.org

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Deployment Steps](#deployment-steps)
- [SSL Certificate Management](#ssl-certificate-management)
- [Service Access](#service-access)
- [Monitoring and Logging](#monitoring-and-logging)
- [Backup and Restore](#backup-and-restore)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

- **OS**: Ubuntu 22.04 LTS or Debian 12+ recommended
- **CPU**: 4+ cores
- **RAM**: 8GB minimum, 16GB recommended
- **Disk**: 50GB+ SSD with additional space for backups
- **Network**: Public IP with ports 80, 443 accessible

### Software Requirements

```bash
# Install Docker and Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Add current user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Verify installation
docker --version
docker compose version
```

### DNS Configuration

Ensure the following DNS records are configured:

| Type | Name | Value |
|------|------|-------|
| A | openidx.tdv.org | YOUR_SERVER_IP |
| A | www.openidx.tdv.org | YOUR_SERVER_IP |

Verify DNS propagation:

```bash
dig +short openidx.tdv.org
dig +short www.openidx.tdv.org
```

---

## Quick Start

```bash
# 1. Clone repository (or copy deployment files)
cd /opt/openidx/deployments/docker

# 2. Generate secrets and configure environment
cp .env.production .env.local
# Edit .env.local with your secrets (see Configuration section)

# 3. Create required directories
mkdir -p data/{postgres,redis,elasticsearch,etcd,certbot}
mkdir -p backups/postgres

# 4. Set proper permissions
chmod 600 .env.local

# 5. Start production services
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# 6. Check service health
docker compose ps
docker compose logs -f
```

---

## Configuration

### 1. Environment Variables

Copy and customize the production environment file:

```bash
cp .env.production .env.local
```

Edit `.env.local` and update the following critical values:

#### Required Secrets

```bash
# Generate with: openssl rand -base64 64
POSTGRES_PASSWORD=<generate_secure_password>
REDIS_PASSWORD=<generate_secure_password>
JWT_SECRET=<generate_64_byte_secret>
ACCESS_SESSION_SECRET=<generate_64_byte_secret>
SCIM_BEARER_TOKEN=<generate_48_byte_token>
ZITI_PWD=<generate_ziti_admin_password>
GUACAMOLE_ADMIN_PASSWORD=<generate_guacamole_password>
```

#### SMTP Configuration (Email)

```bash
# Mailgun Example
SMTP_HOST=smtp.mailgun.org
SMTP_PORT=587
SMTP_USER=postmaster@openidx.tdv.org
SMTP_PASSWORD=your_mailgun_smtp_password
SMTP_FROM=noreply@openidx.tdv.org
```

#### Domain Configuration

```bash
DOMAIN=openidx.tdv.org
OAUTH_ISSUER=https://openidx.tdv.org
CORS_ALLOWED_ORIGINS=https://openidx.tdv.org
```

### 2. Generate All Secrets at Once

```bash
# Utility script to generate all secrets
cat > generate-secrets.sh << 'EOF'
#!/bin/bash
echo "POSTGRES_PASSWORD=$(openssl rand -base64 32)"
echo "REDIS_PASSWORD=$(openssl rand -base64 32)"
echo "JWT_SECRET=$(openssl rand -base64 64)"
echo "ACCESS_SESSION_SECRET=$(openssl rand -base64 64)"
echo "SCIM_BEARER_TOKEN=$(openssl rand -base64 48)"
echo "ZITI_PWD=$(openssl rand -base64 24)"
echo "GUACAMOLE_ADMIN_PASSWORD=$(openssl rand -base64 16)"
EOF

chmod +x generate-secrets.sh
./generate-secrets.sh > .env.local
```

---

## Deployment Steps

### Step 1: Initial Setup

```bash
# Navigate to deployment directory
cd /opt/openidx/deployments/docker

# Create directory structure
mkdir -p data/{postgres,redis,elasticsearch,etcd,certbot}
mkdir -p backups/postgres
mkdir -p scripts

# Set proper permissions
chmod 700 data
chmod 700 backups
```

### Step 2: Start Infrastructure Services

```bash
# Start PostgreSQL, Redis, Elasticsearch
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    up -d postgres redis elasticsearch etcd

# Wait for services to be healthy
sleep 30

# Verify
docker compose ps postgres redis elasticsearch etcd
```

### Step 3: Start API Gateway and Core Services

```bash
# Start APISIX and OPA
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    up -d apisix etcd opa

# Wait for gateway to be ready
sleep 15

# Load production routes
./load-production-routes.sh
```

### Step 4: Start Application Services

```bash
# Start all OpenIDX services
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    up -d identity-service governance-service provisioning-service \
           audit-service admin-api oauth-service access-service

# Wait for services to start
sleep 30

# Check service health
docker compose ps
```

### Step 5: Obtain SSL Certificate

```bash
# Start nginx and certbot in dry-run mode first (staging)
CERTBOT_STAGING=true docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d nginx-proxy certbot

# Check logs for certificate status
docker compose logs -f certbot

# If staging succeeds, restart without staging flag
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d nginx-proxy certbot
```

### Step 6: Start Admin Console

```bash
# Build and start admin console
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    up -d admin-console
```

### Step 7: Start Backup Scheduler

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    up -d backup-scheduler
```

### Step 8: Verify Deployment

```bash
# Check all services are running
docker compose ps

# Check health endpoints
curl https://openidx.tdv.org/health
curl https://openidx.tdv.org/api/v1/identity/health
curl https://openidx.tdv.org/.well-known/openid-configuration
```

---

## SSL Certificate Management

### Automatic Renewal

Certbot automatically renews certificates before expiry. The renewal process:

1. Checks certificate expiry daily
2. Renews if less than 30 days remaining
3. Reloads nginx automatically

### Manual Renewal

```bash
# Check certificate status
docker compose exec certbot certbot certificates

# Force renewal
docker compose exec certbot certbot renew --force-renewal

# Reload nginx after manual renewal
docker compose exec nginx-proxy nginx -s reload
```

### Troubleshooting Certificates

```bash
# View certbot logs
docker compose logs -f certbot

# Check nginx configuration
docker compose exec nginx-proxy nginx -t

# View certificate details
docker compose exec nginx-proxy openssl x509 -in \
    /etc/letsencrypt/live/openidx.tdv.org/fullchain.pem -noout -text
```

---

## Service Access

### Public Endpoints

| Service | URL | Description |
|---------|-----|-------------|
| Admin Console | https://openidx.tdv.org/ | React admin UI |
| API Gateway | https://openidx.tdv.org/api/v1/ | All API endpoints |
| OAuth/OIDC | https://openidx.tdv.org/oauth/ | OAuth authorization |
| OIDC Discovery | https://openidx.tdv.org/.well-known/ | OpenID Connect discovery |
| JWKS | https://openidx.tdv.org/.well-known/jwks.json | Public keys |
| SCIM | https://openidx.tdv.org/scim/v2/ | User provisioning |

### Internal Services (localhost only)

| Service | Port | Description |
|---------|------|-------------|
| Identity Service | 8001 | User management |
| Governance Service | 8002 | Access reviews |
| Provisioning Service | 8003 | SCIM provisioning |
| Audit Service | 8004 | Audit logging |
| Admin API | 8005 | Admin operations |
| OAuth Service | 8006 | OAuth/OIDC provider |
| Access Service | 8007 | Zero Trust access |
| APISIX Admin API | 9188 | Gateway configuration |

---

## Monitoring and Logging

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f identity-service
docker compose logs -f nginx-proxy

# Last 100 lines
docker compose logs --tail=100
```

### Health Checks

```bash
# Service health
curl http://localhost:8001/health  # Identity
curl http://localhost:8002/health  # Governance
curl http://localhost:8003/health  # Provisioning
curl http://localhost:8004/health  # Audit
curl http://localhost:8005/health  # Admin API
curl http://localhost:8006/health  # OAuth
curl http://localhost:8007/health  # Access

# Public health check
curl https://openidx.tdv.org/health
```

### Enable Monitoring Stack (Optional)

```bash
# Deploy Prometheus, Grafana, Jaeger
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile monitoring up -d prometheus grafana jaeger

# Access Grafana: http://localhost:3001
# Default credentials: admin / admin
```

---

## Backup and Restore

### Automated Backups

Backups run automatically on schedule (default: 2 AM daily). Configure in `.env.local`:

```bash
BACKUP_SCHEDULE=0 2 * * *  # Cron expression
BACKUP_RETENTION_DAYS=7     # Days to keep backups
```

### Manual Backup

```bash
# Run backup manually
docker compose exec backup-scheduler /scripts/backup.sh

# List backups
ls -lh backups/postgres/openidx_backup_*.sql.gz
```

### Restore from Backup

```bash
# 1. Stop application services (keep database running)
docker compose stop identity-service governance-service provisioning-service \
                   audit-service admin-api oauth-service access-service

# 2. Download and decompress backup
gunzip -c backups/postgres/openidx_backup_YYYYMMDD_HHMMSS.sql.gz > /tmp/restore.sql

# 3. Restore to database
docker compose exec -T postgres psql -U openidx -d openidx < /tmp/restore.sql

# 4. Restart services
docker compose start identity-service governance-service provisioning-service \
                   audit-service admin-api oauth-service access-service
```

---

## Troubleshooting

### Common Issues

#### 1. Services Fail to Start

```bash
# Check service logs
docker compose logs <service-name>

# Verify environment variables
docker compose config

# Check resource availability
docker stats
```

#### 2. Database Connection Errors

```bash
# Verify PostgreSQL is running
docker compose ps postgres

# Check database logs
docker compose logs postgres

# Test connection from service container
docker compose exec identity-service \
    psql postgres://openidx:password@postgres:5432/openidx
```

#### 3. SSL Certificate Issues

```bash
# Check certificate status
docker compose exec certbot certbot certificates

# Force certificate renewal
docker compose exec certbot certbot renew --force-renewal

# Verify nginx can read certificates
docker compose exec nginx-proxy ls -la /etc/letsencrypt/live/openidx.tdv.org/
```

#### 4. API Gateway Routing Issues

```bash
# Check APISIX routes
curl http://localhost:9188/apisix/admin/routes \
    -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1"

# Reload routes
./load-production-routes.sh
```

#### 5. High Memory Usage

```bash
# Check resource limits
docker compose config | grep -A 5 deploy

# Adjust in docker-compose.prod.yml
deploy:
  resources:
    limits:
      memory: 1G  # Adjust as needed
```

### Performance Tuning

#### PostgreSQL

```bash
# Edit postgres configuration
docker compose exec postgres psql -U openidx -d openidx

# Analyze query performance
EXPLAIN ANALYZE <your_query>;

# Vacuum and reindex
VACUUM ANALYZE;
REINDEX DATABASE openidx;
```

#### Redis

```bash
# Check Redis info
docker compose exec redis redis-cli -a <password> INFO

# Monitor slow queries
docker compose exec redis redis-cli -a <password> SLOWLOG GET 10
```

---

## Production Checklist

- [ ] DNS A records configured
- [ ] Firewall allows ports 80, 443
- [ ] All secrets generated (POSTGRES_PASSWORD, JWT_SECRET, etc.)
- [ ] SMTP configured for email notifications
- [ ] SSL certificate obtained
- [ ] Automated backups configured
- [ ] Log aggregation enabled (optional)
- [ ] Monitoring stack deployed (optional)
- [ ] Admin console accessible
- [ ] OAuth flow tested
- [ ] API endpoints responding
- [ ] Health checks passing

---

## Support

For issues and questions:

1. Check service logs: `docker compose logs -f`
2. Review this documentation
3. Check project GitHub issues

---

## Security Considerations

1. **Never commit** `.env.production` or `.env.local` to version control
2. **Rotate secrets** periodically (JWT, database passwords)
3. **Keep software updated**: `docker compose pull && docker compose up -d`
4. **Review access logs** regularly: `docker compose logs nginx-proxy`
5. **Enable firewall** and restrict SSH access
6. **Use fail2ban** for brute force protection
7. **Regular backups** with off-site storage
