# OpenIDX External Access Setup Guide

## Server Information
- **Server IP**: 192.168.31.76
- **Domain**: openidx.tdv.org
- **Configuration Date**: 2026-02-22

## Access URLs

### Admin Console
- **HTTP**: http://192.168.31.76:3000
- **HTTP (Domain)**: http://openidx.tdv.org:3000
- **After DNS setup**: https://openidx.tdv.org (when SSL is configured)

### API Gateway (APISIX)
- **HTTP**: http://192.168.31.76:8088
- **HTTPS**: http://192.168.31.76:8443
- **Admin API**: http://192.168.31.76:9188

### OAuth/OIDC Service
- **HTTP**: http://192.168.31.76:8006
- **Well-Known (JWKS)**: http://192.168.31.76:8006/.well-known/jwks.json
- **Issuer URL**: http://192.168.31.76:8006

### Microservices (via APISIX Gateway)
All microservices are routed through APISIX at port 8088:

- **Identity Service**: http://192.168.31.76:8088/api/v1/identity/*
- **Governance Service**: http://192.168.31.76:8088/api/v1/governance/*
- **Provisioning Service**: http://192.168.31.76:8088/api/v1/provisioning/*
- **Audit Service**: http://192.168.31.76:8088/api/v1/audit/*
- **Access Service**: http://192.168.31.76:8088/api/v1/access/*
- **Admin API**: http://192.168.31.76:8088/api/v1/*

### Additional Services
- **Guacamole (RDP/VNC Gateway)**: http://192.168.31.76:8085/guacamole
- **Demo Application**: http://192.168.31.76:8090
- **Mailpit (Email Testing)**: http://192.168.31.76:8025
- **Elasticsearch**: http://192.168.31.76:9200
- **PostgreSQL**: 192.168.31.76:5432
- **Redis**: 192.168.31.76:6379

## DNS Configuration

To use the domain `openidx.tdv.org`, add the following DNS records:

### For your local DNS (e.g., /etc/hosts on client):
```
192.168.31.76  openidx.tdv.org
192.168.31.76  api.openidx.tdv.org
192.168.31.76  oauth.openidx.tdv.org
```

### For production DNS (if applicable):
```
A Record: openidx.tdv.org → 192.168.31.76
A Record: api.openidx.tdv.org → 192.168.31.76
A Record: oauth.openidx.tdv.org → 192.168.31.76
```

## Firewall Configuration

Ensure the following ports are open on your firewall:

```bash
# For APISIX Gateway
sudo firewall-cmd --permanent --add-port=8088/tcp   # HTTP API Gateway
sudo firewall-cmd --permanent --add-port=8443/tcp   # HTTPS API Gateway
sudo firewall-cmd --permanent --add-port=9188/tcp   # APISIX Admin API

# For Admin Console
sudo firewall-cmd --permanent --add-port=3000/tcp

# For OAuth Service
sudo firewall-cmd --permanent --add-port=8006/tcp

# For direct service access (optional)
sudo firewall-cmd --permanent --add-port=8001/tcp   # Identity Service
sudo firewall-cmd --permanent --add-port=8002/tcp   # Governance Service
sudo firewall-cmd --permanent --add-port=8003/tcp   # Provisioning Service
sudo firewall-cmd --permanent --add-port=8004/tcp   # Audit Service
sudo firewall-cmd --permanent --add-port=8005/tcp   # Admin API
sudo firewall-cmd --permanent --add-port=8007/tcp   # Access Service

# For supporting services
sudo firewall-cmd --permanent --add-port=5432/tcp   # PostgreSQL
sudo firewall-cmd --permanent --add-port=6379/tcp   # Redis
sudo firewall-cmd --permanent --add-port=9200/tcp   # Elasticsearch
sudo firewall-cmd --permanent --add-port=8085/tcp   # Guacamole

# Reload firewall
sudo firewall-cmd --reload
```

Or for ufw (Ubuntu):
```bash
sudo ufw allow 8088/tcp
sudo ufw allow 8443/tcp
sudo ufw allow 9188/tcp
sudo ufw allow 3000/tcp
sudo ufw allow 8006/tcp
# ... add other ports as needed
```

## CORS Configuration

APISIX has been configured to allow CORS from:
- http://localhost:3000
- https://openidx.tdv.org
- http://openidx.tdv.org

This allows the admin console to communicate with the backend API when accessed via the domain.

## Testing External Access

### Test API Gateway:
```bash
curl http://192.168.31.76:8088/api/v1/health
```

### Test Admin Console:
```bash
curl http://192.168.31.76:3000/
```

### Test OAuth JWKS:
```bash
curl http://192.168.31.76:8006/.well-known/jwks.json
```

## Next Steps

1. **Update Client DNS**: Add the domain to your client's `/etc/hosts` file or configure your DNS server
2. **Configure SSL/TLS**: For production, set up SSL certificates for `openidx.tdv.org`
3. **Update OAuth Issuer**: If using HTTPS, update `OAUTH_ISSUER` in docker-compose.yml
4. **Test Access**: Open http://openidx.tdv.org:3000 in your browser

## SSL/TLS Setup (Optional)

For production use with HTTPS, you'll need to:

1. Obtain SSL certificates for `openidx.tdv.org`
2. Update APISIX configuration to use the certificates
3. Update OAuth issuer URL to use `https://`
4. Update admin console environment variables to use `https://`

## Service Status

All services are running and healthy:
- ✅ PostgreSQL
- ✅ Redis
- ✅ Elasticsearch
- ✅ APISIX Gateway
- ✅ Identity Service
- ✅ OAuth Service
- ✅ Governance Service
- ✅ Provisioning Service
- ✅ Audit Service
- ✅ Admin API
- ✅ Access Service
- ✅ Admin Console

## Troubleshooting

If you can't access the services from your client:

1. **Check firewall**: Ensure ports are open
   ```bash
   sudo firewall-cmd --list-ports
   ```

2. **Check APISIX is listening**:
   ```bash
   ss -tlnp | grep 8088
   ```

3. **Test locally**:
   ```bash
   curl http://localhost:8088/api/v1/health
   ```

4. **Check APISIX logs**:
   ```bash
   docker compose logs -f apisix
   ```

5. **Verify CORS**: Check browser console for CORS errors

## Architecture Diagram

```
Client (192.168.31.x)
    ↓
openidx.tdv.org:3000 (Admin Console)
    ↓
APISIX Gateway (192.168.31.76:8088)
    ↓
┌─────────────────────────────────────┐
│  Microservices (Docker Network)     │
│  - Identity Service (8001)          │
│  - OAuth Service (8006)             │
│  - Governance Service (8002)        │
│  - Provisioning Service (8003)      │
│  - Audit Service (8004)             │
│  - Access Service (8007)            │
│  - Admin API (8005)                 │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Data Layer                         │
│  - PostgreSQL (5432)                │
│  - Redis (6379)                     │
│  - Elasticsearch (9200)             │
└─────────────────────────────────────┘
```
