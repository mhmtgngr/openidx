# Troubleshooting

## Services Won't Start

### "Failed to connect to database"

PostgreSQL isn't ready or credentials are wrong.

```bash
# Check if PostgreSQL is running
docker compose -f deployments/docker/docker-compose.infra.yml ps postgres

# Test connection
docker exec -it openidx-postgres pg_isready -U openidx

# Check logs
docker compose -f deployments/docker/docker-compose.infra.yml logs postgres
```

Make sure `DATABASE_URL` in your `.env` matches the `POSTGRES_PASSWORD`.

### "Failed to connect to Redis"

```bash
docker compose -f deployments/docker/docker-compose.infra.yml ps redis
docker exec -it openidx-redis redis-cli ping
```

### Port Already in Use

If a port is occupied:

```bash
# Find what's using a port (Linux/macOS)
lsof -i :8001

# Or on Windows
netstat -ano | findstr :8001
```

Stop the conflicting process or change the port in your `.env`.

## Authentication Issues

### "invalid token" or "missing authorization header"

- Check that the OAuth service is running: `curl http://localhost:8006/health`
- Verify the OIDC discovery endpoint: `curl http://localhost:8006/.well-known/openid-configuration`
- In development mode (`APP_ENV=development`), auth middleware is bypassed on some services

### JWKS Fetch Failures

If services can't validate tokens:

```bash
# Check JWKS endpoint
curl http://localhost:8006/.well-known/jwks.json

# Check Keycloak (if using Keycloak auth)
curl http://localhost:8180/realms/openidx/protocol/openid-connect/certs
```

The JWKS cache has a 1-hour TTL. Restart the service to clear the cache.

### CORS Errors in Browser

CORS is configured to allow all origins in development. In production, update the CORS middleware in `internal/common/middleware/middleware.go` to restrict allowed origins.

## Docker Issues

### Containers Keep Restarting

Check logs for the failing container:

```bash
docker compose -f deployments/docker/docker-compose.yml logs --tail 50 identity-service
```

Common causes:

- Missing environment variables — run `./scripts/generate-secrets.sh`
- Database not ready — check the depends_on health conditions
- Port conflicts — another service using the same port

### Out of Disk Space

Docker volumes can grow large. Clean up:

```bash
# Remove stopped containers and unused images
docker system prune

# Remove all volumes (WARNING: destroys data)
docker volume prune
```

### Build Failures

```bash
# Rebuild without cache
docker compose -f deployments/docker/docker-compose.yml build --no-cache

# Check Go module downloads
go mod download
go mod verify
```

## Frontend Issues

### Blank Page / API Errors

Check that the API gateway and backend services are running:

```bash
curl http://localhost:8088/api/v1/dashboard
```

Verify `VITE_API_URL` and `VITE_OAUTH_URL` in the frontend environment match your running services.

### npm install Fails

```bash
# Clear npm cache
cd web/admin-console
rm -rf node_modules package-lock.json
npm install
```

## Monitoring

### No Metrics in Prometheus

1. Check that the service `/metrics` endpoint responds:
   ```bash
   curl http://localhost:8001/metrics
   ```
2. Check Prometheus targets: [http://localhost:9090/targets](http://localhost:9090/targets)
3. Verify `deployments/docker/prometheus/prometheus.yml` has the correct service hostnames

### Grafana Dashboards Empty

1. Check Prometheus datasource in Grafana: Settings > Data Sources > Prometheus
2. Verify the datasource URL is `http://prometheus:9090` (internal Docker network)
3. Check that metrics are being scraped: query `up` in Prometheus

## Getting Help

- [GitHub Issues](https://github.com/openidx/openidx/issues) — bug reports and feature requests
- [Security Issues](https://github.com/openidx/openidx/blob/main/SECURITY.md) — report via security@openidx.io
