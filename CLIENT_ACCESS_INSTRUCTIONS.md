# Client Access Instructions for OpenIDX

## Quick Start

### From Your Client Machine (192.168.31.x)

**IMPORTANT**: Access the admin console using the SERVER IP, not localhost:

```
http://192.168.31.76:3000
```

Do NOT use `http://localhost:3000` - that will try to connect to your own client machine!

## Problem and Solution

### The Issue
When you accessed `http://192.168.31.76:3000`, the admin console was trying to make API calls to `http://localhost:8088`, which doesn't exist on your client machine.

### The Fix
The admin console has been rebuilt to use `http://192.168.31.76:8088` for all API calls.

## Step-by-Step Access

### Option 1: Direct IP Access (Recommended for testing)

1. **Open your browser and navigate to:**
   ```
   http://192.168.31.76:3000
   ```

2. **The admin console will now:**
   - Load from: `http://192.168.31.76:3000`
   - Make API calls to: `http://192.168.31.76:8088`
   - Make OAuth calls to: `http://192.168.31.76:8006`

### Option 2: Domain Access (Requires /etc/hosts modification)

If you want to use `openidx.tdv.org`, follow these steps:

#### On Your Client Machine:

1. **Edit your hosts file:**

   **Linux/Mac:**
   ```bash
   sudo nano /etc/hosts
   ```

   **Windows (as Administrator):**
   ```
   notepad C:\Windows\System32\drivers\etc\hosts
   ```

2. **Add these lines:**
   ```
   192.168.31.76  openidx.tdv.org
   192.168.31.76  api.openidx.tdv.org
   192.168.31.76  oauth.openidx.tdv.org
   ```

3. **Save the file**

4. **Open your browser and navigate to:**
   ```
   http://openidx.tdv.org:3000
   ```

### Option 3: Rebuild for Domain (If using domain name)

If you want to use the domain name `openidx.tdv.org`, the admin console needs to be rebuilt again:

```bash
# On the server
cd /home/cmit/openidx/deployments/docker

# Update docker-compose.yml to use the domain
# Change VITE_API_URL from http://192.168.31.76:8088 to http://openidx.tdv.org:8088
# Change VITE_OAUTH_URL from http://192.168.31.76:8006 to http://openidx.tdv.org:8006

# Rebuild and restart
docker compose build --no-cache admin-console
docker compose up -d admin-console
```

## Testing API Access

From your client machine, test these URLs:

```bash
# Test API Gateway
curl http://192.168.31.76:8088/api/v1/health

# Test Identity Providers (should return empty array [])
curl http://192.168.31.76:8088/api/v1/identity/providers

# Test OAuth JWKS
curl http://192.168.31.76:8006/.well-known/jwks.json

# Test Admin Console
curl http://192.168.31.76:3000/
```

## Browser Testing

Open your browser's Developer Console (F12) and check:

1. **Network Tab**: Look for failed requests
2. **Console Tab**: Check for errors
3. **All API calls should go to**: `http://192.168.31.76:8088/api/v1/*`

## CORS Configuration

APISIX is configured to allow CORS from:
- `http://localhost:3000`
- `https://openidx.tdv.org`
- `http://openidx.tdv.org`

## Troubleshooting

### "Network Error" or "ERR_BLOCKED_BY_CLIENT"

**Problem**: Browser is blocking requests to localhost

**Solution**: Make sure you're accessing the admin console via `http://192.168.31.76:3000`, not `http://localhost:3000`

### "Failed to fetch"

**Problem**: API calls are failing

**Solution**: Check that you can access the API directly:
```bash
curl http://192.168.31.76:8088/api/v1/health
```

### CORS Errors

**Problem**: Browser blocking cross-origin requests

**Solution**: The CORS has been configured. If you still see errors, check the browser console for the exact origin being blocked.

### Nothing Loads

**Problem**: Can't access the admin console at all

**Solution**:
1. Check if the server is reachable from your client:
   ```bash
   ping 192.168.31.76
   ```

2. Check if port 3000 is accessible:
   ```bash
   telnet 192.168.31.76 3000
   ```

3. Check firewall on the server:
   ```bash
   sudo firewall-cmd --list-ports
   ```

## Current Configuration

- **Server IP**: 192.168.31.76
- **Admin Console**: http://192.168.31.76:3000
- **API Gateway**: http://192.168.31.76:8088
- **OAuth Service**: http://192.168.31.76:8006
- **Admin Console Built With**: `VITE_API_URL=http://192.168.31.76:8088`

## Next Steps

1. Try accessing http://192.168.31.76:3000 from your client browser
2. Check browser console for any remaining errors
3. If you want to use the domain name, add it to /etc/hosts or rebuild the admin console
