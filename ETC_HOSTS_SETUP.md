# Fix CORS Issue for OpenIDX Access

## The Problem

You're accessing the admin console via `http://openidx.tdv.org:3000`, but the built JavaScript is making API calls to `http://192.168.31.76:8088`.

The browser sees this as a cross-origin request:
- **Origin**: `http://openidx.tdv.org:3000`
- **API**: `http://192.168.31.76:8088` (different origin!)

## The Solution

You need to add ALL these entries to your client's `/etc/hosts` file:

### On Your Client Machine

**Linux/Mac:**
```bash
sudo nano /etc/hosts
```

**Windows (as Administrator):**
```
notepad C:\Windows\System32\drivers\etc\hosts
```

### Add These Lines:

```
192.168.31.76  openidx.tdv.org
192.168.31.76  api.openidx.tdv.org
192.168.31.76  oauth.openidx.tdv.org
192.168.31.76  identity.openidx.tdv.org
192.168.31.76  governance.openidx.tdv.org
192.168.31.76  audit.openidx.tdv.org
192.168.31.76  provisioning.openidx.tdv.org
192.168.31.76  access.openidx.tdv.org
```

### Why This Many Entries?

This ensures that:
1. You can access the admin console: `http://openidx.tdv.org:3000`
2. API calls to `http://openidx.tdv.org:8088` will resolve to the same server
3. All microservices can be accessed via their subdomains

## Alternative: Use IP Address Everywhere

If you don't want to modify `/etc/hosts`, access everything via IP:

```
http://192.168.31.76:3000
```

But you'll need to rebuild the admin console again with the IP instead of the domain.

## Current Status

✅ Admin console rebuilt with domain: `openidx.tdv.org`
✅ APISIX CORS configured for: `http://openidx.tdv.org`
✅ Services running on: `192.168.31.76`

## Next Steps

1. Add the entries above to your `/etc/hosts` file
2. Clear your browser cache (Ctrl+Shift+Delete)
3. Access: `http://openidx.tdv.org:3000`
4. The API calls will now go to `http://openidx.tdv.org:8088` (same origin!)

## Verification

After updating `/etc/hosts`, verify from your client:

```bash
# Should resolve to 192.168.31.76
nslookup openidx.tdv.org

# Should work without CORS errors
curl http://openidx.tdv.org:8088/api/v1/identity/providers
```
