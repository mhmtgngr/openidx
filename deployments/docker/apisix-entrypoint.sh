#!/bin/sh
# Custom APISIX entrypoint that fixes Admin API IP whitelist

# Fix nginx.conf to allow Admin API access from Podman network
if [ -f /usr/local/apisix/conf/nginx.conf ]; then
    # Check if we've already patched it
    if ! grep -q "allow 10.0.0.0/8" /usr/local/apisix/conf/nginx.conf; then
        echo "Patching nginx.conf to allow Admin API access from Podman network..."
        # Add allow rule for Podman networks after the 127.0.0.0/24 line
        sed -i '/allow 127.0.0.0\/24;/a\            allow 10.0.0.0/8;' /usr/local/apisix/conf/nginx.conf
        echo "Nginx config patched successfully"
    fi
fi

# Link apisix.yaml if it exists in the shared volume
if [ -f /apisix-conf/apisix.yaml ]; then
    ln -sf /apisix-conf/apisix.yaml /usr/local/apisix/conf/apisix.yaml
fi

# Start APISIX
exec /docker-entrypoint.sh docker-start
