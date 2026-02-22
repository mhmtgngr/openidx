#!/bin/sh
# Wrapper script to patch nginx.conf and start APISIX

# Link apisix.yaml
ln -sf /apisix-conf/apisix.yaml /usr/local/apisix/conf/apisix.yaml

# Start APISIX in background to generate nginx.conf
/docker-entrypoint.sh docker-start &
APISIX_PID=$!

# Wait for nginx.conf to be generated
echo "Waiting for nginx.conf to be generated..."
for i in $(seq 1 30); do
    if [ -f /usr/local/apisix/conf/nginx.conf ]; then
        echo "nginx.conf found!"
        break
    fi
    sleep 1
done

# Patch nginx.conf to allow Admin API from Podman network
if [ -f /usr/local/apisix/conf/nginx.conf ]; then
    if ! grep -q "allow 10.0.0.0/8" /usr/local/apisix/conf/nginx.conf; then
        echo "Patching nginx.conf to allow Admin API access..."
        sed -i '/allow 127.0.0.0\/24;/a\            allow 10.0.0.0/8;\n            allow 172.16.0.0/12;\n            allow 192.168.0.0/16;' /usr/local/apisix/conf/nginx.conf
        echo "Reloading nginx with patched config..."
        kill -HUP $APISIX_PID
        echo "Nginx config patched and reloaded!"
    fi
fi

# Wait for APISIX process
wait $APISIX_PID
