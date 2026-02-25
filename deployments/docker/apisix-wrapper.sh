#!/bin/sh
# Wrapper script to patch nginx.conf and start APISIX

# Link apisix.yaml
ln -sf /apisix-conf/apisix.yaml /usr/local/apisix/conf/apisix.yaml

# Wait for etcd to be ready
echo "Waiting for etcd to be ready..."
for i in $(seq 1 60); do
    if bash -c "echo > /dev/tcp/openidx-etcd/2379" 2>/dev/null; then
        echo "etcd is ready!"
        break
    fi
    echo "Waiting for etcd... (attempt $i/60)"
    sleep 1
done

# Start APISIX in background to generate nginx.conf
/docker-entrypoint.sh docker-start &
APISIX_PID=$!

# Wait for nginx.conf to be generated
echo "Waiting for nginx.conf to be generated..."
for i in $(seq 1 60); do
    if [ -f /usr/local/apisix/conf/nginx.conf ]; then
        echo "nginx.conf found!"
        break
    fi
    # Check if APISIX process is still running
    if ! kill -0 $APISIX_PID 2>/dev/null; then
        echo "APISIX process died before generating nginx.conf, exiting..."
        exit 1
    fi
    sleep 1
done

# Patch nginx.conf to allow Admin API from Podman network
if [ -f /usr/local/apisix/conf/nginx.conf ]; then
    if ! grep -q "allow 10.0.0.0/8" /usr/local/apisix/conf/nginx.conf; then
        echo "Patching nginx.conf to allow Admin API access..."
        sed -i '/allow 127.0.0.0\/24;/a\            allow 10.0.0.0/8;\n            allow 172.16.0.0/12;\n            allow 192.168.0.0/16;' /usr/local/apisix/conf/nginx.conf
        echo "Reloading nginx with patched config..."
        # Only send HUP if process is still running
        if kill -0 $APISIX_PID 2>/dev/null; then
            kill -HUP $APISIX_PID
            echo "Nginx config patched and reloaded!"
        else
            echo "APISIX process died before reload could be sent, restarting..."
            /docker-entrypoint.sh docker-start
        fi
    fi
fi

# Wait for APISIX process (if still running)
if kill -0 $APISIX_PID 2>/dev/null; then
    wait $APISIX_PID
else
    echo "APISIX process exited, starting fresh..."
    exec /docker-entrypoint.sh docker-start
fi
