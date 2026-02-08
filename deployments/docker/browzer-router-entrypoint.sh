#!/bin/sh
# BrowZer Router Entrypoint
# Starts nginx and watches for config file changes, reloading gracefully.

CONFIG_FILE="/shared-config/browzer-router.conf"
NGINX_CONF="/etc/nginx/conf.d/browzer-router.conf"
POLL_INTERVAL=5

# Wait for config file to exist
echo "[browzer-router] Waiting for config file: $CONFIG_FILE"
while [ ! -f "$CONFIG_FILE" ]; do
    sleep 2
done
echo "[browzer-router] Config file found"

# Copy config and start nginx
cp "$CONFIG_FILE" "$NGINX_CONF"
nginx -g 'daemon off;' &
NGINX_PID=$!
echo "[browzer-router] nginx started (PID $NGINX_PID)"

# Track config mtime
LAST_MTIME=$(stat -c %Y "$CONFIG_FILE" 2>/dev/null || echo 0)

# Poll for config changes
while true; do
    sleep $POLL_INTERVAL

    # Check if nginx crashed
    if ! kill -0 $NGINX_PID 2>/dev/null; then
        echo "[browzer-router] nginx died, restarting..."
        cp "$CONFIG_FILE" "$NGINX_CONF"
        nginx -g 'daemon off;' &
        NGINX_PID=$!
        LAST_MTIME=$(stat -c %Y "$CONFIG_FILE" 2>/dev/null || echo 0)
        continue
    fi

    # Check for config changes
    CURR_MTIME=$(stat -c %Y "$CONFIG_FILE" 2>/dev/null || echo 0)
    if [ "$CURR_MTIME" != "$LAST_MTIME" ]; then
        echo "[browzer-router] Config changed, reloading nginx..."
        cp "$CONFIG_FILE" "$NGINX_CONF"
        nginx -s reload
        LAST_MTIME=$CURR_MTIME
    fi
done
