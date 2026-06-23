#!/bin/sh
# BrowZer hop entrypoint. Starts nginx and reloads on config change.
# The hop SNI-demuxes per BrowZer `hop` route and rewrites the HTTP Host before
# TLS-proxying to the real upstream (the runtime sends "Host: unknown").
CONFIG_FILE="/shared-config/browzer-hop.conf"
NGINX_CONF="/etc/nginx/conf.d/default.conf"
POLL_INTERVAL=5

echo "[browzer-hop] Waiting for config file: $CONFIG_FILE"
while [ ! -f "$CONFIG_FILE" ]; do sleep 2; done
echo "[browzer-hop] Config file found"
cp "$CONFIG_FILE" "$NGINX_CONF"
nginx -g 'daemon off;' &
NGINX_PID=$!
echo "[browzer-hop] nginx started (PID $NGINX_PID)"
LAST_MTIME=$(stat -c %Y "$CONFIG_FILE" 2>/dev/null || echo 0)
while true; do
    sleep $POLL_INTERVAL
    if ! kill -0 $NGINX_PID 2>/dev/null; then
        echo "[browzer-hop] nginx died, restarting..."
        cp "$CONFIG_FILE" "$NGINX_CONF"; nginx -g 'daemon off;' & NGINX_PID=$!
        LAST_MTIME=$(stat -c %Y "$CONFIG_FILE" 2>/dev/null || echo 0); continue
    fi
    CURR_MTIME=$(stat -c %Y "$CONFIG_FILE" 2>/dev/null || echo 0)
    if [ "$CURR_MTIME" != "$LAST_MTIME" ]; then
        echo "[browzer-hop] Config changed, reloading nginx..."
        cp "$CONFIG_FILE" "$NGINX_CONF"; nginx -s reload
        LAST_MTIME=$CURR_MTIME
    fi
done
