#!/bin/sh
# Front-nginx entrypoint for the OpenIDX edge (oidx-nginx).
#
# The base nginx.conf is bind-mounted and hand-maintained (admin console, OAuth,
# the *.tdv.org access-proxy wildcard, the BrowZer bootstrapper/ctrl vhosts). It
# ends with a WILDCARD include of the access-service-generated per-app BrowZer
# public vhosts:  include /shared-config/browzer-*.conf;
# (wildcard so nginx still starts if the file isn't generated yet.)
#
# This entrypoint starts nginx and reloads it whenever the generated vhosts file
# changes, so publishing/un-publishing a BrowZer app needs no nginx restart —
# mirrors deployments/docker/browzer-hop-entrypoint.sh.
VHOSTS="/shared-config/browzer-vhosts.conf"
POLL_INTERVAL=5

echo "[oidx-nginx] starting; watching $VHOSTS for changes"
nginx -g 'daemon off;' &
NGINX_PID=$!
LAST_MTIME=$(stat -c %Y "$VHOSTS" 2>/dev/null || echo 0)

while true; do
    sleep $POLL_INTERVAL
    if ! kill -0 $NGINX_PID 2>/dev/null; then
        echo "[oidx-nginx] nginx died, restarting..."
        nginx -g 'daemon off;' &
        NGINX_PID=$!
        LAST_MTIME=$(stat -c %Y "$VHOSTS" 2>/dev/null || echo 0)
        continue
    fi
    CURR_MTIME=$(stat -c %Y "$VHOSTS" 2>/dev/null || echo 0)
    if [ "$CURR_MTIME" != "$LAST_MTIME" ]; then
        if nginx -t 2>/dev/null; then
            nginx -s reload
            echo "[oidx-nginx] vhosts changed, reloaded"
        else
            echo "[oidx-nginx] generated vhosts failed nginx -t; keeping running config"
        fi
        LAST_MTIME=$CURR_MTIME
    fi
done
