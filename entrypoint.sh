#!/bin/sh

# Set defaults
export CACHE_SIZE="${CACHE_SIZE:-5g}"
export CACHE_EXPIRY="${CACHE_EXPIRY:-12h}"

# Disable cache if size is 0
if [ "$CACHE_SIZE" = "0" ]; then
    export CACHE_SIZE="1m"
    export CACHE_EXPIRY="1s"
    echo "Caching disabled"
fi

# Replace env vars in nginx config
envsubst '${CACHE_SIZE} ${CACHE_EXPIRY}' < /usr/local/openresty/nginx/conf/nginx.conf.template > /usr/local/openresty/nginx/conf/nginx.conf

# Ensure cache directory exists and has correct permissions
mkdir -p /cache
chown -R nobody:nobody /cache
chmod -R 755 /cache

echo "Starting with CACHE_SIZE=$CACHE_SIZE, CACHE_EXPIRY=$CACHE_EXPIRY"

# Start OpenResty
exec openresty -g "daemon off;"
