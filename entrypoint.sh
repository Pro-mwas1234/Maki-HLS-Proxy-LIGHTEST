#!/bin/sh

# Ensure cache directory exists and has correct permissions
mkdir -p /cache
chown -R nobody:nobody /cache
chmod -R 755 /cache

# Start OpenResty
exec openresty -g "daemon off;"
