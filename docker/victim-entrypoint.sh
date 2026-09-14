#!/bin/sh
set -e

# Replace the default route with the gateway IP
if [ -n "$GATEWAY_IP" ]; then
    ip route replace default via "$GATEWAY_IP"
fi

# Pursue with the final command
exec "$@"