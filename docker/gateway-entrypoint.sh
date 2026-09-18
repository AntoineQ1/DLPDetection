#!/bin/sh
set -e

# Mitproxy certificate setup
mkdir -p /root/.mitmproxy
if [ -f /config/certs/mitmproxy-ca.pem ]; then
    cp /config/certs/mitmproxy-ca.pem /root/.mitmproxy/mitmproxy-ca.pem
fi

# Ensure IP forwarding is enabled
iptables -P FORWARD ACCEPT

# Redirect HTTP and HTTPS traffic to mitmproxy
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080

# Masquerade other outgoing traffic to allow responses to be routed back to the container
iptables -t nat -A POSTROUTING -j MASQUERADE

# Pursue with the final command
exec "$@"
