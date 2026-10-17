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

# Let the user override the default command if arguments are provided
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

# Enable addon if available
ADDON_OPT=""
if [ -f /app/detection/l7_web/addon.py ]; then
    echo "[gateway] Loading the L7 Web addon..."
    ADDON_OPT="-s /app/detection/l7_web/addon.py"
fi

# Run mitmdump
exec mitmdump --mode transparent --showhost --listen-port 8080 "$ADDON_OPT"