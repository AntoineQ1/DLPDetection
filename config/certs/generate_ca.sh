#!/bin/bash
set -e

# 1. Determine the absolute directory of the script
CERT_DIR="$(cd -P -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# 2. Creation of a self-signed CA certificate and private key
openssl req -x509 -new -nodes \
    -newkey rsa:2048 -sha256 -days 365 \
    -keyout "${CERT_DIR}/mitmproxy-ca.key" \
    -out "${CERT_DIR}/mitmproxy-ca-cert.pem" \
    -subj "/C=SE/O=KTH/CN=DLP Gateway Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign"

# 3. Combine the CA certificate and private key into a single PEM file
cat "${CERT_DIR}/mitmproxy-ca-cert.pem" "${CERT_DIR}/mitmproxy-ca.key" > "${CERT_DIR}/mitmproxy-ca.pem"

# 4. Copy the CA certificate to a .crt file
cp "${CERT_DIR}/mitmproxy-ca-cert.pem" "${CERT_DIR}/mitmproxy-ca-cert.crt"

echo "Valid CA certificate and private key generated successfully in ${CERT_DIR}."