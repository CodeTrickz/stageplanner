#!/bin/bash
# Generate Traefik basic auth password hash
# Usage: ./generate-traefik-auth.sh <username> <password>

if [ $# -ne 2 ]; then
    echo "Usage: $0 <username> <password>"
    echo "Example: $0 admin mypassword"
    exit 1
fi

USERNAME=$1
PASSWORD=$2

# Try to use htpasswd if available
if command -v htpasswd &> /dev/null; then
    HASH=$(htpasswd -nb "$USERNAME" "$PASSWORD" | sed -e 's/\$/\$\$/g')
    echo "$HASH"
elif command -v docker &> /dev/null; then
    HASH=$(docker run --rm httpd:2.4-alpine htpasswd -nb "$USERNAME" "$PASSWORD" 2>/dev/null | sed -e 's/\$/\$\$/g')
    echo "$HASH"
else
    echo "Error: htpasswd or docker not found. Please install one of them."
    exit 1
fi
