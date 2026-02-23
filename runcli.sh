#!/bin/bash

export SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Matrix connection
export MATRIX_HOMESERVER="https://matrix.example.com"
export MATRIX_USER="@testuser2:matrix.example.com"
export MATRIX_PASSWORD="testpassword123"

# Auth method: jwt via Keycloak
export AUTH_METHOD="jwt"
export KEYCLOAK_URL="https://keycloak.example.com"
export KEYCLOAK_REALM="matrix"
export KEYCLOAK_CLIENT_ID="synapse-oauth"
export KEYCLOAK_CLIENT_SECRET=""
export JWT_LOGIN_TYPE="com.famedly.login.token.oauth"

# Crypto store (local path for test)
export CRYPTO_STORE_PATH="${SCRIPT_DIR}/test_crypto_store.local"

# load local settings with real data...
if [ -e "${SCRIPT_DIR}/runcli.local.include.sh" ] ; then
  source "${SCRIPT_DIR}/runcli.local.include.sh"
fi

# --- Run test ---
# ROOM_ID="!lceDNMHJdVmLqdXCpN:matrix.elasticc.io"  # testht2-room
ROOM_ID=""

echo "=== minimatrix local test ==="
echo "Homeserver: $MATRIX_HOMESERVER"
echo "User:       $MATRIX_USER"
echo "Auth:       $AUTH_METHOD"
echo ""

python -m minimatrix.cli invites

## Test 1: List rooms
#echo "--- Listing rooms ---"
#python -m minimatrix.cli rooms
#python -m minimatrix.cli --auto-join rooms

# Test 2: Send a test message
if [ -n "$ROOM_ID" ]; then
    echo ""
    echo "--- Sending test message to $ROOM_ID ---"
    python -m minimatrix.cli send --room "$ROOM_ID" --message "minimatrix local test $(date -Iseconds)"
fi


