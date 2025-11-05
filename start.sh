#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$ROOT_DIR/server"
BUILD_DIR="${BUILD_DIR:-$SERVER_DIR/build}"
BINARY_NAME="nuheat_checkout_server"
BINARY_PATH="$BUILD_DIR/$BINARY_NAME"

# Default to sandbox PayPal credentials if they were not exported already.
: "${PAYPAL_CLIENT_ID:=Ad5bl8F7Fl51qwyJYKNm1CqrM1fjzIKjZ7mQjYxzHIj8Y45AJbiOg_Qx8Qd0Q-_JGYcJL1JiDrn_aOa7}"
: "${PAYPAL_CLIENT_SECRET:=EFlbbC9DtlJ6X94sA2rz_YLag_QYev2OPrEVLC_UNOjc0Bm3cJEB9_iQbhWyccN2vt1IdmbureAaU03R}"
: "${PAYPAL_ENV:=sandbox}"
: "${PAYPAL_WEBHOOK_ID:=55M68644152697312}"
: "${ADMIN_ACCESS_PIN:=483726}"
export PAYPAL_CLIENT_ID PAYPAL_CLIENT_SECRET PAYPAL_ENV PAYPAL_WEBHOOK_ID ADMIN_ACCESS_PIN

# Resolve template/static paths so the binary can be run from repo root.
: "${INDEX_TEMPLATE_PATH:=$SERVER_DIR/templates/index.html}"
: "${STATIC_ROOT:=$ROOT_DIR/public}"
export INDEX_TEMPLATE_PATH STATIC_ROOT

: "${ALLOWED_ORIGINS:=http://127.0.0.1,https://nuheathanger.clipsandwedges.com,https://nuheat.clipsandwedges.com}"
export ALLOWED_ORIGINS

if [[ ! -x "$BINARY_PATH" ]]; then
  echo "[start] executable not found. building $BINARY_NAME..."
  cmake -S "$SERVER_DIR" -B "$BUILD_DIR"
  cmake --build "$BUILD_DIR" --target "$BINARY_NAME"
fi

echo "[start] launching $BINARY_NAME from $BINARY_PATH"
exec "$BINARY_PATH"
