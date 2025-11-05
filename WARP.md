# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

Landing page with PayPal checkout for 3D-printed holders that fit the Nuheat / Mapeheat NH AC0200 fault sensor and the Nuheat MatSense Pro (AC0100) indicator. The C++ server renders HTML templates and exposes PayPal API endpoints to prevent client-side price tampering.

## Architecture

**Backend (C++ HTTP Server)**
- Single-file server in `server/main.cpp` (~710 lines)
- Uses header-only libraries: `httplib.h` (HTTP server) and `json.hpp` (nlohmann/json)
- PayPal integration via libcurl with OAuth2 bearer token authentication
- Template rendering: loads `server/templates/index.html`, injects PayPal client ID and inline JavaScript helper
- Static file serving: mounts `public/` directory at `/static` prefix
- CORS handling: validates requests against `ALLOWED_ORIGINS` environment variable

**Key Classes & Functions**
- `PayPalClient`: handles create_order() and capture_order() via PayPal REST API
- `http_post()`, `http_post_empty()`: libcurl wrappers for HTTP requests
- `resolve_allowed_origin()`, `is_request_origin_allowed()`: CORS validation
- Price enforcement: product catalog with hardcoded $16.89 item + $6.88 shipping (total $23.77) per option in `product_catalog()` / `PayPalClient::create_order()`

**Frontend**
- `server/templates/index.html`: landing page template with placeholder variables
- `public/styles.css`: page styling
- `public/images/`: product gallery images
- Inline JavaScript (injected via `{{INLINE_PAYPAL_HELPER}}`): mounts PayPal checkout buttons, handles create/capture flow

## Commands

### Build
```bash
cd server
cmake -S . -B build
cmake --build build
```

### Run Server
Quick start with defaults (includes build if needed):
```bash
./start.sh
```

Manual start with environment variables:
```bash
export PAYPAL_CLIENT_ID=your_client_id
export PAYPAL_CLIENT_SECRET=your_secret
export PAYPAL_ENV=sandbox  # or production
export ALLOWED_ORIGINS=http://127.0.0.1,https://yourdomain.com
export INDEX_TEMPLATE_PATH=server/templates/index.html
export STATIC_ROOT=public

./server/build/nuheat_checkout_server
```

Server listens on `0.0.0.0:8080` by default (override with `SERVER_HOST`/`SERVER_PORT` env vars).

### Clean Build
```bash
rm -rf server/build
```

## Development Guidelines

**Pricing Changes**
- Update `product_catalog()` (around lines 255-270 in `server/main.cpp`) to change item and shipping amounts.
- Ensure corresponding values in `PayPalClient::create_order()` (around lines 480-520) reflect the same totals.

**Template Modifications**
- Edit `server/templates/index.html` for content/FAQ changes
- Server performs simple string replacement for `{{PAYPAL_CLIENT_ID}}` and `{{INLINE_PAYPAL_HELPER}}`
- Restart server to see template changes

**CORS Configuration**
- `ALLOWED_ORIGINS` must be set (comma-separated list)
- Server returns 403 for requests from non-allowed origins
- Use `*` to allow all origins (development only)

**PayPal Environment**
- `PAYPAL_ENV=sandbox`: uses `https://api-m.sandbox.paypal.com`
- `PAYPAL_ENV=production` or `live`: uses `https://api-m.paypal.com`

## Dependencies

**Build Requirements**
- CMake 3.16+
- C++17 compiler (Clang/GCC/MSVC)
- libcurl with SSL support

**Bundled Headers**
- `httplib.h`: cpp-httplib single-header HTTP server library
- `json.hpp`: nlohmann/json for JSON parsing
