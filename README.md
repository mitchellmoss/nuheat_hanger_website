# Nuheat / Mapeheat Fault Sensor Hook Holder Landing Page

Landing page + PayPal checkout gateway for selling the 3D-printed NH AC0200 fault sensor hook holder directly (outside eBay). The C++ server renders the HTML template and exposes the PayPal API endpoints so product pricing cannot be tampered with in the browser.

## Getting Started

1. Build and run the C++ server (see “Secure Checkout Server” below).
2. Visit <http://localhost:8080> (or whichever host/port you configure) to preview the site locally.

## PayPal Checkout

1. Set the `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, and `PAYPAL_ENV` environment variables before launching the server. The client ID is baked into the rendered HTML while the secret stays server-side.
2. The backend enforces $16.89 item price + $6.88 shipping (total $23.77). Update the values inside `PayPalClient::create_order()` in `server/main.cpp` if you change pricing.
3. After publishing, test the flow in PayPal sandbox (or a low-dollar live transaction) before sending real traffic.

## Search Engine Optimization

- The page includes meta tags for title, description, Open Graph, and Twitter cards.
- A JSON-LD product schema is embedded to help search engines understand the offer and pricing.
- All product images are stored locally under `public/images/` with descriptive alt text.

## Customization

- Update copy/FAQ content inside `server/templates/index.html`.
- Adjust colors, spacing, or typography via `public/styles.css`.
- Swap or add gallery images by placing new files in `public/images/` and updating the markup in the template.
- Override defaults by setting `INDEX_TEMPLATE_PATH` or `STATIC_ROOT` environment variables if you reorganize the directories.

## Secure Checkout Server (C++)

The `/api/create-order` and `/api/capture-order` endpoints are implemented in C++ under `server/` so pricing cannot be modified in the browser.

### Requirements

- CMake 3.16+
- A C++17 compiler (Clang, GCC, or MSVC)
- libcurl with SSL support

### Build & Run

```bash
cd server
cmake -S . -B build
cmake --build build

# Environment variables required by the server
export PAYPAL_CLIENT_ID=your_paypal_client_id
export PAYPAL_CLIENT_SECRET=your_paypal_client_secret
export PAYPAL_ENV=sandbox            # or production
# Optional: restrict CORS to a single origin
# export ALLOWED_ORIGIN=https://yourdomain.com

./build/nuheat_checkout_server
```

The server listens on `0.0.0.0:8080` by default (override with `SERVER_HOST` / `SERVER_PORT`). Static assets (CSS + images) are served from `public/` under the `/static` prefix.

## Deployment

Deploy the C++ service behind HTTPS (for example, behind Nginx/Apache or a managed load balancer). Terminate TLS in front of the binary, keep PayPal credentials in environment variables or a secrets manager, and restrict `ALLOWED_ORIGIN` to your production domain so only your storefront can invoke the checkout endpoints.
