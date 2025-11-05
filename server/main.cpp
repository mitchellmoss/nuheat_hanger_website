#include "httplib.h"
#include "json.hpp"

#include <curl/curl.h>

#include <cstdlib>
#include <functional>
#include <fstream>
#include <iostream>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <stdexcept>
#include <unordered_map>
#include <algorithm>
#include <cctype>
#include <array>
#include <iomanip>

using json = nlohmann::json;

namespace {

struct HttpResponse {
  CURLcode code{CURLE_OK};
  long status{0};
  std::string body;
  std::string error_message;

  bool ok() const {
    return code == CURLE_OK && status >= 200 && status < 300;
  }
};

size_t write_to_string(void *contents, size_t size, size_t nmemb, void *userp) {
  const size_t total = size * nmemb;
  auto *buffer = static_cast<std::string *>(userp);
  buffer->append(static_cast<const char *>(contents), total);
  return total;
}

HttpResponse http_post(const std::string &url,
                       const std::string &payload,
                       const std::vector<std::string> &headers,
                       const std::optional<std::string> &user_pwd = std::nullopt,
                       const std::optional<long> timeout_seconds = 10) {
  CURL *curl = curl_easy_init();
  HttpResponse response;

  if (!curl) {
    response.code = CURLE_FAILED_INIT;
    response.error_message = "Failed to init curl";
    return response;
  }

  struct curl_slist *header_list = nullptr;
  for (const auto &header : headers) {
    header_list = curl_slist_append(header_list, header.c_str());
  }

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload.size());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_string);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "nuheat-checkout-server/1.0");

  if (timeout_seconds) {
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, *timeout_seconds);
  }

  if (user_pwd) {
    curl_easy_setopt(curl, CURLOPT_USERPWD, user_pwd->c_str());
  }

  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

  response.code = curl_easy_perform(curl);

  if (response.code != CURLE_OK) {
    response.error_message = curl_easy_strerror(response.code);
  } else {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status);
  }

  if (header_list) {
    curl_slist_free_all(header_list);
  }

  curl_easy_cleanup(curl);
  return response;
}

HttpResponse http_post_empty(const std::string &url,
                             const std::vector<std::string> &headers,
                             const std::optional<std::string> &user_pwd = std::nullopt,
                             const std::optional<long> timeout_seconds = 10) {
  return http_post(url, "", headers, user_pwd, timeout_seconds);
}

std::string get_env_or_default(const char *key, const std::string &default_value = "") {
  const char *value = std::getenv(key);
  if (!value) {
    return default_value;
  }
  return std::string(value);
}

std::string get_env_or_throw(const char *key) {
  const char *value = std::getenv(key);
  if (!value) {
    std::ostringstream oss;
    oss << "Missing required environment variable: " << key;
    throw std::runtime_error(oss.str());
  }
  return std::string(value);
}

std::string paypal_base_url(const std::string &environment) {
  if (environment == "live" || environment == "production") {
    return "https://api-m.paypal.com";
  }
  return "https://api-m.sandbox.paypal.com";
}

std::string load_file_or_throw(const std::string &path) {
  std::ifstream file(path);
  if (!file) {
    std::ostringstream oss;
    oss << "Failed to open template file: " << path;
    throw std::runtime_error(oss.str());
  }
  std::ostringstream buffer;
  buffer << file.rdbuf();
  return buffer.str();
}

void replace_all(std::string &str, const std::string &from, const std::string &to) {
  if (from.empty()) {
    return;
  }
  std::size_t start_pos = 0;
  while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
    str.replace(start_pos, from.length(), to);
    start_pos += to.length();
  }
}

std::string trim_copy(const std::string &value) {
  const auto first = value.find_first_not_of(" \t\n\r\f\v");
  if (first == std::string::npos) {
    return "";
  }
  const auto last = value.find_last_not_of(" \t\n\r\f\v");
  return value.substr(first, last - first + 1);
}

std::string to_lower_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return value;
}

std::vector<std::string> parse_allowed_origins(const std::string &value) {
  std::vector<std::string> origins;
  std::stringstream ss(value);
  std::string token;
  while (std::getline(ss, token, ',')) {
    auto trimmed = trim_copy(token);
    if (!trimmed.empty()) {
      origins.push_back(trimmed);
    }
  }
  return origins;
}

bool origin_matches(const std::vector<std::string> &allowed_origins, const std::string &origin) {
  return std::any_of(allowed_origins.begin(),
                     allowed_origins.end(),
                     [&](const std::string &allowed_origin) {
                       return allowed_origin == "*" || allowed_origin == origin;
                     });
}

std::optional<std::string> resolve_allowed_origin(const httplib::Request &req,
                                                  const std::vector<std::string> &allowed_origins) {
  if (allowed_origins.empty()) {
    return std::nullopt;
  }

  const auto origin = req.get_header_value("Origin");
  if (origin.empty()) {
    return std::nullopt;
  }

  if (origin_matches(allowed_origins, origin)) {
    return origin;
  }
  return std::nullopt;
}

bool is_request_origin_allowed(const httplib::Request &req,
                               const std::vector<std::string> &allowed_origins) {
  if (allowed_origins.empty()) {
    return false;
  }

  const auto origin = req.get_header_value("Origin");
  if (origin.empty()) {
    return true;
  }

  return origin_matches(allowed_origins, origin);
}

bool is_valid_order_id(const std::string &order_id) {
  static const std::regex kPayPalOrderIdPattern("^[A-Z0-9-]{9,64}$");
  return std::regex_match(order_id, kPayPalOrderIdPattern);
}

bool is_json_content_type(const std::string &content_type_raw) {
  if (content_type_raw.empty()) {
    return false;
  }
  const auto separator = content_type_raw.find(';');
  auto mime = content_type_raw.substr(0, separator);
  mime = trim_copy(mime);
  mime = to_lower_copy(mime);
  return mime == "application/json";
}

struct ProductOption {
  std::string id;
  std::string reference_id;
  std::string description;
  int item_price_cents;
  int shipping_cents;

  int total_price_cents() const {
    return item_price_cents + shipping_cents;
  }
};

std::string format_price_cents(int cents) {
  std::ostringstream oss;
  oss << (cents / 100) << '.' << std::setw(2) << std::setfill('0') << (cents % 100);
  return oss.str();
}

const std::array<ProductOption, 2> &product_catalog() {
  static const std::array<ProductOption, 2> catalog{{
      {"ac0200-holder",
       "NH-AC0200-HOOK-1",
       "3D-Printed Hook Holder for NH AC0200 Fault Sensor",
       1689,
       688},
      {"ac0100-holder",
       "NH-AC0100-HOOK-1",
       "3D-Printed Hook Holder for Nuheat MatSense Pro (AC0100)",
       1689,
       688},
  }};
  return catalog;
}

const ProductOption &default_product() {
  const auto &catalog = product_catalog();
  return catalog.front();
}

const ProductOption *find_product_by_id(const std::string &id) {
  const auto &catalog = product_catalog();
  for (const auto &product : catalog) {
    if (product.id == id) {
      return &product;
    }
  }
  return nullptr;
}

const char kInlinePayPalHelper[] = R"(<script>
(function () {
  var statusEl = document.getElementById('paypal-status');
  var yearEl = document.getElementById('copyright-year');
  if (yearEl) {
    yearEl.textContent = new Date().getFullYear();
  }

  var fallbackTimer;
  var buttonsRendered = false;
  var retryTimer = null;
  var productSelector = 'input[name="product-option"]';

  function getSelectedProductId() {
    var selected = document.querySelector(productSelector + ':checked');
    return selected ? selected.value : null;
  }

  function showFallbackMessage() {
    if (statusEl && !statusEl.textContent && !buttonsRendered) {
      statusEl.textContent = 'Unable to load PayPal checkout. Refresh or email orders@nuheat-hanger.com to place your order.';
    }
  }

  function createOrderOnServer() {
    var payload = {};
    var selectedProduct = getSelectedProductId();
    if (selectedProduct) {
      payload.productId = selectedProduct;
    }

    return fetch('/api/create-order', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      credentials: 'same-origin',
      body: JSON.stringify(payload)
    }).then(function (res) {
      if (!res.ok) {
        return res.json().catch(function () {
          throw new Error('Failed to create order on server.');
        }).then(function (err) {
          var message = err && err.error ? ' ' + err.error : '';
          if (err && err.details) {
            message += ' ' + err.details;
          }
          throw new Error('Failed to create order on server.' + message);
        });
      }
      return res.json();
    }).then(function (data) {
      if (!data.orderID) {
        throw new Error('Server response missing orderID.');
      }
      return data.orderID;
    });
  }

  function captureOrderOnServer(orderID) {
    return fetch('/api/capture-order', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      credentials: 'same-origin',
      body: JSON.stringify({ orderID: orderID })
    }).then(function (res) {
      if (!res.ok) {
        return res.json().catch(function () {
          throw new Error('Failed to capture order on server.');
        }).then(function (err) {
          var details = err && err.details ? ' ' + err.details : '';
          throw new Error('Failed to capture order on server.' + details);
        });
      }
      return res.json();
    });
  }

  function mountPayPalButtons() {
    if (buttonsRendered) {
      return;
    }

    if (!window.paypal || typeof window.paypal.Buttons !== 'function') {
      var sdkScript = document.querySelector('script[src*="paypal.com/sdk"]');
      if (sdkScript && !sdkScript.dataset.retryScheduled) {
        sdkScript.dataset.retryScheduled = 'true';
        sdkScript.addEventListener('load', mountPayPalButtons, { once: true });
      }
      if (!retryTimer) {
        retryTimer = window.setTimeout(function () {
          retryTimer = null;
          if (window.paypal && typeof window.paypal.Buttons === 'function') {
            mountPayPalButtons();
          }
        }, 400);
      }
      return;
    }

    buttonsRendered = true;
    if (retryTimer) {
      window.clearTimeout(retryTimer);
      retryTimer = null;
    }

    var buttons = window.paypal.Buttons({
      style: {
        layout: 'vertical',
        color: 'gold',
        shape: 'rect',
        label: 'paypal'
      },
      createOrder: function () {
        return createOrderOnServer().catch(function (err) {
          console.error('Failed to create order', err);
          if (statusEl) {
            statusEl.textContent = 'Unable to start checkout right now. Try again in a moment or email orders@nuheat-hanger.com.';
          }
          throw err;
        });
      },
      onApprove: function (data) {
        return captureOrderOnServer(data.orderID).then(function (order) {
          if (statusEl) {
            window.clearTimeout(fallbackTimer);
            fallbackTimer = null;
            var transaction = order && order.purchase_units && order.purchase_units[0] && order.purchase_units[0].payments && order.purchase_units[0].payments.captures && order.purchase_units[0].payments.captures[0];
            var txnId = transaction && transaction.id ? ' Transaction ID: ' + transaction.id + '.' : '';
            statusEl.textContent = 'Thanks! Your order is confirmed.' + txnId;
          }
        }).catch(function (err) {
          console.error('Failed to capture order', err);
          if (statusEl) {
            statusEl.textContent = 'We confirmed your payment with PayPal, but validation failed on our side. Please contact orders@nuheat-hanger.com with your transaction ID.';
          }
          throw err;
        });
      },
      onError: function (err) {
        console.error('PayPal checkout error', err);
        if (statusEl) {
          window.clearTimeout(fallbackTimer);
          fallbackTimer = null;
          statusEl.textContent = 'Something went wrong with PayPal checkout. Try again or email orders@nuheat-hanger.com.';
        }
      },
      onCancel: function () {
        if (statusEl) {
          statusEl.textContent = 'Checkout canceled. You can try again whenever you are ready.';
        }
      }
    });

    buttons.render('#paypal-button-container').then(function () {
      if (statusEl) {
        statusEl.textContent = '';
      }
      if (fallbackTimer) {
        window.clearTimeout(fallbackTimer);
        fallbackTimer = null;
      }
    }).catch(function (err) {
      buttonsRendered = false;
      if (statusEl) {
        window.clearTimeout(fallbackTimer);
        fallbackTimer = null;
        statusEl.textContent = 'Unable to load PayPal checkout. Refresh or email orders@nuheat-hanger.com to place your order.';
      }
      throw err;
    });
  }

  function init() {
    if (statusEl) {
      statusEl.textContent = 'Loading secure PayPal checkout…';
    }
    fallbackTimer = window.setTimeout(showFallbackMessage, 6000);
    mountPayPalButtons();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
</script>
)";

class PayPalClient {
public:
  PayPalClient(std::string client_id,
               std::string client_secret,
               std::string environment)
      : client_id_(std::move(client_id)),
        client_secret_(std::move(client_secret)),
        base_url_(paypal_base_url(environment)) {}

  json create_order(const ProductOption &product) {
    const auto token = fetch_access_token();
    if (!token) {
      throw std::runtime_error("Unable to retrieve PayPal access token");
    }

    const auto total_value = format_price_cents(product.total_price_cents());
    const auto item_value = format_price_cents(product.item_price_cents);
    const auto shipping_value = format_price_cents(product.shipping_cents);

    json request_body = {
        {"intent", "CAPTURE"},
        {"purchase_units",
         json::array({json{
             {"reference_id", product.reference_id},
             {"description", product.description},
             {"amount",
              json{
                  {"currency_code", "USD"},
                  {"value", total_value},
                  {"breakdown",
                   json{
                       {"item_total",
                        json{{"currency_code", "USD"}, {"value", item_value}}},
                       {"shipping",
                        json{{"currency_code", "USD"}, {"value", shipping_value}}},
                   }},
              }},
         }})},
        {"application_context",
         json{
             {"shipping_preference", "NO_SHIPPING"},
             {"user_action", "PAY_NOW"},
         }},
    };

    const auto url = base_url_ + "/v2/checkout/orders";
    HttpResponse response = http_post(url,
                                      request_body.dump(),
                                      {
                                          "Content-Type: application/json",
                                          "Accept: application/json",
                                          "Authorization: Bearer " + *token,
                                      });

    if (!response.ok()) {
      std::ostringstream oss;
      oss << "Failed to create PayPal order. HTTP status " << response.status
          << ". Error: " << response.error_message << ". Body: " << response.body;
      throw std::runtime_error(oss.str());
    }

    return json::parse(response.body);
  }

  json capture_order(const std::string &order_id) {
    const auto token = fetch_access_token();
    if (!token) {
      throw std::runtime_error("Unable to retrieve PayPal access token");
    }

    const auto url = base_url_ + "/v2/checkout/orders/" + order_id + "/capture";
    HttpResponse response = http_post_empty(url,
                                            {
                                                "Content-Type: application/json",
                                                "Accept: application/json",
                                                "Authorization: Bearer " + *token,
                                            });

    if (!response.ok()) {
      std::ostringstream oss;
      oss << "Failed to capture PayPal order " << order_id << ". HTTP status "
          << response.status << ". Error: " << response.error_message
          << ". Body: " << response.body;
      throw std::runtime_error(oss.str());
    }

    return json::parse(response.body);
  }

private:
  std::optional<std::string> fetch_access_token() {
    const auto url = base_url_ + "/v1/oauth2/token";
    const std::string payload = "grant_type=client_credentials";
    const std::string userpwd = client_id_ + ":" + client_secret_;

    HttpResponse response = http_post(url,
                                      payload,
                                      {
                                          "Accept: application/json",
                                          "Accept-Language: en_US",
                                          "Content-Type: application/x-www-form-urlencoded",
                                      },
                                      userpwd);

    if (!response.ok()) {
      std::cerr << "[paypal] OAuth token request failed. HTTP status "
                << response.status << ". Error: " << response.error_message
                << ". Body: " << response.body << std::endl;
      return std::nullopt;
    }

    try {
      auto data = json::parse(response.body);
      if (data.contains("access_token")) {
        return data.at("access_token").get<std::string>();
      }
      std::cerr << "[paypal] OAuth response missing access_token" << std::endl;
    } catch (const json::parse_error &err) {
      std::cerr << "[paypal] Failed to parse OAuth response: " << err.what() << std::endl;
    }
    return std::nullopt;
  }

  std::string client_id_;
  std::string client_secret_;
  std::string base_url_;
};

void append_cors_headers(const httplib::Request &req,
                         httplib::Response &res,
                         const std::vector<std::string> &allowed_origins) {
  if (!allowed_origins.empty()) {
    res.set_header("Vary", "Origin");
  }

  if (const auto allowed_origin = resolve_allowed_origin(req, allowed_origins)) {
    res.set_header("Access-Control-Allow-Origin", allowed_origin->c_str());
  }

  res.set_header("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.set_header("Access-Control-Allow-Headers", "Content-Type");
  res.set_header("Access-Control-Allow-Credentials", "true");
}

} // namespace

int main() {
  curl_global_init(CURL_GLOBAL_DEFAULT);

  try {
    const auto allowed_origins_raw =
        get_env_or_default("ALLOWED_ORIGINS",
                           get_env_or_default("ALLOWED_ORIGIN", ""));
    const auto allowed_origins = parse_allowed_origins(allowed_origins_raw);
    if (allowed_origins.empty()) {
      throw std::runtime_error(
          "No CORS origins configured. Set ALLOWED_ORIGINS to a comma-separated list of allowed origins.");
    }
    const auto paypal_client_id = get_env_or_throw("PAYPAL_CLIENT_ID");
    const auto paypal_client_secret = get_env_or_throw("PAYPAL_CLIENT_SECRET");
    const auto paypal_environment = get_env_or_default("PAYPAL_ENV", "sandbox");

    PayPalClient paypal_client(paypal_client_id, paypal_client_secret, paypal_environment);

    const auto template_path = get_env_or_default("INDEX_TEMPLATE_PATH", "templates/index.html");
    const auto static_root = get_env_or_default("STATIC_ROOT", "../public");
    std::string index_template = load_file_or_throw(template_path);
    replace_all(index_template, "{{INLINE_PAYPAL_HELPER}}", kInlinePayPalHelper);
    replace_all(index_template, "{{PAYPAL_CLIENT_ID}}", paypal_client_id);
    const std::string index_html = index_template;

    httplib::Server server;

    if (!server.set_mount_point("/static", static_root.c_str())) {
      std::cerr << "[warning] Failed to mount static assets from " << static_root << std::endl;
    }

    const auto send_index = [&](const httplib::Request &, httplib::Response &res) {
      res.set_content(index_html, "text/html; charset=UTF-8");
    };
    server.Get("/", send_index);
    server.Get("/index.html", send_index);

    server.Options("/api/create-order", [&](const httplib::Request &req, httplib::Response &res) {
      if (!is_request_origin_allowed(req, allowed_origins)) {
        res.status = 403;
        json err = {{"error", "Origin not allowed"}};
        res.set_content(err.dump(), "application/json");
      } else {
        res.status = 204;
      }
      append_cors_headers(req, res, allowed_origins);
    });

    server.Options("/api/capture-order", [&](const httplib::Request &req, httplib::Response &res) {
      if (!is_request_origin_allowed(req, allowed_origins)) {
        res.status = 403;
        json err = {{"error", "Origin not allowed"}};
        res.set_content(err.dump(), "application/json");
      } else {
        res.status = 204;
      }
      append_cors_headers(req, res, allowed_origins);
    });

    server.Post("/api/create-order",
                [&](const httplib::Request &req, httplib::Response &res) {
                  if (!is_request_origin_allowed(req, allowed_origins)) {
                    res.status = 403;
                    json err = {{"error", "Origin not allowed"}};
                    res.set_content(err.dump(), "application/json");
                    append_cors_headers(req, res, allowed_origins);
                    return;
                  }

                  try {
                    std::string product_id = default_product().id;
                    if (!req.body.empty()) {
                      if (!is_json_content_type(req.get_header_value("Content-Type"))) {
                        res.status = 415;
                        json err = {{"error", "Content-Type must be application/json"}};
                        res.set_content(err.dump(), "application/json");
                        append_cors_headers(req, res, allowed_origins);
                        return;
                      }

                      auto body = json::parse(req.body);
                      if (body.contains("productId")) {
                        if (!body.at("productId").is_string()) {
                          res.status = 400;
                          json err = {{"error", "productId must be a string"}};
                          res.set_content(err.dump(), "application/json");
                          append_cors_headers(req, res, allowed_origins);
                          return;
                        }
                        product_id = body.at("productId").get<std::string>();
                      }
                    }

                    const auto *product = find_product_by_id(product_id);
                    if (!product) {
                      res.status = 422;
                      json err = {{"error", "Unknown productId"}};
                      res.set_content(err.dump(), "application/json");
                      append_cors_headers(req, res, allowed_origins);
                      return;
                    }

                    auto order = paypal_client.create_order(*product);
                    json response = {
                        {"orderID", order.at("id")},
                        {"status", order.value("status", "UNKNOWN")},
                        {"productId", product->id},
                    };
                    res.status = 200;
                    res.set_content(response.dump(), "application/json");
                  } catch (const json::parse_error &ex) {
                    res.status = 400;
                    json err = {
                        {"error", "Invalid JSON in request body"},
                        {"details", ex.what()},
                    };
                    res.set_content(err.dump(), "application/json");
                    std::cerr << "[error] create-order parse: " << ex.what() << std::endl;
                  } catch (const std::exception &ex) {
                    res.status = 500;
                    json err = {
                        {"error", "Failed to create PayPal order"},
                        {"details", ex.what()},
                    };
                    res.set_content(err.dump(), "application/json");
                    std::cerr << "[error] " << ex.what() << std::endl;
                  }
                  append_cors_headers(req, res, allowed_origins);
                });

    server.Post("/api/capture-order",
                [&](const httplib::Request &req, httplib::Response &res) {
                  if (!is_request_origin_allowed(req, allowed_origins)) {
                    res.status = 403;
                    json err = {{"error", "Origin not allowed"}};
                    res.set_content(err.dump(), "application/json");
                    append_cors_headers(req, res, allowed_origins);
                    return;
                  }

                  try {
                    if (!is_json_content_type(req.get_header_value("Content-Type"))) {
                      res.status = 415;
                      json err = {{"error", "Content-Type must be application/json"}};
                      res.set_content(err.dump(), "application/json");
                    } else if (req.body.empty()) {
                      res.status = 400;
                      json err = {{"error", "Missing request body"}};
                      res.set_content(err.dump(), "application/json");
                    } else {
                      auto body = json::parse(req.body);
                      if (!body.contains("orderID")) {
                        res.status = 400;
                        json err = {{"error", "orderID is required"}};
                        res.set_content(err.dump(), "application/json");
                      } else if (!body.at("orderID").is_string()) {
                        res.status = 400;
                        json err = {{"error", "orderID must be a string"}};
                        res.set_content(err.dump(), "application/json");
                      } else {
                        const auto order_id = body.at("orderID").get<std::string>();
                        if (!is_valid_order_id(order_id)) {
                          res.status = 422;
                          json err = {{"error", "orderID format is invalid"}};
                          res.set_content(err.dump(), "application/json");
                        } else {
                          auto capture_result = paypal_client.capture_order(order_id);
                          res.status = 200;
                          res.set_content(capture_result.dump(), "application/json");
                        }
                      }
                    }
                  } catch (const json::parse_error &err) {
                    res.status = 400;
                    json err_payload = {
                        {"error", "Invalid JSON payload"},
                        {"details", err.what()},
                    };
                    res.set_content(err_payload.dump(), "application/json");
                  } catch (const std::exception &ex) {
                    res.status = 500;
                    json err = {
                        {"error", "Failed to capture PayPal order"},
                        {"details", ex.what()},
                    };
                    res.set_content(err.dump(), "application/json");
                    std::cerr << "[error] " << ex.what() << std::endl;
                  }
                  append_cors_headers(req, res, allowed_origins);
                });

    server.set_error_handler([&](const httplib::Request &req, httplib::Response &res) {
      append_cors_headers(req, res, allowed_origins);
      json err = {
          {"error", "Route not found"},
      };
      res.set_content(err.dump(), "application/json");
    });

    const auto host = get_env_or_default("SERVER_HOST", "0.0.0.0");
    const int port = std::stoi(get_env_or_default("SERVER_PORT", "8080"));

    std::cout << "Checkout server running on " << host << ":" << port << std::endl;
    std::cout << "CORS allowed origins: " << allowed_origins_raw << std::endl;
    std::cout << "Serving index template from: " << template_path << std::endl;
    std::cout << "Static assets root: " << static_root << std::endl;
    std::cout << "PayPal environment: " << paypal_environment << std::endl;

    server.listen(host.c_str(), port);
  } catch (const std::exception &ex) {
    std::cerr << "[fatal] " << ex.what() << std::endl;
    curl_global_cleanup();
    return 1;
  }

  curl_global_cleanup();
  return 0;
}
