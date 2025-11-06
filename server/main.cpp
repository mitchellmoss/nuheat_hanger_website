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
#include <vector>
#include <chrono>
#include <random>
#include <mutex>

using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;

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

HttpResponse http_get(const std::string &url,
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
  curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
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

std::string url_encode(const std::string &value) {
  std::ostringstream escaped;
  escaped << std::hex << std::uppercase;
  escaped.fill('0');

  for (unsigned char ch : value) {
    if (std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~') {
      escaped << static_cast<char>(ch);
    } else {
      escaped << '%' << std::setw(2) << static_cast<int>(ch);
    }
  }

  return escaped.str();
}

std::string url_decode(const std::string &value) {
  std::string result;
  result.reserve(value.size());

  auto from_hex = [](char ch) -> int {
    if (ch >= '0' && ch <= '9') {
      return ch - '0';
    }
    if (ch >= 'A' && ch <= 'F') {
      return ch - 'A' + 10;
    }
    if (ch >= 'a' && ch <= 'f') {
      return ch - 'a' + 10;
    }
    return -1;
  };

  for (size_t i = 0; i < value.size(); ++i) {
    const char ch = value[i];
    if (ch == '+') {
      result.push_back(' ');
    } else if (ch == '%' && i + 2 < value.size()) {
      const int high = from_hex(value[i + 1]);
      const int low = from_hex(value[i + 2]);
      if (high >= 0 && low >= 0) {
        result.push_back(static_cast<char>((high << 4) | low));
        i += 2;
      } else {
        result.push_back(ch);
      }
    } else {
      result.push_back(ch);
    }
  }

  return result;
}

std::unordered_map<std::string, std::string> parse_urlencoded_body(const std::string &body) {
  std::unordered_map<std::string, std::string> result;
  size_t start = 0;
  while (start <= body.size()) {
    const auto end = body.find('&', start);
    const std::string pair = (end == std::string::npos) ? body.substr(start)
                                                        : body.substr(start, end - start);
    if (!pair.empty()) {
      const auto eq_pos = pair.find('=');
      const std::string key = url_decode(pair.substr(0, eq_pos));
      const std::string value = (eq_pos == std::string::npos) ? std::string()
                                                              : url_decode(pair.substr(eq_pos + 1));
      if (!key.empty()) {
        result[key] = value;
      }
    }
    if (end == std::string::npos) {
      break;
    }
    start = end + 1;
  }
  return result;
}

std::string paypal_ipn_verify_url(const std::string &environment) {
  if (environment == "live" || environment == "production") {
    return "https://ipnpb.paypal.com/cgi-bin/webscr";
  }
  return "https://ipnpb.sandbox.paypal.com/cgi-bin/webscr";
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

std::string normalize_origin(const std::string &origin) {
  auto trimmed = trim_copy(origin);
  if (trimmed.empty()) {
    return trimmed;
  }

  const auto scheme_end = trimmed.find("://");
  if (scheme_end == std::string::npos) {
    return to_lower_copy(trimmed);
  }

  std::string scheme = to_lower_copy(trimmed.substr(0, scheme_end));
  std::string remainder = trimmed.substr(scheme_end + 3);

  while (!remainder.empty() && remainder.back() == '/') {
    remainder.pop_back();
  }

  std::string host = remainder;
  std::string port;

  if (!remainder.empty() && remainder.front() == '[') {
    const auto closing = remainder.find(']');
    if (closing != std::string::npos) {
      host = to_lower_copy(remainder.substr(0, closing + 1));
      if (closing + 1 < remainder.size() && remainder.at(closing + 1) == ':') {
        port = remainder.substr(closing + 2);
      }
    } else {
      host = to_lower_copy(remainder);
    }
  } else {
    const auto colon_pos = remainder.find(':');
    if (colon_pos != std::string::npos) {
      host = to_lower_copy(remainder.substr(0, colon_pos));
      port = remainder.substr(colon_pos + 1);
    } else {
      host = to_lower_copy(remainder);
    }
  }

  port = trim_copy(port);
  if (port.empty()) {
    return scheme + "://" + host;
  }

  if ((scheme == "http" && port == "80") || (scheme == "https" && port == "443")) {
    return scheme + "://" + host;
  }

  return scheme + "://" + host + ":" + port;
}

bool origin_matches(const std::vector<std::string> &allowed_origins, const std::string &origin) {
  const auto normalized_origin = normalize_origin(origin);
  return std::any_of(allowed_origins.begin(),
                     allowed_origins.end(),
                     [&](const std::string &allowed_origin) {
                       if (allowed_origin == "*") {
                         return true;
                       }
                       return normalize_origin(allowed_origin) == normalized_origin;
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

  if (origin_matches(allowed_origins, origin)) {
    return true;
  }

  const auto host_header = trim_copy(req.get_header_value("Host"));
  if (!host_header.empty()) {
    const auto scheme_end = origin.find("://");
    if (scheme_end != std::string::npos) {
      const std::string scheme = to_lower_copy(origin.substr(0, scheme_end));
      const std::string reconstructed_origin = scheme + "://" + host_header;
      if (normalize_origin(reconstructed_origin) == normalize_origin(origin)) {
        return true;
      }
    }
  }

  std::cerr << "[cors] Denying origin '" << origin << "' for host '" << host_header << "'" << std::endl;
  return false;
}

bool is_valid_order_id(const std::string &order_id) {
  static const std::regex kPayPalOrderIdPattern("^[A-Z0-9-]{9,64}$");
  return std::regex_match(order_id, kPayPalOrderIdPattern);
}

bool is_valid_paypal_resource_id(const std::string &value) {
  if (value.empty() || value.size() > 64) {
    return false;
  }
  return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
    return std::isalnum(ch) || ch == '-';
  });
}

bool is_valid_rfc3339_datetime(const std::string &value) {
  static const std::regex kPattern(
      R"(^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$)");
  return std::regex_match(value, kPattern);
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

std::unordered_map<std::string, std::string> parse_cookies(const std::string &header) {
  std::unordered_map<std::string, std::string> cookies;
  if (header.empty()) {
    return cookies;
  }

  std::stringstream ss(header);
  std::string pair;
  while (std::getline(ss, pair, ';')) {
    const auto eq = pair.find('=');
    if (eq == std::string::npos) {
      continue;
    }
    auto name = trim_copy(pair.substr(0, eq));
    auto value = trim_copy(pair.substr(eq + 1));
    if (!name.empty()) {
      cookies[name] = value;
    }
  }
  return cookies;
}

std::optional<std::string> get_cookie_value(const httplib::Request &req, const std::string &name) {
  const auto header = req.get_header_value("Cookie");
  if (header.empty()) {
    return std::nullopt;
  }
  const auto cookies = parse_cookies(header);
  const auto it = cookies.find(name);
  if (it == cookies.end()) {
    return std::nullopt;
  }
  return it->second;
}

constexpr std::chrono::minutes kAdminSessionTtl{240};
constexpr std::chrono::minutes kAdminSessionSlidingRefresh = kAdminSessionTtl;
constexpr std::chrono::minutes kAdminLoginWindow{10};
constexpr std::chrono::minutes kAdminLockoutDuration{15};
constexpr int kAdminMaxLoginAttempts = 5;
const char kAdminSessionCookieName[] = "AdminSession";

struct AdminSession {
  std::chrono::system_clock::time_point expires_at{};
  std::string remote_ip;
};

struct LoginAttemptInfo {
  int attempts{0};
  std::chrono::steady_clock::time_point window_start{std::chrono::steady_clock::time_point::min()};
  std::chrono::steady_clock::time_point blocked_until{std::chrono::steady_clock::time_point::min()};
};

std::mutex admin_auth_mutex;
std::unordered_map<std::string, AdminSession> admin_sessions;
std::unordered_map<std::string, LoginAttemptInfo> admin_login_attempts;

std::string generate_session_token() {
  std::array<unsigned char, 32> bytes{};
  std::random_device rd;
  for (auto &byte : bytes) {
    byte = static_cast<unsigned char>(rd() & 0xFF);
  }
  static constexpr char kHex[] = "0123456789abcdef";
  std::string token;
  token.reserve(bytes.size() * 2);
  for (auto byte : bytes) {
    token.push_back(kHex[byte >> 4]);
    token.push_back(kHex[byte & 0x0F]);
  }
  return token;
}

void prune_expired_sessions_locked(std::chrono::system_clock::time_point now) {
  for (auto it = admin_sessions.begin(); it != admin_sessions.end();) {
    if (it->second.expires_at <= now) {
      it = admin_sessions.erase(it);
    } else {
      ++it;
    }
  }
}

std::optional<std::string> extract_admin_session_token(const httplib::Request &req) {
  return get_cookie_value(req, kAdminSessionCookieName);
}

bool is_admin_authenticated(const httplib::Request &req) {
  const auto token_opt = extract_admin_session_token(req);
  if (!token_opt) {
    return false;
  }

  const auto token = *token_opt;
  const auto now = std::chrono::system_clock::now();

  std::lock_guard<std::mutex> lock(admin_auth_mutex);
  prune_expired_sessions_locked(now);
  const auto it = admin_sessions.find(token);
  if (it == admin_sessions.end()) {
    return false;
  }

  if (it->second.expires_at <= now) {
    admin_sessions.erase(it);
    return false;
  }

  it->second.expires_at = now + kAdminSessionSlidingRefresh;
  return true;
}

void invalidate_admin_session(const std::string &token) {
  if (token.empty()) {
    return;
  }
  std::lock_guard<std::mutex> lock(admin_auth_mutex);
  admin_sessions.erase(token);
}

std::string issue_admin_session(const std::string &remote_ip) {
  const auto now = std::chrono::system_clock::now();
  std::lock_guard<std::mutex> lock(admin_auth_mutex);
  prune_expired_sessions_locked(now);

  std::string token;
  do {
    token = generate_session_token();
  } while (admin_sessions.count(token) > 0);

  admin_sessions[token] = AdminSession{
      now + kAdminSessionTtl,
      remote_ip,
  };

  return token;
}

struct LoginDecision {
  bool allowed{true};
  bool blocked{false};
  std::chrono::steady_clock::duration retry_after{};
};

LoginDecision evaluate_login_attempt(const std::string &remote_ip, bool success) {
  const auto now = std::chrono::steady_clock::now();
  std::lock_guard<std::mutex> lock(admin_auth_mutex);

  auto &entry = admin_login_attempts[remote_ip];

  if (entry.window_start == std::chrono::steady_clock::time_point::min() ||
      now - entry.window_start > kAdminLoginWindow) {
    entry.window_start = now;
    entry.attempts = 0;
  }

  if (entry.blocked_until != std::chrono::steady_clock::time_point::min() &&
      now < entry.blocked_until) {
    return LoginDecision{
        .allowed = false,
        .blocked = true,
        .retry_after = entry.blocked_until - now,
    };
  }

  if (success) {
    entry.attempts = 0;
    entry.blocked_until = std::chrono::steady_clock::time_point::min();
    return LoginDecision{.allowed = true};
  }

  entry.attempts += 1;
  if (entry.attempts >= kAdminMaxLoginAttempts) {
    entry.attempts = 0;
    entry.blocked_until = now + kAdminLockoutDuration;
    return LoginDecision{
        .allowed = false,
        .blocked = true,
        .retry_after = kAdminLockoutDuration,
    };
  }

  return LoginDecision{.allowed = false, .blocked = false};
}

std::string format_duration_seconds(std::chrono::steady_clock::duration duration) {
  using namespace std::chrono;
  const auto seconds_total = duration_cast<seconds>(duration).count();
  if (seconds_total <= 0) {
    return "0";
  }
  return std::to_string(seconds_total);
}

LoginDecision check_login_block(const std::string &remote_ip) {
  const auto now = std::chrono::steady_clock::now();
  std::lock_guard<std::mutex> lock(admin_auth_mutex);

  auto &entry = admin_login_attempts[remote_ip];
  if (entry.window_start == std::chrono::steady_clock::time_point::min() ||
      now - entry.window_start > kAdminLoginWindow) {
    entry.window_start = now;
    entry.attempts = 0;
  }

  if (entry.blocked_until != std::chrono::steady_clock::time_point::min() &&
      now < entry.blocked_until) {
    return LoginDecision{
        .allowed = false,
        .blocked = true,
        .retry_after = entry.blocked_until - now,
    };
  }

  return LoginDecision{.allowed = true};
}

struct ProductOption {
  std::string id;
  std::string reference_id;
  std::string name;
  std::string description;
  int unit_price_cents;
};

struct SelectedProduct {
  const ProductOption *option;
  int quantity;
};

constexpr int kFlatShippingCents = 688;

std::string format_price_cents(int cents) {
  std::ostringstream oss;
  oss << (cents / 100) << '.' << std::setw(2) << std::setfill('0') << (cents % 100);
  return oss.str();
}

const std::array<ProductOption, 2> &product_catalog() {
  static const std::array<ProductOption, 2> catalog{{
      {"ac0200-holder",
       "NH-AC0200-HOOK-1",
       "NH AC0200 Fault Sensor Holder",
       "3D-Printed Hook Holder for NH AC0200 Fault Sensor",
       1689},
      {"ac0100-holder",
       "NH-AC0100-HOOK-1",
       "MatSense Pro (AC0100) Holder",
       "3D-Printed Hook Holder for Nuheat MatSense Pro (AC0100)",
       1689},
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
  var productOptionSelector = '.purchase__option';
  var productPanelSelector = '.purchase__option-panel';
  var productInputSelector = '.purchase__quantity-input';
  var productImageEl = document.getElementById('purchase-product-image');
  var lastSelectedProductId = null;
  var matchesSelector = Element.prototype.matches || Element.prototype.msMatchesSelector || Element.prototype.webkitMatchesSelector;
  var productImageMap = {
    'ac0200-holder': {
      src: 'https://nuheat.clipsandwedges.com/static/images/holder-front.jpg',
      alt: 'Close up of the NH AC0200 holder detailing the zip-tie channel'
    },
    'ac0100-holder': {
      src: '/static/images/holder_small_front.jpg',
      alt: 'MatSense Pro (AC0100) sensor shown seated in the smaller holder'
    }
  };

  function parseQuantity(value) {
    var quantity = parseInt(value, 10);
    if (isNaN(quantity) || quantity < 0) {
      return 0;
    }
    return quantity;
  }

  function findInputByProductId(productId) {
    return document.querySelector(productInputSelector + '[data-product-id="' + productId + '"]');
  }

  function refreshOptionStates() {
    var options = document.querySelectorAll(productOptionSelector);
    if (!options || !options.length) {
      return;
    }
    for (var i = 0; i < options.length; i++) {
      var option = options[i];
      var panel = option.querySelector(productPanelSelector);
      if (!panel) {
        continue;
      }
      var input = option.querySelector(productInputSelector);
      var quantity = input ? parseQuantity(input.value) : 0;
      if (quantity > 0) {
        panel.classList.add('is-selected');
        panel.setAttribute('aria-pressed', 'true');
      } else {
        panel.classList.remove('is-selected');
        panel.setAttribute('aria-pressed', 'false');
      }
    }
  }

  function sanitizeAllQuantities() {
    var inputs = document.querySelectorAll(productInputSelector);
    if (!inputs || !inputs.length) {
      return;
    }
    var firstPositive = null;
    for (var i = 0; i < inputs.length; i++) {
      var input = inputs[i];
      var productId = input.getAttribute('data-product-id');
      if (!productId) {
        continue;
      }
      var quantity = parseQuantity(input.value);
      input.value = String(quantity);
      if (quantity > 0 && !firstPositive) {
        firstPositive = productId;
      }
      if (quantity === 0 && lastSelectedProductId === productId) {
        lastSelectedProductId = null;
      }
    }
    if (!lastSelectedProductId && firstPositive) {
      lastSelectedProductId = firstPositive;
    }
    refreshOptionStates();
  }

  function getProductSelections() {
    var inputs = document.querySelectorAll(productInputSelector);
    var selections = [];
    if (!inputs || !inputs.length) {
      return selections;
    }
    for (var i = 0; i < inputs.length; i++) {
      var input = inputs[i];
      var productId = input.getAttribute('data-product-id');
      if (!productId) {
        continue;
      }
      var quantity = parseQuantity(input.value);
      if (quantity > 0) {
        selections.push({
          productId: productId,
          quantity: quantity
        });
      }
    }
    return selections;
  }

  function getPrimaryProductId() {
    if (lastSelectedProductId) {
      var lastInput = findInputByProductId(lastSelectedProductId);
      if (lastInput && parseQuantity(lastInput.value) > 0) {
        return lastSelectedProductId;
      }
      lastSelectedProductId = null;
    }
    var selections = getProductSelections();
    if (selections.length > 0) {
      return selections[0].productId;
    }
    var fallbackInput = document.querySelector(productInputSelector);
    return fallbackInput ? fallbackInput.getAttribute('data-product-id') : null;
  }

  function handleQuantityEvent(event, sanitize) {
    var target = event && (event.target || event.srcElement);
    if (!target) {
      return;
    }
    if (sanitize) {
      target.value = String(parseQuantity(target.value));
    }
    var productId = target.getAttribute('data-product-id');
    if (!productId) {
      return;
    }
    var quantity = parseQuantity(target.value);
    if (quantity > 0) {
      lastSelectedProductId = productId;
    } else if (lastSelectedProductId === productId) {
      lastSelectedProductId = null;
    }
    refreshOptionStates();
    updateProductImage();
    if (statusEl && statusEl.textContent) {
      var selections = getProductSelections();
      if (selections.length > 0) {
        statusEl.textContent = '';
      }
    }
  }

  function showFallbackMessage() {
    if (statusEl && !statusEl.textContent && !buttonsRendered) {
      statusEl.textContent = 'Unable to load PayPal checkout. Refresh or email orders@nuheat-hanger.com to place your order.';
    }
  }

  function createOrderOnServer() {
    sanitizeAllQuantities();
    updateProductImage();
    var payload = {};
    var selections = getProductSelections();
    if (!selections.length) {
      var error = new Error('Select at least one holder before checkout.');
      error.code = 'NO_SELECTION';
      if (statusEl) {
        statusEl.textContent = error.message;
      }
      var firstInput = document.querySelector(productInputSelector);
      if (firstInput && typeof firstInput.focus === 'function') {
        firstInput.focus();
      }
      return Promise.reject(error);
    }
    payload.items = selections;

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

  function updateProductImage() {
    if (!productImageEl) {
      return;
    }
    var selectedProduct = getPrimaryProductId();
    if (!selectedProduct) {
      return;
    }
    var config = productImageMap[selectedProduct];
    if (!config) {
      return;
    }
    productImageEl.setAttribute('src', config.src);
    productImageEl.setAttribute('alt', config.alt);
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
          if (err && err.code === 'NO_SELECTION') {
            return Promise.reject(err);
          }
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
    var productInputs = document.querySelectorAll(productInputSelector);
    if (productInputs && productInputs.length) {
      for (var i = 0; i < productInputs.length; i++) {
        var input = productInputs[i];
        input.addEventListener('input', function (event) {
          handleQuantityEvent(event, false);
        });
        input.addEventListener('change', function (event) {
          handleQuantityEvent(event, true);
        });
      }
    }

    var productOptions = document.querySelectorAll(productOptionSelector);
    if (productOptions && productOptions.length) {
      for (var j = 0; j < productOptions.length; j++) {
        (function () {
          var option = productOptions[j];
          var panel = option.querySelector(productPanelSelector);
          var input = option.querySelector(productInputSelector);
          if (!panel || !input) {
            return;
          }
          if (!panel.hasAttribute('tabindex')) {
            panel.setAttribute('tabindex', '0');
          }
          panel.setAttribute('role', 'button');
          panel.addEventListener('click', function (event) {
            if (event.target && matchesSelector && matchesSelector.call(event.target, productInputSelector)) {
              return;
            }
            if (parseQuantity(input.value) === 0) {
              input.value = '1';
            }
            handleQuantityEvent({ target: input }, true);
            if (typeof input.focus === 'function') {
              input.focus();
              if (typeof input.select === 'function') {
                input.select();
              }
            }
          });
          panel.addEventListener('keydown', function (event) {
            if (event.key === 'Enter' || event.key === ' ' || event.key === 'Spacebar') {
              event.preventDefault();
              if (parseQuantity(input.value) === 0) {
                input.value = '1';
              }
              handleQuantityEvent({ target: input }, true);
              if (typeof input.focus === 'function') {
                input.focus();
                if (typeof input.select === 'function') {
                  input.select();
                }
              }
            }
          });
        })();
      }
    }

    sanitizeAllQuantities();
    var initialSelections = getProductSelections();
    if (initialSelections.length) {
      lastSelectedProductId = initialSelections[0].productId;
    }
    refreshOptionStates();
    updateProductImage();
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

  json create_order(const std::vector<SelectedProduct> &selections) {
    if (selections.empty()) {
      throw std::invalid_argument("At least one product must be provided when creating an order");
    }

    const auto token = fetch_access_token();
    if (!token) {
      throw std::runtime_error("Unable to retrieve PayPal access token");
    }

    json items = json::array();
    int item_total_cents = 0;
    std::vector<std::string> summary_entries;
    summary_entries.reserve(selections.size());

    for (const auto &selection : selections) {
      if (!selection.option) {
        continue;
      }
      if (selection.quantity <= 0) {
        continue;
      }
      const auto &product = *selection.option;
      item_total_cents += product.unit_price_cents * selection.quantity;
      items.push_back({
          {"name", product.name},
          {"description", product.description},
          {"sku", product.reference_id},
          {"quantity", std::to_string(selection.quantity)},
          {"category", "PHYSICAL_GOODS"},
          {"unit_amount",
           json{
               {"currency_code", "USD"},
               {"value", format_price_cents(product.unit_price_cents)},
           }},
      });

      std::ostringstream line;
      line << product.name << " x" << selection.quantity;
      summary_entries.push_back(line.str());
    }

    if (items.empty() || item_total_cents <= 0) {
      throw std::invalid_argument("Order must contain at least one item with quantity greater than zero");
    }

    const int shipping_cents = kFlatShippingCents;
    const auto shipping_value = format_price_cents(shipping_cents);
    const auto item_value = format_price_cents(item_total_cents);
    const auto total_value = format_price_cents(item_total_cents + shipping_cents);

    const std::string reference_id = selections.size() == 1 && selections.front().option
                                         ? selections.front().option->reference_id
                                         : "NUHEAT-MULTI";

    std::ostringstream description_builder;
    for (std::size_t i = 0; i < summary_entries.size(); ++i) {
      if (i > 0) {
        description_builder << "; ";
      }
      description_builder << summary_entries[i];
    }
    const auto description = description_builder.str();

    json request_body = {
        {"intent", "CAPTURE"},
        {"purchase_units",
         json::array({json{
             {"reference_id", reference_id},
             {"description", description},
             {"custom_id", "Nuheat Sensor Holders"},
             {"items", items},
             {"amount",
              json{
                  {"currency_code", "USD"},
                  {"value", total_value},
                  {"breakdown",
                   json{
                       {"item_total", json{{"currency_code", "USD"}, {"value", item_value}}},
                       {"shipping", json{{"currency_code", "USD"}, {"value", shipping_value}}},
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

  bool verify_webhook_signature(const std::string &webhook_id,
                                const std::string &transmission_id,
                                const std::string &transmission_time,
                                const std::string &cert_url,
                                const std::string &auth_algo,
                                const std::string &transmission_sig,
                                const std::string &event_body_raw) {
    const auto token = fetch_access_token();
    if (!token) {
      throw std::runtime_error("Unable to retrieve PayPal access token");
    }

    ordered_json request_body = {
        {"transmission_id", transmission_id},
        {"transmission_time", transmission_time},
        {"cert_url", cert_url},
        {"auth_algo", auth_algo},
        {"transmission_sig", transmission_sig},
        {"webhook_id", webhook_id},
    };

    try {
      request_body["webhook_event"] = ordered_json::parse(event_body_raw);
    } catch (const nlohmann::json::parse_error &err) {
      std::ostringstream oss;
      oss << "Failed to parse webhook payload for verification: " << err.what();
      throw std::runtime_error(oss.str());
    }

    const auto url = base_url_ + "/v1/notifications/verify-webhook-signature";
    HttpResponse response = http_post(url,
                                      request_body.dump(),
                                      {
                                          "Content-Type: application/json",
                                          "Accept: application/json",
                                          "Authorization: Bearer " + *token,
                                      });

    if (!response.ok()) {
      std::ostringstream oss;
      oss << "Failed to verify PayPal webhook signature. HTTP status " << response.status
          << ". Error: " << response.error_message << ". Body: " << response.body;
      throw std::runtime_error(oss.str());
    }

    try {
      auto payload = json::parse(response.body);
      const auto status = payload.value("verification_status", std::string());
      const std::string serialized = payload.dump();
      if (status != "SUCCESS") {
        std::cerr << "[paypal] Webhook verification status=" << status << " response=" << serialized
                  << std::endl;
      }
      last_verify_response_ = serialized;
      return status == "SUCCESS";
    } catch (const json::parse_error &err) {
      std::ostringstream oss;
      oss << "Failed to parse PayPal webhook verification response: " << err.what();
      throw std::runtime_error(oss.str());
    }
  }

  HttpResponse get_order(const std::string &order_id) {
    return authorized_get("/v2/checkout/orders/" + order_id);
  }

  HttpResponse get_capture(const std::string &capture_id) {
    return authorized_get("/v2/payments/captures/" + capture_id);
  }

  HttpResponse get_transactions(const std::string &start_date,
                                const std::string &end_date,
                                const std::optional<int> &page,
                                const std::optional<int> &page_size,
                                const std::optional<std::string> &transaction_status,
                                const std::optional<std::string> &fields) {
    std::vector<std::string> query_params;
    query_params.push_back("start_date=" + url_encode(start_date));
    query_params.push_back("end_date=" + url_encode(end_date));

    if (page && *page > 0) {
      query_params.push_back("page=" + std::to_string(*page));
    }
    if (page_size && *page_size > 0) {
      query_params.push_back("page_size=" + std::to_string(*page_size));
    }
    if (transaction_status && !transaction_status->empty()) {
      query_params.push_back("transaction_status=" + url_encode(*transaction_status));
    }
    if (fields && !fields->empty()) {
      query_params.push_back("fields=" + url_encode(*fields));
    } else {
      query_params.push_back("fields=all");
    }

    std::string query;
    for (std::size_t i = 0; i < query_params.size(); ++i) {
      if (i > 0) {
        query += "&";
      }
      query += query_params[i];
    }

    return authorized_get("/v1/reporting/transactions?" + query);
  }

  const std::string &last_verify_response() const {
    return last_verify_response_;
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
  std::string last_verify_response_;

  HttpResponse authorized_get(const std::string &path) {
    const auto token = fetch_access_token();
    if (!token) {
      throw std::runtime_error("Unable to retrieve PayPal access token");
    }

    const auto url = base_url_ + path;
    HttpResponse response = http_get(url,
                                     {
                                         "Accept: application/json",
                                         "Authorization: Bearer " + *token,
                                     });

    return response;
  }
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

  res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
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
    const auto paypal_webhook_id = get_env_or_throw("PAYPAL_WEBHOOK_ID");
    const auto admin_access_pin = get_env_or_throw("ADMIN_ACCESS_PIN");

    PayPalClient paypal_client(paypal_client_id, paypal_client_secret, paypal_environment);

    const auto template_path = get_env_or_default("INDEX_TEMPLATE_PATH", "templates/index.html");
    const auto static_root = get_env_or_default("STATIC_ROOT", "../public");
    std::string index_template = load_file_or_throw(template_path);
    replace_all(index_template, "{{INLINE_PAYPAL_HELPER}}", kInlinePayPalHelper);
    replace_all(index_template, "{{PAYPAL_CLIENT_ID}}", paypal_client_id);
    const std::string index_html = index_template;
    const auto admin_template_path = get_env_or_default("ADMIN_TEMPLATE_PATH", "templates/admin.html");
    const std::string admin_html = load_file_or_throw(admin_template_path);

    httplib::Server server;

    if (!server.set_mount_point("/static", static_root.c_str())) {
      std::cerr << "[warning] Failed to mount static assets from " << static_root << std::endl;
    }

    const auto send_index = [&](const httplib::Request &, httplib::Response &res) {
      res.set_content(index_html, "text/html; charset=UTF-8");
    };
    server.Get("/", send_index);
    server.Get("/index.html", send_index);
    const auto send_admin = [&](const httplib::Request &, httplib::Response &res) {
      res.set_content(admin_html, "text/html; charset=UTF-8");
    };
    server.Get("/admin", send_admin);
    server.Get("/admin/index.html", send_admin);

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

    server.Options("/api/admin/paypal/lookup", [&](const httplib::Request &req, httplib::Response &res) {
      if (!is_request_origin_allowed(req, allowed_origins)) {
        res.status = 403;
        json err = {{"error", "Origin not allowed"}};
        res.set_content(err.dump(), "application/json");
      } else {
        res.status = 204;
      }
      append_cors_headers(req, res, allowed_origins);
    });
    server.Options("/api/admin/paypal/transactions", [&](const httplib::Request &req, httplib::Response &res) {
      if (!is_request_origin_allowed(req, allowed_origins)) {
        res.status = 403;
        json err = {{"error", "Origin not allowed"}};
        res.set_content(err.dump(), "application/json");
      } else {
        res.status = 204;
      }
      append_cors_headers(req, res, allowed_origins);
    });

    server.Options("/api/admin/login", [&](const httplib::Request &req, httplib::Response &res) {
      if (!is_request_origin_allowed(req, allowed_origins)) {
        res.status = 403;
        json err = {{"error", "Origin not allowed"}};
        res.set_content(err.dump(), "application/json");
      } else {
        res.status = 204;
      }
      append_cors_headers(req, res, allowed_origins);
    });

    server.Options("/api/admin/logout", [&](const httplib::Request &req, httplib::Response &res) {
      if (!is_request_origin_allowed(req, allowed_origins)) {
        res.status = 403;
        json err = {{"error", "Origin not allowed"}};
        res.set_content(err.dump(), "application/json");
      } else {
        res.status = 204;
      }
      append_cors_headers(req, res, allowed_origins);
    });

    server.Options("/api/admin/session", [&](const httplib::Request &req, httplib::Response &res) {
      if (!is_request_origin_allowed(req, allowed_origins)) {
        res.status = 403;
        json err = {{"error", "Origin not allowed"}};
        res.set_content(err.dump(), "application/json");
      } else {
        res.status = 204;
      }
      append_cors_headers(req, res, allowed_origins);
    });

    server.Post("/api/admin/login",
                [&](const httplib::Request &req, httplib::Response &res) {
                  res.set_header("Cache-Control", "no-store");

                  if (!is_request_origin_allowed(req, allowed_origins)) {
                    res.status = 403;
                    json err = {{"error", "Origin not allowed"}};
                    res.set_content(err.dump(), "application/json");
                    append_cors_headers(req, res, allowed_origins);
                    return;
                  }

                  if (is_admin_authenticated(req)) {
                    res.status = 200;
                    json payload = {
                        {"status", "ok"},
                        {"message", "Already signed in"},
                    };
                    res.set_content(payload.dump(), "application/json");
                    append_cors_headers(req, res, allowed_origins);
                    return;
                  }

                  if (!is_json_content_type(req.get_header_value("Content-Type"))) {
                    res.status = 415;
                    json err = {{"error", "Content-Type must be application/json"}};
                    res.set_content(err.dump(), "application/json");
                    append_cors_headers(req, res, allowed_origins);
                    return;
                  }

                  if (req.body.empty()) {
                    res.status = 400;
                    json err = {{"error", "Missing request body"}};
                    res.set_content(err.dump(), "application/json");
                    append_cors_headers(req, res, allowed_origins);
                    return;
                  }

                  try {
                    const json body = json::parse(req.body);
                    if (!body.contains("pin") || !body.at("pin").is_string()) {
                      res.status = 400;
                      json err = {{"error", "pin is required and must be a string"}};
                      res.set_content(err.dump(), "application/json");
                      append_cors_headers(req, res, allowed_origins);
                      return;
                    }

                    const std::string provided_pin = trim_copy(body.at("pin").get<std::string>());
                    const std::string remote_ip = req.remote_addr.empty() ? "<unknown>" : req.remote_addr;

                    const auto block_status = check_login_block(remote_ip);
                    if (!block_status.allowed && block_status.blocked) {
                      const auto retry_seconds = format_duration_seconds(block_status.retry_after);
                      res.status = 429;
                      res.set_header("Retry-After", retry_seconds);
                      json err = {
                          {"error", "Too many attempts. Try again later."},
                          {"retryAfterSeconds", retry_seconds},
                      };
                      res.set_content(err.dump(), "application/json");
                      std::cerr << "[admin][login] Rate limit active for " << remote_ip << std::endl;
                      append_cors_headers(req, res, allowed_origins);
                      return;
                    }

                    const bool pin_valid = provided_pin == admin_access_pin;
                    if (!pin_valid) {
                      const auto decision = evaluate_login_attempt(remote_ip, false);
                      if (decision.blocked) {
                        const auto retry_seconds = format_duration_seconds(decision.retry_after);
                        res.status = 429;
                        res.set_header("Retry-After", retry_seconds);
                        json err = {
                            {"error", "Too many attempts. Try again later."},
                            {"retryAfterSeconds", retry_seconds},
                        };
                        res.set_content(err.dump(), "application/json");
                        std::cerr << "[admin][login] Locking out " << remote_ip << " after repeated failures"
                                  << std::endl;
                      } else {
                        res.status = 401;
                        json err = {{"error", "Invalid PIN"}};
                        res.set_content(err.dump(), "application/json");
                      }
                      std::cerr << "[admin][login] Invalid PIN attempt from " << remote_ip << std::endl;
                      append_cors_headers(req, res, allowed_origins);
                      return;
                    }

                    evaluate_login_attempt(remote_ip, true);

                    const auto session_token = issue_admin_session(remote_ip);
                    const auto session_max_age =
                        std::chrono::duration_cast<std::chrono::seconds>(kAdminSessionTtl).count();

                    std::ostringstream cookie;
                    cookie << kAdminSessionCookieName << '=' << session_token
                           << "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" << session_max_age;
                    res.set_header("Set-Cookie", cookie.str());

                    res.status = 200;
                    json payload = {
                        {"status", "ok"},
                    };
                    res.set_content(payload.dump(), "application/json");
                    std::cout << "[admin][login] PIN accepted from " << remote_ip << std::endl;
                  } catch (const json::parse_error &err) {
                    res.status = 400;
                    json payload = {
                        {"error", "Invalid JSON payload"},
                        {"details", err.what()},
                    };
                    res.set_content(payload.dump(), "application/json");
                  }

                  append_cors_headers(req, res, allowed_origins);
                });

    server.Post("/api/admin/logout",
                [&](const httplib::Request &req, httplib::Response &res) {
                  res.set_header("Cache-Control", "no-store");

                  if (!is_request_origin_allowed(req, allowed_origins)) {
                    res.status = 403;
                    json err = {{"error", "Origin not allowed"}};
                    res.set_content(err.dump(), "application/json");
                    append_cors_headers(req, res, allowed_origins);
                    return;
                  }

                  if (const auto token = extract_admin_session_token(req)) {
                    invalidate_admin_session(*token);
                  }

                  res.set_header("Set-Cookie",
                                 std::string(kAdminSessionCookieName) +
                                     "=deleted; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
                  res.status = 200;
                  json payload = {
                      {"status", "signed_out"},
                  };
                  res.set_content(payload.dump(), "application/json");
                  append_cors_headers(req, res, allowed_origins);
                });

    server.Get("/api/admin/session",
               [&](const httplib::Request &req, httplib::Response &res) {
                 res.set_header("Cache-Control", "no-store");

                 if (!is_request_origin_allowed(req, allowed_origins)) {
                   res.status = 403;
                   json err = {{"error", "Origin not allowed"}};
                   res.set_content(err.dump(), "application/json");
                   append_cors_headers(req, res, allowed_origins);
                   return;
                 }

                 const bool authenticated = is_admin_authenticated(req);
                 res.status = 200;
                 json payload = {
                     {"authenticated", authenticated},
                 };
                 res.set_content(payload.dump(), "application/json");

                 if (!authenticated) {
                   res.set_header("Set-Cookie",
                                  std::string(kAdminSessionCookieName) +
                                      "=deleted; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
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
                    std::vector<SelectedProduct> selections;
                    std::vector<std::string> requested_order;
                    std::unordered_map<std::string, int> quantity_by_product;
                    bool legacy_payload_invalid = false;
                    std::string legacy_payload_error;

                    auto apply_legacy_payload = [&](const json &body) {
                      if (!body.contains("productId")) {
                        return;
                      }
                      if (!body.at("productId").is_string()) {
                        legacy_payload_invalid = true;
                        legacy_payload_error = "productId must be a string";
                        return;
                      }
                      const auto legacy_id = body.at("productId").get<std::string>();
                      if (legacy_id.empty()) {
                        return;
                      }
                      quantity_by_product[legacy_id] += 1;
                      if (std::find(requested_order.begin(), requested_order.end(), legacy_id) == requested_order.end()) {
                        requested_order.push_back(legacy_id);
                      }
                    };

                    if (!req.body.empty()) {
                      if (!is_json_content_type(req.get_header_value("Content-Type"))) {
                        res.status = 415;
                        json err = {{"error", "Content-Type must be application/json"}};
                        res.set_content(err.dump(), "application/json");
                        append_cors_headers(req, res, allowed_origins);
                        return;
                      }

                      auto body = json::parse(req.body);
                      if (body.contains("items")) {
                        if (!body.at("items").is_array()) {
                          res.status = 400;
                          json err = {{"error", "items must be an array"}};
                          res.set_content(err.dump(), "application/json");
                          append_cors_headers(req, res, allowed_origins);
                          return;
                        }
                        for (const auto &entry : body.at("items")) {
                          if (!entry.is_object()) {
                            res.status = 400;
                            json err = {{"error", "Each item must be an object"}};
                            res.set_content(err.dump(), "application/json");
                            append_cors_headers(req, res, allowed_origins);
                            return;
                          }
                          if (!entry.contains("productId") || !entry.at("productId").is_string()) {
                            res.status = 400;
                            json err = {{"error", "Each item requires a string productId"}};
                            res.set_content(err.dump(), "application/json");
                            append_cors_headers(req, res, allowed_origins);
                            return;
                          }
                          if (!entry.contains("quantity")) {
                            res.status = 400;
                            json err = {{"error", "Each item requires a quantity"}};
                            res.set_content(err.dump(), "application/json");
                            append_cors_headers(req, res, allowed_origins);
                            return;
                          }
                          const std::string product_id = entry.at("productId").get<std::string>();
                          const auto quantity_value = entry.at("quantity");
                          if (!quantity_value.is_number_integer()) {
                            res.status = 400;
                            json err = {{"error", "quantity must be an integer"}};
                            res.set_content(err.dump(), "application/json");
                            append_cors_headers(req, res, allowed_origins);
                            return;
                          }
                          const int quantity = quantity_value.get<int>();
                          if (quantity <= 0) {
                            continue;
                          }
                          quantity_by_product[product_id] += quantity;
                          if (std::find(requested_order.begin(), requested_order.end(), product_id) == requested_order.end()) {
                            requested_order.push_back(product_id);
                          }
                        }
                      } else {
                        apply_legacy_payload(body);
                        if (legacy_payload_invalid) {
                          res.status = 400;
                          json err = {{"error", legacy_payload_error}};
                          res.set_content(err.dump(), "application/json");
                          append_cors_headers(req, res, allowed_origins);
                          return;
                        }
                      }
                    }

                    if (quantity_by_product.empty()) {
                      const auto &product = default_product();
                      quantity_by_product[product.id] = 1;
                      requested_order.push_back(product.id);
                    }

                    for (const auto &product_id : requested_order) {
                      const auto quantity_it = quantity_by_product.find(product_id);
                      if (quantity_it == quantity_by_product.end()) {
                        continue;
                      }
                      const auto *product = find_product_by_id(product_id);
                      if (!product) {
                        res.status = 422;
                        json err = {{"error", "Unknown productId"}, {"details", product_id}};
                        res.set_content(err.dump(), "application/json");
                        append_cors_headers(req, res, allowed_origins);
                        return;
                      }
                      if (quantity_it->second <= 0) {
                        continue;
                      }
                      selections.push_back(SelectedProduct{product, quantity_it->second});
                    }

                    if (selections.empty()) {
                      res.status = 422;
                      json err = {{"error", "At least one product with quantity greater than zero is required"}};
                      res.set_content(err.dump(), "application/json");
                      append_cors_headers(req, res, allowed_origins);
                      return;
                    }

                    auto order = paypal_client.create_order(selections);
                    json selected_items = json::array();
                    for (const auto &selection : selections) {
                      selected_items.push_back({
                          {"productId", selection.option->id},
                          {"quantity", selection.quantity},
                      });
                    }
                    json response = {
                        {"orderID", order.at("id")},
                        {"status", order.value("status", "UNKNOWN")},
                        {"items", selected_items},
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

    server.Post("/api/admin/paypal/lookup",
                [&](const httplib::Request &req, httplib::Response &res) {
                  res.set_header("Cache-Control", "no-store");

                  if (!is_request_origin_allowed(req, allowed_origins)) {
                    res.status = 403;
                    json err = {{"error", "Origin not allowed"}};
                    res.set_content(err.dump(), "application/json");
                    append_cors_headers(req, res, allowed_origins);
                    return;
                  }

                  if (!is_admin_authenticated(req)) {
                    res.status = 401;
                    json err = {{"error", "Authentication required"}};
                    res.set_content(err.dump(), "application/json");
                    append_cors_headers(req, res, allowed_origins);
                    return;
                  }

                  if (!is_json_content_type(req.get_header_value("Content-Type"))) {
                    res.status = 415;
                    json err = {{"error", "Content-Type must be application/json"}};
                    res.set_content(err.dump(), "application/json");
                    append_cors_headers(req, res, allowed_origins);
                    return;
                  }

                  if (req.body.empty()) {
                    res.status = 400;
                    json err = {{"error", "Missing request body"}};
                    res.set_content(err.dump(), "application/json");
                    append_cors_headers(req, res, allowed_origins);
                    return;
                  }

                  try {
                    const json body = json::parse(req.body);
                    if (!body.contains("id") || !body.at("id").is_string()) {
                      res.status = 400;
                      json err = {{"error", "id is required and must be a string"}};
                      res.set_content(err.dump(), "application/json");
                      append_cors_headers(req, res, allowed_origins);
                      return;
                    }

                    std::string lookup_type = "capture";
                    if (body.contains("type")) {
                      if (!body.at("type").is_string()) {
                        res.status = 400;
                        json err = {{"error", "type must be a string"}};
                        res.set_content(err.dump(), "application/json");
                        append_cors_headers(req, res, allowed_origins);
                        return;
                      }
                      lookup_type = to_lower_copy(trim_copy(body.at("type").get<std::string>()));
                    }

                    const std::string resource_id = trim_copy(body.at("id").get<std::string>());
                    if (!is_valid_paypal_resource_id(resource_id)) {
                      res.status = 422;
                      json err = {{"error", "id format is invalid"}};
                      res.set_content(err.dump(), "application/json");
                      append_cors_headers(req, res, allowed_origins);
                      return;
                    }

                    HttpResponse remote;
                    if (lookup_type == "order") {
                      remote = paypal_client.get_order(resource_id);
                    } else if (lookup_type == "capture") {
                      remote = paypal_client.get_capture(resource_id);
                    } else {
                      res.status = 400;
                      json err = {{"error", "type must be \"order\" or \"capture\""}};
                      res.set_content(err.dump(), "application/json");
                      append_cors_headers(req, res, allowed_origins);
                      return;
                    }

                    if (remote.status == 404) {
                      res.status = 404;
                      json err = {
                          {"error", "Resource not found in PayPal"},
                          {"resourceId", resource_id},
                          {"resourceType", lookup_type},
                      };
                      res.set_content(err.dump(), "application/json");
                      append_cors_headers(req, res, allowed_origins);
                      return;
                    }

                    if (!remote.ok()) {
                      res.status = 502;
                      json err = {
                          {"error", "Failed to retrieve resource from PayPal"},
                          {"status", remote.status},
                          {"message", remote.error_message},
                      };
                      if (!remote.body.empty()) {
                        err["body"] = remote.body;
                      }
                      res.set_content(err.dump(), "application/json");
                      append_cors_headers(req, res, allowed_origins);
                      return;
                    }

                    try {
                      const json payload = json::parse(remote.body);
                      json result = {
                          {"status", "ok"},
                          {"resourceType", lookup_type},
                          {"resourceId", resource_id},
                          {"payload", payload},
                      };
                      res.status = 200;
                      res.set_content(result.dump(), "application/json");
                      std::cout << "[paypal][admin] Lookup success type=" << lookup_type
                                << " id=" << resource_id << std::endl;
                    } catch (const json::parse_error &err) {
                      res.status = 502;
                      json err_payload = {
                          {"error", "Unable to parse PayPal response"},
                          {"details", err.what()},
                      };
                      res.set_content(err_payload.dump(), "application/json");
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
                        {"error", "Lookup failed"},
                        {"details", ex.what()},
                    };
                    res.set_content(err.dump(), "application/json");
                    std::cerr << "[paypal][admin] Lookup failed: " << ex.what() << std::endl;
                  }

                  append_cors_headers(req, res, allowed_origins);
                });

    server.Post("/api/admin/paypal/transactions",
                [&](const httplib::Request &req, httplib::Response &res) {
                  res.set_header("Cache-Control", "no-store");

                  if (!is_request_origin_allowed(req, allowed_origins)) {
                    res.status = 403;
                    json err = {{"error", "Origin not allowed"}};
                    res.set_content(err.dump(), "application/json");
                    append_cors_headers(req, res, allowed_origins);
                    return;
                  }

                  if (!is_admin_authenticated(req)) {
                    res.status = 401;
                    json err = {{"error", "Authentication required"}};
                    res.set_content(err.dump(), "application/json");
                    append_cors_headers(req, res, allowed_origins);
                    return;
                  }

                  if (!is_json_content_type(req.get_header_value("Content-Type"))) {
                    res.status = 415;
                    json err = {{"error", "Content-Type must be application/json"}};
                    res.set_content(err.dump(), "application/json");
                    append_cors_headers(req, res, allowed_origins);
                    return;
                  }

                  if (req.body.empty()) {
                    res.status = 400;
                    json err = {{"error", "Missing request body"}};
                    res.set_content(err.dump(), "application/json");
                    append_cors_headers(req, res, allowed_origins);
                    return;
                  }

                  try {
                    const json body = json::parse(req.body);

                    if (!body.contains("startDate") || !body.at("startDate").is_string()) {
                      res.status = 400;
                      json err = {{"error", "startDate is required and must be a string"}};
                      res.set_content(err.dump(), "application/json");
                      append_cors_headers(req, res, allowed_origins);
                      return;
                    }
                    if (!body.contains("endDate") || !body.at("endDate").is_string()) {
                      res.status = 400;
                      json err = {{"error", "endDate is required and must be a string"}};
                      res.set_content(err.dump(), "application/json");
                      append_cors_headers(req, res, allowed_origins);
                      return;
                    }

                    const std::string start_date = trim_copy(body.at("startDate").get<std::string>());
                    const std::string end_date = trim_copy(body.at("endDate").get<std::string>());
                    if (start_date.empty() || end_date.empty()) {
                      res.status = 422;
                      json err = {{"error", "startDate and endDate cannot be empty"}};
                      res.set_content(err.dump(), "application/json");
                      append_cors_headers(req, res, allowed_origins);
                      return;
                    }

                    if (!is_valid_rfc3339_datetime(start_date) || !is_valid_rfc3339_datetime(end_date)) {
                      res.status = 422;
                      json err = {{"error", "startDate and endDate must be RFC3339 timestamps"}};
                      res.set_content(err.dump(), "application/json");
                      append_cors_headers(req, res, allowed_origins);
                      return;
                    }

                    if (start_date > end_date) {
                      res.status = 422;
                      json err = {{"error", "startDate must be before endDate"}};
                      res.set_content(err.dump(), "application/json");
                      append_cors_headers(req, res, allowed_origins);
                      return;
                    }

                    int page = 1;
                    if (body.contains("page")) {
                      const auto &page_node = body.at("page");
                      if (!page_node.is_number_integer()) {
                        res.status = 400;
                        json err = {{"error", "page must be an integer"}};
                        res.set_content(err.dump(), "application/json");
                        append_cors_headers(req, res, allowed_origins);
                        return;
                      }
                      page = page_node.get<int>();
                      if (page < 1) {
                        res.status = 422;
                        json err = {{"error", "page must be at least 1"}};
                        res.set_content(err.dump(), "application/json");
                        append_cors_headers(req, res, allowed_origins);
                        return;
                      }
                    }

                    int page_size = 100;
                    if (body.contains("pageSize")) {
                      const auto &size_node = body.at("pageSize");
                      if (!size_node.is_number_integer()) {
                        res.status = 400;
                        json err = {{"error", "pageSize must be an integer"}};
                        res.set_content(err.dump(), "application/json");
                        append_cors_headers(req, res, allowed_origins);
                        return;
                      }
                      page_size = size_node.get<int>();
                      if (page_size < 1 || page_size > 500) {
                        res.status = 422;
                        json err = {{"error", "pageSize must be between 1 and 500"}};
                        res.set_content(err.dump(), "application/json");
                        append_cors_headers(req, res, allowed_origins);
                        return;
                      }
                    }

                    std::optional<std::string> transaction_status;
                    if (body.contains("transactionStatus")) {
                      if (!body.at("transactionStatus").is_string()) {
                        res.status = 400;
                        json err = {{"error", "transactionStatus must be a string"}};
                        res.set_content(err.dump(), "application/json");
                        append_cors_headers(req, res, allowed_origins);
                        return;
                      }
                      std::string status_value =
                          trim_copy(body.at("transactionStatus").get<std::string>());
                      if (!status_value.empty()) {
                        std::transform(status_value.begin(),
                                       status_value.end(),
                                       status_value.begin(),
                                       [](unsigned char ch) { return static_cast<char>(std::toupper(ch)); });
                        transaction_status = status_value;
                      }
                    }

                    std::optional<std::string> fields;
                    if (body.contains("fields")) {
                      if (!body.at("fields").is_string()) {
                        res.status = 400;
                        json err = {{"error", "fields must be a string"}};
                        res.set_content(err.dump(), "application/json");
                        append_cors_headers(req, res, allowed_origins);
                        return;
                      }
                      std::string fields_value = trim_copy(body.at("fields").get<std::string>());
                      if (!fields_value.empty()) {
                        fields = fields_value;
                      }
                    }

                    const std::optional<int> page_param = page > 0 ? std::optional<int>(page) : std::nullopt;
                    const std::optional<int> page_size_param =
                        page_size > 0 ? std::optional<int>(page_size) : std::nullopt;

                    HttpResponse remote = paypal_client.get_transactions(start_date,
                                                                         end_date,
                                                                         page_param,
                                                                         page_size_param,
                                                                         transaction_status,
                                                                         fields);

                    if (!remote.ok()) {
                      res.status = remote.status == 0 ? 502 : static_cast<int>(remote.status);
                      json err = {
                          {"error", "Failed to retrieve transactions from PayPal"},
                          {"status", remote.status},
                          {"message", remote.error_message},
                      };
                      if (!remote.body.empty()) {
                        err["body"] = remote.body;
                      }
                      res.set_content(err.dump(), "application/json");
                      append_cors_headers(req, res, allowed_origins);
                      return;
                    }

                    try {
                      const json payload = json::parse(remote.body);
                      std::size_t returned = 0;
                      if (payload.contains("transaction_details") &&
                          payload.at("transaction_details").is_array()) {
                        returned = payload.at("transaction_details").size();
                      }
                      json result = {
                          {"status", "ok"},
                          {"startDate", start_date},
                          {"endDate", end_date},
                          {"page", page},
                          {"pageSize", page_size},
                          {"payload", payload},
                          {"returned", returned},
                      };
                      if (transaction_status) {
                        result["transactionStatus"] = *transaction_status;
                      }
                      if (fields) {
                        result["fields"] = *fields;
                      } else {
                        result["fields"] = "all";
                      }

                      res.status = 200;
                      res.set_content(result.dump(), "application/json");
                      std::cout << "[paypal][admin] Transaction search start=" << start_date
                                << " end=" << end_date << " page=" << page << " size=" << page_size
                                << " returned=" << returned << std::endl;
                    } catch (const json::parse_error &err) {
                      res.status = 502;
                      json err_payload = {
                          {"error", "Unable to parse PayPal response"},
                          {"details", err.what()},
                      };
                      res.set_content(err_payload.dump(), "application/json");
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
                        {"error", "Transaction search failed"},
                        {"details", ex.what()},
                    };
                    res.set_content(err.dump(), "application/json");
                    std::cerr << "[paypal][admin] Transaction search failed: " << ex.what() << std::endl;
                  }

                  append_cors_headers(req, res, allowed_origins);
                });

    server.Post("/api/paypal/ipn",
                [&](const httplib::Request &req, httplib::Response &res) {
                  res.set_header("Cache-Control", "no-store");

                  const auto content_type = req.get_header_value("Content-Type");
                  const bool request_is_json = is_json_content_type(content_type);

                  if (request_is_json) {
                    if (req.body.empty()) {
                      res.status = 400;
                      res.set_content("Missing webhook payload", "text/plain; charset=UTF-8");
                      std::cerr << "[paypal][webhook] Received empty payload" << std::endl;
                      return;
                    }

                    try {
                      const auto transmission_id = req.get_header_value("PAYPAL-TRANSMISSION-ID");
                      const auto transmission_time = req.get_header_value("PAYPAL-TRANSMISSION-TIME");
                      const auto cert_url = req.get_header_value("PAYPAL-CERT-URL");
                      const auto auth_algo = req.get_header_value("PAYPAL-AUTH-ALGO");
                      const auto transmission_sig = req.get_header_value("PAYPAL-TRANSMISSION-SIG");

                      if (transmission_id.empty() || transmission_time.empty() || cert_url.empty() ||
                          auth_algo.empty() || transmission_sig.empty()) {
                        res.status = 400;
                        res.set_content("Missing PayPal verification headers", "text/plain; charset=UTF-8");
                        std::cerr << "[paypal][webhook] Missing verification headers. transmission_id="
                                  << (transmission_id.empty() ? "<empty>" : transmission_id) << std::endl;
                        return;
                      }

                      const json event = json::parse(req.body);
                      const auto event_id = event.value("id", std::string("<unknown>"));
                      const auto event_type = event.value("event_type", std::string("<unknown>"));
                      const auto resource_type = event.value("resource_type", std::string("<unknown>"));

                      bool verified = false;
                      std::string webhook_id = req.get_header_value("PAYPAL-WEBHOOK-ID");
                      if (webhook_id.empty()) {
                        webhook_id = paypal_webhook_id;
                      } else if (webhook_id != paypal_webhook_id) {
                        std::cerr << "[paypal][webhook] Header webhook id " << webhook_id
                                  << " differs from configured id " << paypal_webhook_id << std::endl;
                      }

                      try {
                        verified = paypal_client.verify_webhook_signature(webhook_id,
                                                                          transmission_id,
                                                                          transmission_time,
                                                                          cert_url,
                                                                          auth_algo,
                                                                          transmission_sig,
                                                                          req.body);
                      } catch (const std::exception &verify_err) {
                        res.status = 500;
                        res.set_content("Webhook verification failure", "text/plain; charset=UTF-8");
                        std::cerr << "[paypal][webhook] Verification failed for event " << event_id
                                  << ": " << verify_err.what() << std::endl;
                        return;
                      }

                      if (!verified) {
                        res.status = 400;
                        res.set_content("Webhook signature invalid", "text/plain; charset=UTF-8");
                        const auto verify_payload = paypal_client.last_verify_response();
                        if (!verify_payload.empty()) {
                          std::cerr << "[paypal][webhook] Verification response: " << verify_payload << std::endl;
                        }
                        std::cerr << "[paypal][webhook] INVALID signature for event " << event_id
                                  << " type=" << event_type << " webhook_id=" << webhook_id << std::endl;
                        return;
                      }

                      std::string resource_id;
                      if (event.contains("resource") && event.at("resource").is_object()) {
                        const auto &resource = event.at("resource");
                        if (resource.contains("id") && resource.at("id").is_string()) {
                          resource_id = resource.at("id").get<std::string>();
                        } else if (resource.contains("supplementary_data") &&
                                   resource.at("supplementary_data").is_object()) {
                          const auto &supplementary = resource.at("supplementary_data");
                          if (supplementary.contains("related_ids") &&
                              supplementary.at("related_ids").is_object()) {
                            const auto &related = supplementary.at("related_ids");
                            if (related.contains("order_id") && related.at("order_id").is_string()) {
                              resource_id = related.at("order_id").get<std::string>();
                            }
                          }
                        }
                      }

                      std::cout << "[paypal][webhook] VERIFIED event_id=" << event_id
                                << " type=" << event_type << " resource_type=" << resource_type
                                << " resource_id=" << (resource_id.empty() ? "<none>" : resource_id) << std::endl;

                      res.status = 200;
                      json response_body = {
                          {"status", "accepted"},
                          {"eventId", event_id},
                          {"eventType", event_type},
                      };
                      res.set_content(response_body.dump(), "application/json");
                    } catch (const json::parse_error &err) {
                      res.status = 400;
                      res.set_content("Invalid JSON payload", "text/plain; charset=UTF-8");
                      std::cerr << "[paypal][webhook] Failed to parse payload: " << err.what() << std::endl;
                    }
                    return;
                  }

                  if (req.body.empty()) {
                    res.status = 400;
                    res.set_content("Missing IPN payload", "text/plain; charset=UTF-8");
                    std::cerr << "[paypal][ipn] Received empty payload" << std::endl;
                    return;
                  }

                  const std::string verify_url = paypal_ipn_verify_url(paypal_environment);
                  std::string verify_payload = "cmd=_notify-validate";
                  verify_payload.reserve(verify_payload.size() + 1 + req.body.size());
                  if (!req.body.empty()) {
                    verify_payload.push_back('&');
                    verify_payload.append(req.body);
                  }

                  HttpResponse verify_response =
                      http_post(verify_url,
                                verify_payload,
                                {
                                    "Content-Type: application/x-www-form-urlencoded",
                                    "Connection: close",
                                });

                  if (!verify_response.ok()) {
                    res.status = 500;
                    res.set_content("Verification transport failure", "text/plain; charset=UTF-8");
                    std::cerr << "[paypal][ipn] Verification request failed. HTTP status "
                              << verify_response.status << ". Error: " << verify_response.error_message
                              << ". Body: " << verify_response.body << std::endl;
                    return;
                  }

                  const std::string verification_status = trim_copy(verify_response.body);
                  const bool verified = verification_status == "VERIFIED";
                  const bool invalid = verification_status == "INVALID";

                  const auto params = parse_urlencoded_body(req.body);
                  const auto get_param = [&](const std::string &key) -> std::string {
                    const auto it = params.find(key);
                    return it != params.end() ? it->second : std::string();
                  };

                  const std::string txn_id = get_param("txn_id");
                  const std::string payment_status = get_param("payment_status");
                  const std::string payer_email = get_param("payer_email");
                  const std::string mc_gross = get_param("mc_gross");
                  const std::string invoice = get_param("invoice");

                  if (verified) {
                    std::cout << "[paypal][ipn] VERIFIED txn_id=" << (txn_id.empty() ? "<none>" : txn_id)
                              << " status=" << (payment_status.empty() ? "<unknown>" : payment_status)
                              << " gross=" << (mc_gross.empty() ? "<n/a>" : mc_gross)
                              << " invoice=" << (invoice.empty() ? "<none>" : invoice)
                              << " payer=" << (payer_email.empty() ? "<hidden>" : payer_email) << std::endl;
                  } else if (invalid) {
                    std::cerr << "[paypal][ipn] INVALID payload txn_id=" << (txn_id.empty() ? "<none>" : txn_id)
                              << " status=" << (payment_status.empty() ? "<unknown>" : payment_status)
                              << std::endl;
                  } else {
                    std::cerr << "[paypal][ipn] Unexpected verification response: " << verification_status
                              << ". txn_id=" << (txn_id.empty() ? "<none>" : txn_id) << std::endl;
                  }

                  res.status = 200;
                  if (verified) {
                    res.set_content("VERIFIED", "text/plain; charset=UTF-8");
                  } else if (invalid) {
                    res.set_content("INVALID", "text/plain; charset=UTF-8");
                  } else {
                    res.set_content("UNKNOWN", "text/plain; charset=UTF-8");
                  }
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
