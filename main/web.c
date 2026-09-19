#include "web.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "auth.h"
#include "runner.h"
#include "storage.h"
#include "wifi.h"

static const char *TAG = "web";
static httpd_handle_t s_server = NULL;

static void set_security_headers(httpd_req_t *req, bool api) {
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(req, "Referrer-Policy", "no-referrer");
    httpd_resp_set_hdr(req, "Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    httpd_resp_set_hdr(req, "Content-Security-Policy",
                       "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; "
                       "worker-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    httpd_resp_set_hdr(req, "Cache-Control", api ? "no-store" : "no-cache, max-age=0");
}

static esp_err_t send_json(httpd_req_t *req, const char *json) {
    set_security_headers(req, true);
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    return httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t send_error(httpd_req_t *req, int status, const char *msg) {
    char buf[384];
    const char *status_text = "500 Internal Server Error";
    if (status == 400) status_text = "400 Bad Request";
    else if (status == 401) status_text = "401 Unauthorized";
    else if (status == 404) status_text = "404 Not Found";
    else if (status == 408) status_text = "408 Request Timeout";
    else if (status == 409) status_text = "409 Conflict";
    else if (status == 413) status_text = "413 Payload Too Large";
    else if (status == 429) status_text = "429 Too Many Requests";
    httpd_resp_set_status(req, status_text);
    int n = snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", msg ? msg : "request failed");
    if (n < 0 || (size_t)n >= sizeof(buf)) return ESP_FAIL;
    return send_json(req, buf);
}

static esp_err_t require_auth(httpd_req_t *req) {
    if (auth_request_authenticated(req)) return ESP_OK;
    return send_error(req, 401, "authentication required");
}

static bool query_name(httpd_req_t *req, char *name, size_t name_len) {
    size_t qlen = httpd_req_get_url_query_len(req);
    if (qlen == 0 || qlen > 128) return false;
    char *query = calloc(1, qlen + 1);
    if (!query) return false;
    if (httpd_req_get_url_query_str(req, query, qlen + 1) != ESP_OK) { free(query); return false; }
    esp_err_t err = httpd_query_key_value(query, "name", name, name_len);
    free(query);
    return err == ESP_OK && storage_valid_name(name);
}

static esp_err_t recv_body(httpd_req_t *req, size_t max_len, char **body, size_t *len) {
    if (req->content_len > max_len) return ESP_ERR_INVALID_SIZE;
    size_t n = (size_t)req->content_len;
    char *buf = calloc(1, n + 1);
    if (!buf) return ESP_ERR_NO_MEM;
    size_t off = 0;
    while (off < n) {
        int r = httpd_req_recv(req, buf + off, n - off);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (r <= 0) { free(buf); return ESP_FAIL; }
        off += (size_t)r;
    }
    buf[n] = '\0';
    *body = buf;
    *len = n;
    return ESP_OK;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool json_hex_field(const char *json, size_t json_len, const char *field, uint8_t *out, size_t out_len) {
    cJSON *root = cJSON_ParseWithLength(json, json_len);
    if (!root || !cJSON_IsObject(root)) { cJSON_Delete(root); return false; }
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, field);
    bool ok = cJSON_IsString(item) && item->valuestring && strlen(item->valuestring) == out_len * 2;
    if (ok) {
        const char *p = item->valuestring;
        for (size_t i = 0; i < out_len; ++i) {
            int hi = hex_value(*p++), lo = hex_value(*p++);
            if (hi < 0 || lo < 0) { ok = false; break; }
            out[i] = (uint8_t)((hi << 4) | lo);
        }
    }
    cJSON_Delete(root);
    return ok;
}

static esp_err_t static_handler(httpd_req_t *req) {
    const char *path = req->uri;
    const char *file = NULL;
    const char *type = NULL;
    if (strcmp(path, "/") == 0) {
        file = wifi_is_provisioning() ? "/littlefs/www/provision.html" : "/littlefs/www/index.html";
        type = "text/html; charset=utf-8";
    } else if (strcmp(path, "/style.css") == 0) {
        file = "/littlefs/www/style.css";
        type = "text/css; charset=utf-8";
    } else if (strcmp(path, "/app.js") == 0) {
        file = "/littlefs/www/app.js";
        type = "application/javascript; charset=utf-8";
    } else if (strcmp(path, "/crypto-worker.js") == 0) {
        file = "/littlefs/www/crypto-worker.js";
        type = "application/javascript; charset=utf-8";
    } else if (strcmp(path, "/crypto.wasm") == 0) {
        file = "/littlefs/www/crypto.wasm";
        type = "application/wasm";
    } else if (strcmp(path, "/provision.html") == 0) {
        file = "/littlefs/www/provision.html";
        type = "text/html; charset=utf-8";
    } else if (strcmp(path, "/provision.css") == 0) {
        file = "/littlefs/www/provision.css";
        type = "text/css; charset=utf-8";
    } else if (strcmp(path, "/provision.js") == 0) {
        file = "/littlefs/www/provision.js";
        type = "application/javascript; charset=utf-8";
    } else {
        return send_error(req, 404, "resource not found");
    }

    FILE *fp = fopen(file, "rb");
    if (!fp) return send_error(req, 404, "resource not found");
    set_security_headers(req, false);
    httpd_resp_set_type(req, type);
    uint8_t buf[1024];
    while (!feof(fp)) {
        size_t n = fread(buf, 1, sizeof(buf), fp);
        if (n > 0 && httpd_resp_send_chunk(req, (const char *)buf, n) != ESP_OK) {
            fclose(fp);
            return ESP_FAIL;
        }
        if (ferror(fp)) { fclose(fp); return ESP_FAIL; }
    }
    fclose(fp);
    return httpd_resp_send_chunk(req, NULL, 0);
}

static esp_err_t wifi_provision_handler(httpd_req_t *req) {
    if (!wifi_is_provisioning()) return send_error(req, 409, "Wi-Fi provisioning is not active");

    char *body = NULL;
    size_t len = 0;
    esp_err_t err = recv_body(req, 1024, &body, &len);
    if (err == ESP_ERR_INVALID_SIZE) return send_error(req, 413, "request is too large");
    if (err != ESP_OK) return send_error(req, 400, "failed to read request");

    cJSON *root = cJSON_ParseWithLength(body, len);
    free(body);
    if (!root || !cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return send_error(req, 400, "invalid JSON request");
    }

    const cJSON *ssid_item = cJSON_GetObjectItemCaseSensitive(root, "ssid");
    const cJSON *password_item = cJSON_GetObjectItemCaseSensitive(root, "password");
    if (!cJSON_IsString(ssid_item) || !ssid_item->valuestring ||
        !cJSON_IsString(password_item) || !password_item->valuestring) {
        cJSON_Delete(root);
        return send_error(req, 400, "ssid and password are required");
    }

    err = wifi_provision_credentials(ssid_item->valuestring, password_item->valuestring);
    cJSON_Delete(root);
    if (err == ESP_ERR_INVALID_ARG) return send_error(req, 400, "invalid Wi-Fi credentials");
    if (err != ESP_OK) return send_error(req, 500, "could not save Wi-Fi credentials");
    return send_json(req, "{\"ok\":true,\"rebooting\":true}");
}

static esp_err_t apps_handler(httpd_req_t *req) {
    esp_err_t auth = require_auth(req);
    if (auth != ESP_OK) return auth;
    char json[4096];
    esp_err_t err = storage_list_apps(json, sizeof(json));
    if (err != ESP_OK) return send_error(req, 500, "could not list apps");
    return send_json(req, json);
}

static esp_err_t app_get_handler(httpd_req_t *req, const char *name) {
    char *code = NULL;
    size_t len = 0;
    if (storage_read_code(name, &code, &len) != ESP_OK) return send_error(req, 404, "app not found");

    set_security_headers(req, true);
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    if (httpd_resp_send_chunk(req, "{\"name\":\"", 9) != ESP_OK) { free(code); return ESP_FAIL; }
    if (httpd_resp_send_chunk(req, name, strlen(name)) != ESP_OK) { free(code); return ESP_FAIL; }
    if (httpd_resp_send_chunk(req, "\",\"code\":\"", 10) != ESP_OK) { free(code); return ESP_FAIL; }

    char escaped[768];
    size_t used = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)code[i];
        const char *replacement = NULL;
        char small[2];
        size_t rep_len = 1;
        if (c == '"') { replacement = "\\\""; rep_len = 2; }
        else if (c == '\\') { replacement = "\\\\"; rep_len = 2; }
        else if (c == '\n') { replacement = "\\n"; rep_len = 2; }
        else if (c == '\r') { replacement = "\\r"; rep_len = 2; }
        else if (c == '\t') { replacement = "\\t"; rep_len = 2; }
        else if (c < 0x20) { replacement = "?"; rep_len = 1; }
        else { small[0] = (char)c; replacement = small; rep_len = 1; }
        if (used + rep_len > sizeof(escaped) - 1) {
            if (httpd_resp_send_chunk(req, escaped, used) != ESP_OK) { free(code); return ESP_FAIL; }
            used = 0;
        }
        memcpy(escaped + used, replacement, rep_len);
        used += rep_len;
    }
    if (used && httpd_resp_send_chunk(req, escaped, used) != ESP_OK) { free(code); return ESP_FAIL; }
    free(code);
    if (httpd_resp_send_chunk(req, "\"}", 2) != ESP_OK) return ESP_FAIL;
    return httpd_resp_send_chunk(req, NULL, 0);
}

static esp_err_t app_handler(httpd_req_t *req) {
    esp_err_t auth = require_auth(req);
    if (auth != ESP_OK) return auth;
    char name[APP_NAME_MAX + 1] = {0};
    if (!query_name(req, name, sizeof(name))) return send_error(req, 400, "invalid or missing app name");

    if (req->method == HTTP_GET) return app_get_handler(req, name);

    if (req->method == HTTP_POST) {
        char *body = NULL;
        size_t len = 0;
        esp_err_t err = recv_body(req, CONFIG_APP_MAX_CODE_SIZE, &body, &len);
        if (err == ESP_ERR_INVALID_SIZE) return send_error(req, 413, "code is too large");
        if (err != ESP_OK) return send_error(req, 400, "failed to read code");
        err = storage_write_code(name, body, len);
        free(body);
        if (err == ESP_ERR_INVALID_SIZE) return send_error(req, 413, "code is too large");
        if (err != ESP_OK) return send_error(req, 500, "failed to save app");
        return send_json(req, "{\"ok\":true}");
    }

    if (req->method == HTTP_DELETE) {
        if (runner_is_app_running(name)) {
            runner_request_stop();
            return send_error(req, 409, "app is running; stop requested, retry after it exits");
        }
        esp_err_t err = storage_delete_app(name);
        if (err == ESP_ERR_NOT_FOUND) return send_error(req, 404, "app not found");
        if (err != ESP_OK) return send_error(req, 500, "failed to delete app");
        return send_json(req, "{\"ok\":true}");
    }
    return send_error(req, 400, "method not supported");
}

static esp_err_t run_handler(httpd_req_t *req) {
    esp_err_t auth = require_auth(req);
    if (auth != ESP_OK) return auth;
    char name[APP_NAME_MAX + 1] = {0};
    if (!query_name(req, name, sizeof(name))) return send_error(req, 400, "invalid or missing app name");
    esp_err_t err = runner_start(name);
    if (err == ESP_ERR_INVALID_STATE) return send_error(req, 409, "another app is already running");
    if (err == ESP_ERR_NOT_FOUND) return send_error(req, 404, "app not found");
    if (err != ESP_OK) return send_error(req, 500, "could not start app");
    return send_json(req, "{\"ok\":true}");
}

static esp_err_t stop_handler(httpd_req_t *req) {
    esp_err_t auth = require_auth(req);
    if (auth != ESP_OK) return auth;
    esp_err_t err = runner_request_stop();
    if (err == ESP_ERR_INVALID_STATE) return send_error(req, 409, "no app is running");
    if (err != ESP_OK) return send_error(req, 500, "could not request stop");
    return send_json(req, "{\"ok\":true}");
}

static esp_err_t auth_challenge_handler(httpd_req_t *req, bool setup);

static esp_err_t status_handler(httpd_req_t *req) {
    esp_err_t auth = require_auth(req);
    if (auth != ESP_OK) return auth;
    char runner_json[512];
    runner_status_json(runner_json, sizeof(runner_json));
    char out[1024];
    int n = snprintf(out, sizeof(out),
                     "{\"freeHeap\":%u,\"minFreeHeap\":%u,\"uptimeMs\":%llu,\"runner\":%s}",
                     (unsigned)esp_get_free_heap_size(),
                     (unsigned)esp_get_minimum_free_heap_size(),
                     (unsigned long long)(esp_timer_get_time() / 1000ULL),
                     runner_json);
    if (n < 0 || (size_t)n >= sizeof(out)) return ESP_FAIL;
    return send_json(req, out);
}

static esp_err_t setup_challenge_route_handler(httpd_req_t *req) {
    return auth_challenge_handler(req, true);
}

static esp_err_t login_challenge_route_handler(httpd_req_t *req) {
    return auth_challenge_handler(req, false);
}

static esp_err_t auth_info_handler(httpd_req_t *req) {
    char json[256];
    esp_err_t err = auth_get_info_json(json, sizeof(json));
    if (err != ESP_OK) return send_error(req, 500, "could not load authentication state");
    return send_json(req, json);
}

static esp_err_t auth_challenge_handler(httpd_req_t *req, bool setup) {
    char json[256];
    esp_err_t err = auth_get_challenge_json(json, sizeof(json), setup);
    if (err == ESP_ERR_INVALID_STATE) return send_error(req, 409, setup ? "setup is not available" : "device is not configured");
    if (err == ESP_ERR_NOT_ALLOWED) return send_error(req, 429, "temporarily locked");
    if (err != ESP_OK) return send_error(req, 500, "could not create challenge");
    return send_json(req, json);
}

static esp_err_t auth_setup_handler(httpd_req_t *req) {
    char *body = NULL; size_t len = 0;
    esp_err_t err = recv_body(req, CONFIG_APP_HTTP_MAX_BODY < 2048 ? CONFIG_APP_HTTP_MAX_BODY : 2048, &body, &len);
    if (err == ESP_ERR_INVALID_SIZE) return send_error(req, 413, "request is too large");
    if (err != ESP_OK) return send_error(req, 400, "failed to read request");
    uint8_t proof[32], verifier[32];
    bool ok = json_hex_field(body, len, "proof", proof, sizeof(proof)) && json_hex_field(body, len, "verifier", verifier, sizeof(verifier));
    free(body);
    if (!ok) return send_error(req, 400, "invalid setup request");
    char session[AUTH_HEX_32_LEN + 1];
    err = auth_setup(proof, verifier, session);
    if (err == ESP_ERR_INVALID_CRC) return send_error(req, 401, "invalid setup code or challenge");
    if (err == ESP_ERR_TIMEOUT) return send_error(req, 408, "setup challenge expired");
    if (err == ESP_ERR_INVALID_STATE) return send_error(req, 409, "device is already configured");
    if (err != ESP_OK) return send_error(req, 500, "could not set password");
    char session_cookie[128];
    if (auth_set_session_cookie(req, session, session_cookie, sizeof(session_cookie)) != ESP_OK) return send_error(req, 500, "could not create session cookie");
    return send_json(req, "{\"ok\":true}");
}

static esp_err_t auth_login_handler(httpd_req_t *req) {
    char *body = NULL; size_t len = 0;
    esp_err_t err = recv_body(req, CONFIG_APP_HTTP_MAX_BODY < 1024 ? CONFIG_APP_HTTP_MAX_BODY : 1024, &body, &len);
    if (err == ESP_ERR_INVALID_SIZE) return send_error(req, 413, "request is too large");
    if (err != ESP_OK) return send_error(req, 400, "failed to read request");
    uint8_t proof[32];
    bool ok = json_hex_field(body, len, "proof", proof, sizeof(proof));
    free(body);
    if (!ok) return send_error(req, 400, "invalid login request");
    char session[AUTH_HEX_32_LEN + 1];
    err = auth_login(proof, session);
    if (err == ESP_ERR_NOT_ALLOWED) return send_error(req, 429, "too many failed logins; try again shortly");
    if (err == ESP_ERR_INVALID_CRC) return send_error(req, 401, "invalid password");
    if (err == ESP_ERR_TIMEOUT) return send_error(req, 408, "login challenge expired");
    if (err == ESP_ERR_INVALID_STATE) return send_error(req, 409, "device is not configured");
    if (err != ESP_OK) return send_error(req, 500, "login failed");
    char session_cookie[128];
    if (auth_set_session_cookie(req, session, session_cookie, sizeof(session_cookie)) != ESP_OK) return send_error(req, 500, "could not create session cookie");
    return send_json(req, "{\"ok\":true}");
}

static esp_err_t auth_me_handler(httpd_req_t *req) {
    char json[64];
    esp_err_t err = auth_get_me_json(req, json, sizeof(json));
    if (err != ESP_OK) return send_error(req, 401, "authentication required");
    return send_json(req, json);
}

static esp_err_t auth_logout_handler(httpd_req_t *req) {
    auth_logout(req);
    auth_clear_session_cookie(req);
    return send_json(req, "{\"ok\":true}");
}

static esp_err_t auth_password_info_handler(httpd_req_t *req) {
    char json[256];
    esp_err_t err = auth_get_password_info_json(req, json, sizeof(json));
    if (err == ESP_ERR_NOT_FOUND) return send_error(req, 401, "authentication required");
    if (err != ESP_OK) return send_error(req, 500, "could not create password salt");
    return send_json(req, json);
}

static esp_err_t auth_change_password_handler(httpd_req_t *req) {
    char *body = NULL; size_t len = 0;
    esp_err_t auth = require_auth(req);
    if (auth != ESP_OK) return auth;
    esp_err_t err = recv_body(req, CONFIG_APP_HTTP_MAX_BODY < 2048 ? CONFIG_APP_HTTP_MAX_BODY : 2048, &body, &len);
    if (err == ESP_ERR_INVALID_SIZE) return send_error(req, 413, "request is too large");
    if (err != ESP_OK) return send_error(req, 400, "failed to read request");
    uint8_t salt[16], verifier[32];
    bool ok = json_hex_field(body, len, "salt", salt, sizeof(salt)) && json_hex_field(body, len, "verifier", verifier, sizeof(verifier));
    free(body);
    if (!ok) return send_error(req, 400, "invalid password request");
    err = auth_change_password(req, salt, verifier);
    if (err == ESP_ERR_NOT_FOUND) return send_error(req, 401, "authentication required");
    if (err != ESP_OK) return send_error(req, 500, "could not change password");
    return send_json(req, "{\"ok\":true}");
}

esp_err_t web_start(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = CONFIG_APP_HTTP_PORT;
    config.max_uri_handlers = 24;
    config.stack_size = 8192;
    config.recv_wait_timeout = 10;
    config.send_wait_timeout = 10;
    config.lru_purge_enable = true;

    esp_err_t err = httpd_start(&s_server, &config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed: %s", esp_err_to_name(err));
        return err;
    }

    httpd_uri_t root = {.uri = "/", .method = HTTP_GET, .handler = static_handler};
    httpd_uri_t css = {.uri = "/style.css", .method = HTTP_GET, .handler = static_handler};
    httpd_uri_t js = {.uri = "/app.js", .method = HTTP_GET, .handler = static_handler};
    httpd_uri_t worker = {.uri = "/crypto-worker.js", .method = HTTP_GET, .handler = static_handler};
    httpd_uri_t wasm = {.uri = "/crypto.wasm", .method = HTTP_GET, .handler = static_handler};
    httpd_uri_t provision_html = {.uri = "/provision.html", .method = HTTP_GET, .handler = static_handler};
    httpd_uri_t provision_css = {.uri = "/provision.css", .method = HTTP_GET, .handler = static_handler};
    httpd_uri_t provision_js = {.uri = "/provision.js", .method = HTTP_GET, .handler = static_handler};

    httpd_uri_t wifi_provision = {.uri = "/api/wifi/provision", .method = HTTP_POST, .handler = wifi_provision_handler};

    httpd_uri_t auth_info = {.uri = "/api/auth/info", .method = HTTP_GET, .handler = auth_info_handler};
    httpd_uri_t setup_challenge = {.uri = "/api/auth/setup-challenge", .method = HTTP_GET, .handler = setup_challenge_route_handler};
    httpd_uri_t setup = {.uri = "/api/auth/setup", .method = HTTP_POST, .handler = auth_setup_handler};
    httpd_uri_t challenge = {.uri = "/api/auth/challenge", .method = HTTP_GET, .handler = login_challenge_route_handler};
    httpd_uri_t login = {.uri = "/api/auth/login", .method = HTTP_POST, .handler = auth_login_handler};
    httpd_uri_t me = {.uri = "/api/auth/me", .method = HTTP_GET, .handler = auth_me_handler};
    httpd_uri_t logout = {.uri = "/api/auth/logout", .method = HTTP_POST, .handler = auth_logout_handler};
    httpd_uri_t password_info = {.uri = "/api/auth/password-info", .method = HTTP_GET, .handler = auth_password_info_handler};
    httpd_uri_t change_password = {.uri = "/api/auth/change-password", .method = HTTP_POST, .handler = auth_change_password_handler};

    httpd_uri_t apps = {.uri = "/api/apps", .method = HTTP_GET, .handler = apps_handler};
    httpd_uri_t app = {.uri = "/api/app", .method = HTTP_ANY, .handler = app_handler};
    httpd_uri_t run = {.uri = "/api/run", .method = HTTP_POST, .handler = run_handler};
    httpd_uri_t stop = {.uri = "/api/stop", .method = HTTP_POST, .handler = stop_handler};
    httpd_uri_t status = {.uri = "/api/status", .method = HTTP_GET, .handler = status_handler};

    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &root));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &css));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &js));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &worker));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &wasm));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &provision_html));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &provision_css));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &provision_js));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &wifi_provision));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &auth_info));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &setup_challenge));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &setup));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &challenge));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &login));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &me));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &logout));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &password_info));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &change_password));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &apps));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &app));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &run));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &stop));
    ESP_ERROR_CHECK(httpd_register_uri_handler(s_server, &status));

    ESP_LOGI(TAG, "Web UI started on port %d", CONFIG_APP_HTTP_PORT);
    return ESP_OK;
}
