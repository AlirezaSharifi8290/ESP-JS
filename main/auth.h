#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_http_server.h"

#define AUTH_HEX_32_LEN 64
#define AUTH_HEX_16_LEN 32
#define AUTH_PASSWORD_MIN 8
#define AUTH_PASSWORD_MAX 128
#define AUTH_PBKDF2_ITERATIONS 600000U

esp_err_t auth_init(void);
esp_err_t auth_crypto_init(void);
bool auth_is_configured(void);
void auth_log_setup_code(void);

esp_err_t auth_get_info_json(char *out, size_t out_len);
esp_err_t auth_get_challenge_json(char *out, size_t out_len, bool setup_challenge);
esp_err_t auth_get_password_info_json(httpd_req_t *req, char *out, size_t out_len);

esp_err_t auth_setup(const uint8_t proof[32], const uint8_t verifier[32], char session_hex[AUTH_HEX_32_LEN + 1]);
esp_err_t auth_login(const uint8_t proof[32], char session_hex[AUTH_HEX_32_LEN + 1]);
esp_err_t auth_logout(httpd_req_t *req);
esp_err_t auth_get_me_json(httpd_req_t *req, char *out, size_t out_len);
esp_err_t auth_change_password(httpd_req_t *req, const uint8_t salt[16], const uint8_t verifier[32]);

bool auth_request_authenticated(httpd_req_t *req);
esp_err_t auth_set_session_cookie(httpd_req_t *req, const char session_hex[AUTH_HEX_32_LEN + 1], char *cookie_header, size_t cookie_header_len);
esp_err_t auth_clear_session_cookie(httpd_req_t *req);
