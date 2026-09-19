#include "auth.h"

#include <stdio.h>
#include <string.h>

#include "esp_check.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "psa/crypto.h"

static const char *TAG = "auth";

#define AUTH_NAMESPACE "auth"
#define KEY_SALT "salt"
#define KEY_VERIFIER "verifier"
#define KEY_ITER "iter"
#define KEY_SETUP "setup"
#define KEY_SETUP_SALT "setup_salt"

#define AUTH_CHALLENGE_TTL_MS 60000ULL
#define AUTH_SESSION_IDLE_MS (12ULL * 60ULL * 60ULL * 1000ULL)
#define AUTH_LOGIN_LOCKOUT_MS 30000ULL
#define AUTH_MAX_FAILED_LOGINS 5U
#define AUTH_CHALLENGE_COOLDOWN_MS 1000ULL
#define AUTH_MAX_SESSIONS 4U
#define AUTH_MAX_ITERATIONS 2000000U
#define AUTH_COOKIE_MAX 512

typedef struct {
    bool in_use;
    uint8_t token[32];
    uint64_t last_seen_ms;
} auth_session_t;

static SemaphoreHandle_t s_lock;
static bool s_crypto_ready;
static bool s_configured;
static uint8_t s_salt[16];
static uint8_t s_verifier[32];
static uint32_t s_iterations = AUTH_PBKDF2_ITERATIONS;
static uint8_t s_setup_secret[32];
static uint8_t s_setup_salt[16];
static bool s_setup_available;

static uint8_t s_challenge[32];
static uint64_t s_challenge_time_ms;
static uint64_t s_last_challenge_ms;
static bool s_challenge_valid;
static bool s_challenge_is_setup;

static uint32_t s_failed_logins;
static uint64_t s_lockout_until_ms;
static auth_session_t s_sessions[AUTH_MAX_SESSIONS];

static uint64_t now_ms(void) {
    return (uint64_t)(esp_timer_get_time() / 1000ULL);
}

static void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

static void hex_encode(const uint8_t *src, size_t len, char *dst, size_t dst_len) {
    static const char hex[] = "0123456789abcdef";
    if (dst_len < len * 2 + 1) {
        if (dst_len) dst[0] = '\0';
        return;
    }
    for (size_t i = 0; i < len; ++i) {
        dst[i * 2] = hex[src[i] >> 4];
        dst[i * 2 + 1] = hex[src[i] & 0x0f];
    }
    dst[len * 2] = '\0';
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool hex_decode_exact(const char *src, size_t chars, uint8_t *dst, size_t dst_len) {
    if (!src || !dst || dst_len * 2 != chars) return false;
    for (size_t i = 0; i < dst_len; ++i) {
        int hi = hex_value(src[i * 2]);
        int lo = hex_value(src[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        dst[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static bool constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

static esp_err_t hmac_sha256(const uint8_t *key, size_t key_len,
                             const uint8_t *msg, size_t msg_len,
                             uint8_t out[32]) {
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    size_t out_len = 0;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attr, (psa_key_bits_t)(key_len * 8U));

    psa_status_t st = psa_import_key(&attr, key, key_len, &key_id);
    if (st == PSA_SUCCESS) {
        st = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                             msg, msg_len, out, 32, &out_len);
        psa_destroy_key(key_id);
    }
    psa_reset_key_attributes(&attr);
    return (st == PSA_SUCCESS && out_len == 32) ? ESP_OK : ESP_FAIL;
}

static esp_err_t random_bytes(uint8_t *dst, size_t len) {
    if (!s_crypto_ready) return ESP_ERR_INVALID_STATE;
    esp_fill_random(dst, len);
    return ESP_OK;
}

static esp_err_t load_nvs(void) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(AUTH_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;

    size_t salt_len = sizeof(s_salt);
    size_t verifier_len = sizeof(s_verifier);
    uint32_t iterations = AUTH_PBKDF2_ITERATIONS;
    err = nvs_get_blob(nvs, KEY_SALT, s_salt, &salt_len);
    if (err == ESP_OK) err = nvs_get_blob(nvs, KEY_VERIFIER, s_verifier, &verifier_len);
    if (err == ESP_OK) {
        err = nvs_get_u32(nvs, KEY_ITER, &iterations);
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            err = ESP_OK;
            iterations = AUTH_PBKDF2_ITERATIONS;
        }
    }

    if (err == ESP_OK && salt_len == sizeof(s_salt) && verifier_len == sizeof(s_verifier) &&
        iterations >= 100000U && iterations <= AUTH_MAX_ITERATIONS) {
        s_iterations = iterations;
        s_configured = true;
    } else if (err == ESP_ERR_NVS_NOT_FOUND || err == ESP_OK) {
        s_configured = false;
        secure_zero(s_salt, sizeof(s_salt));
        secure_zero(s_verifier, sizeof(s_verifier));
        s_iterations = AUTH_PBKDF2_ITERATIONS;
    } else {
        nvs_close(nvs);
        return err;
    }

    size_t setup_len = sizeof(s_setup_secret);
    size_t setup_salt_len = sizeof(s_setup_salt);
    esp_err_t setup_err = nvs_get_blob(nvs, KEY_SETUP, s_setup_secret, &setup_len);
    esp_err_t setup_salt_err = nvs_get_blob(nvs, KEY_SETUP_SALT, s_setup_salt, &setup_salt_len);
    s_setup_available = !s_configured && setup_err == ESP_OK && setup_salt_err == ESP_OK &&
                        setup_len == sizeof(s_setup_secret) && setup_salt_len == sizeof(s_setup_salt);

    nvs_close(nvs);
    return ESP_OK;
}

static esp_err_t save_credentials(const uint8_t salt[16], const uint8_t verifier[32], uint32_t iterations) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(AUTH_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(nvs, KEY_SALT, salt, 16);
    if (err == ESP_OK) err = nvs_set_blob(nvs, KEY_VERIFIER, verifier, 32);
    if (err == ESP_OK) err = nvs_set_u32(nvs, KEY_ITER, iterations);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

static void erase_setup_material(void) {
    nvs_handle_t nvs;
    if (nvs_open(AUTH_NAMESPACE, NVS_READWRITE, &nvs) != ESP_OK) return;
    nvs_erase_key(nvs, KEY_SETUP);
    nvs_erase_key(nvs, KEY_SETUP_SALT);
    nvs_commit(nvs);
    nvs_close(nvs);
    secure_zero(s_setup_secret, sizeof(s_setup_secret));
    secure_zero(s_setup_salt, sizeof(s_setup_salt));
    s_setup_available = false;
}

static void invalidate_all_sessions_locked(void) {
    for (size_t i = 0; i < AUTH_MAX_SESSIONS; ++i) {
        secure_zero(s_sessions[i].token, sizeof(s_sessions[i].token));
        s_sessions[i].in_use = false;
        s_sessions[i].last_seen_ms = 0;
    }
}

static void invalidate_other_sessions_locked(const uint8_t keep[32]) {
    for (size_t i = 0; i < AUTH_MAX_SESSIONS; ++i) {
        if (s_sessions[i].in_use && !constant_time_equal(s_sessions[i].token, keep, 32)) {
            secure_zero(s_sessions[i].token, sizeof(s_sessions[i].token));
            s_sessions[i].in_use = false;
            s_sessions[i].last_seen_ms = 0;
        }
    }
}

static bool parse_session_cookie(httpd_req_t *req, uint8_t token[32]) {
    size_t len = httpd_req_get_hdr_value_len(req, "Cookie");
    if (len == 0 || len >= AUTH_COOKIE_MAX) return false;
    char cookie[AUTH_COOKIE_MAX];
    if (httpd_req_get_hdr_value_str(req, "Cookie", cookie, sizeof(cookie)) != ESP_OK) return false;

    const char *p = cookie;
    const char *found = NULL;
    while (*p) {
        while (*p == ' ' || *p == ';') ++p;
        if (strncmp(p, "ESPJSession=", 12) == 0) {
            found = p + 12;
            break;
        }
        const char *semi = strchr(p, ';');
        if (!semi) break;
        p = semi + 1;
    }
    if (!found) return false;
    const char *end = strchr(found, ';');
    size_t value_len = end ? (size_t)(end - found) : strlen(found);
    return hex_decode_exact(found, value_len, token, 32);
}

static bool session_valid_locked(const uint8_t token[32], bool refresh) {
    uint64_t now = now_ms();
    for (size_t i = 0; i < AUTH_MAX_SESSIONS; ++i) {
        if (!s_sessions[i].in_use) continue;
        if (now - s_sessions[i].last_seen_ms > AUTH_SESSION_IDLE_MS) {
            secure_zero(s_sessions[i].token, sizeof(s_sessions[i].token));
            s_sessions[i].in_use = false;
            continue;
        }
        if (constant_time_equal(s_sessions[i].token, token, 32)) {
            if (refresh) s_sessions[i].last_seen_ms = now;
            return true;
        }
    }
    return false;
}

static esp_err_t create_session(char out_hex[AUTH_HEX_32_LEN + 1]) {
    uint8_t token[32];
    ESP_RETURN_ON_ERROR(random_bytes(token, sizeof(token)), TAG, "session RNG failed");

    xSemaphoreTake(s_lock, portMAX_DELAY);
    size_t slot = AUTH_MAX_SESSIONS;
    uint64_t oldest = UINT64_MAX;
    size_t oldest_slot = 0;
    uint64_t now = now_ms();
    for (size_t i = 0; i < AUTH_MAX_SESSIONS; ++i) {
        if (!s_sessions[i].in_use) { slot = i; break; }
        if (now - s_sessions[i].last_seen_ms > AUTH_SESSION_IDLE_MS) { slot = i; break; }
        if (s_sessions[i].last_seen_ms < oldest) { oldest = s_sessions[i].last_seen_ms; oldest_slot = i; }
    }
    if (slot == AUTH_MAX_SESSIONS) slot = oldest_slot;
    secure_zero(s_sessions[slot].token, sizeof(s_sessions[slot].token));
    memcpy(s_sessions[slot].token, token, sizeof(token));
    s_sessions[slot].in_use = true;
    s_sessions[slot].last_seen_ms = now;
    xSemaphoreGive(s_lock);

    hex_encode(token, sizeof(token), out_hex, AUTH_HEX_32_LEN + 1);
    secure_zero(token, sizeof(token));
    return ESP_OK;
}

esp_err_t auth_init(void) {
    s_lock = xSemaphoreCreateMutex();
    if (!s_lock) return ESP_ERR_NO_MEM;
    s_crypto_ready = false;
    s_configured = false;
    s_setup_available = false;
    s_challenge_valid = false;
    s_failed_logins = 0;
    s_lockout_until_ms = 0;
    memset(s_sessions, 0, sizeof(s_sessions));
    return load_nvs();
}

esp_err_t auth_crypto_init(void) {
    if (!s_lock) return ESP_ERR_INVALID_STATE;
    psa_status_t st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_crypto_init failed: %ld", (long)st);
        return ESP_FAIL;
    }
    s_crypto_ready = true;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool need_setup = !s_configured && !s_setup_available;
    xSemaphoreGive(s_lock);

    if (!need_setup) return ESP_OK;

    uint8_t secret[32] = {0};
    uint8_t salt[16] = {0};
    nvs_handle_t nvs = 0;
    esp_err_t err = random_bytes(secret, sizeof(secret));
    if (err == ESP_OK) err = random_bytes(salt, sizeof(salt));
    if (err == ESP_OK) err = nvs_open(AUTH_NAMESPACE, NVS_READWRITE, &nvs);
    if (err == ESP_OK) err = nvs_set_blob(nvs, KEY_SETUP, secret, sizeof(secret));
    if (err == ESP_OK) err = nvs_set_blob(nvs, KEY_SETUP_SALT, salt, sizeof(salt));
    if (err == ESP_OK) err = nvs_commit(nvs);
    if (nvs) nvs_close(nvs);
    if (err != ESP_OK) {
        secure_zero(secret, sizeof(secret));
        secure_zero(salt, sizeof(salt));
        return err;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    memcpy(s_setup_secret, secret, sizeof(secret));
    memcpy(s_setup_salt, salt, sizeof(salt));
    s_setup_available = true;
    xSemaphoreGive(s_lock);
    secure_zero(secret, sizeof(secret));
    secure_zero(salt, sizeof(salt));
    return ESP_OK;
}

bool auth_is_configured(void) {
    return s_configured;
}

void auth_log_setup_code(void) {
    char code[AUTH_HEX_32_LEN + 1] = {0};
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool available = !s_configured && s_setup_available;
    if (available) hex_encode(s_setup_secret, sizeof(s_setup_secret), code, sizeof(code));
    xSemaphoreGive(s_lock);
    if (available) {
        ESP_LOGW(TAG, "FIRST-BOOT SETUP CODE: %s", code);
        ESP_LOGW(TAG, "This code is displayed once for device setup; keep it private.");
    }
    secure_zero(code, sizeof(code));
}

esp_err_t auth_get_info_json(char *out, size_t out_len) {
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool configured = s_configured;
    uint32_t iterations = s_iterations;
    uint8_t salt[16];
    memcpy(salt, configured ? s_salt : s_setup_salt, sizeof(salt));
    bool setup_available = s_setup_available;
    xSemaphoreGive(s_lock);

    char salt_hex[AUTH_HEX_16_LEN + 1];
    hex_encode(salt, sizeof(salt), salt_hex, sizeof(salt_hex));
    secure_zero(salt, sizeof(salt));

    if (!configured && setup_available) {
        int n = snprintf(out, out_len, "{\"configured\":false,\"iterations\":%u,\"setupSalt\":\"%s\"}",
                         (unsigned)iterations, salt_hex);
        return (n >= 0 && (size_t)n < out_len) ? ESP_OK : ESP_ERR_INVALID_SIZE;
    }
    if (configured) {
        int n = snprintf(out, out_len, "{\"configured\":true,\"iterations\":%u,\"salt\":\"%s\"}",
                         (unsigned)iterations, salt_hex);
        return (n >= 0 && (size_t)n < out_len) ? ESP_OK : ESP_ERR_INVALID_SIZE;
    }
    int n = snprintf(out, out_len, "{\"configured\":false,\"iterations\":%u}",
                     (unsigned)iterations);
    return (n >= 0 && (size_t)n < out_len) ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

esp_err_t auth_get_challenge_json(char *out, size_t out_len, bool setup_challenge) {
    if (!s_crypto_ready) return ESP_ERR_INVALID_STATE;
    uint64_t now = now_ms();

    xSemaphoreTake(s_lock, portMAX_DELAY);
    if ((s_configured != (!setup_challenge)) || ((!s_setup_available) && setup_challenge)) {
        xSemaphoreGive(s_lock);
        return ESP_ERR_INVALID_STATE;
    }
    if (now - s_last_challenge_ms < AUTH_CHALLENGE_COOLDOWN_MS) {
        xSemaphoreGive(s_lock);
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t challenge[32];
    esp_err_t err = random_bytes(challenge, sizeof(challenge));
    uint32_t iterations = s_iterations;
    if (err == ESP_OK) {
        memcpy(s_challenge, challenge, sizeof(challenge));
        s_challenge_time_ms = now;
        s_last_challenge_ms = now;
        s_challenge_valid = true;
        s_challenge_is_setup = setup_challenge;
    }
    xSemaphoreGive(s_lock);
    if (err != ESP_OK) return err;

    char challenge_hex[AUTH_HEX_32_LEN + 1];
    hex_encode(challenge, sizeof(challenge), challenge_hex, sizeof(challenge_hex));
    secure_zero(challenge, sizeof(challenge));
    int n = snprintf(out, out_len, "{\"challenge\":\"%s\",\"iterations\":%u}",
                     challenge_hex, (unsigned)iterations);
    return (n >= 0 && (size_t)n < out_len) ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

static esp_err_t consume_proof(const uint8_t proof[32], bool setup_challenge) {
    uint8_t key[32];
    uint8_t challenge[32];
    uint64_t issued;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (!s_challenge_valid || s_challenge_is_setup != setup_challenge ||
        now_ms() - s_challenge_time_ms > AUTH_CHALLENGE_TTL_MS) {
        xSemaphoreGive(s_lock);
        return ESP_ERR_TIMEOUT;
    }
    memcpy(challenge, s_challenge, sizeof(challenge));
    issued = s_challenge_time_ms;
    if (setup_challenge) memcpy(key, s_setup_secret, sizeof(key));
    else memcpy(key, s_verifier, sizeof(key));
    xSemaphoreGive(s_lock);

    (void)issued;
    uint8_t expected[32];
    esp_err_t err = hmac_sha256(key, sizeof(key), challenge, sizeof(challenge), expected);
    secure_zero(key, sizeof(key));
    if (err != ESP_OK) { secure_zero(challenge, sizeof(challenge)); return err; }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool same_challenge = s_challenge_valid &&
                          s_challenge_is_setup == setup_challenge &&
                          constant_time_equal(s_challenge, challenge, sizeof(challenge));
    bool valid = same_challenge && constant_time_equal(expected, proof, 32) &&
                 now_ms() - s_challenge_time_ms <= AUTH_CHALLENGE_TTL_MS;
    if (same_challenge) s_challenge_valid = false;
    if (!setup_challenge && valid) {
        s_failed_logins = 0;
    }
    xSemaphoreGive(s_lock);
    secure_zero(challenge, sizeof(challenge));
    secure_zero(expected, sizeof(expected));
    return valid ? ESP_OK : ESP_ERR_INVALID_CRC;
}

esp_err_t auth_setup(const uint8_t proof[32], const uint8_t verifier[32], char session_hex[AUTH_HEX_32_LEN + 1]) {
    if (!proof || !verifier || !session_hex) return ESP_ERR_INVALID_ARG;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (s_configured || !s_setup_available) { xSemaphoreGive(s_lock); return ESP_ERR_INVALID_STATE; }
    xSemaphoreGive(s_lock);

    esp_err_t err = consume_proof(proof, true);
    if (err != ESP_OK) return err;

    uint8_t salt[16];
    xSemaphoreTake(s_lock, portMAX_DELAY);
    memcpy(salt, s_setup_salt, sizeof(salt));
    xSemaphoreGive(s_lock);

    err = save_credentials(salt, verifier, AUTH_PBKDF2_ITERATIONS);
    secure_zero(salt, sizeof(salt));
    if (err != ESP_OK) return err;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    memcpy(s_salt, s_setup_salt, sizeof(s_salt));
    memcpy(s_verifier, verifier, sizeof(s_verifier));
    s_iterations = AUTH_PBKDF2_ITERATIONS;
    s_configured = true;
    s_failed_logins = 0;
    s_lockout_until_ms = 0;
    invalidate_all_sessions_locked();
    xSemaphoreGive(s_lock);

    erase_setup_material();
    return create_session(session_hex);
}

esp_err_t auth_login(const uint8_t proof[32], char session_hex[AUTH_HEX_32_LEN + 1]) {
    if (!proof || !session_hex) return ESP_ERR_INVALID_ARG;
    uint64_t now = now_ms();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (!s_configured) { xSemaphoreGive(s_lock); return ESP_ERR_INVALID_STATE; }
    if (now < s_lockout_until_ms) { xSemaphoreGive(s_lock); return ESP_ERR_NOT_ALLOWED; }
    xSemaphoreGive(s_lock);

    esp_err_t err = consume_proof(proof, false);
    if (err == ESP_OK) return create_session(session_hex);
    if (err == ESP_ERR_TIMEOUT) return err;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_failed_logins++;
    if (s_failed_logins >= AUTH_MAX_FAILED_LOGINS) {
        s_failed_logins = 0;
        s_lockout_until_ms = now_ms() + AUTH_LOGIN_LOCKOUT_MS;
    }
    xSemaphoreGive(s_lock);
    return ESP_ERR_INVALID_CRC;
}

static bool get_authenticated_token(httpd_req_t *req, uint8_t token[32]) {
    if (!parse_session_cookie(req, token)) return false;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool valid = session_valid_locked(token, true);
    xSemaphoreGive(s_lock);
    return valid;
}

bool auth_request_authenticated(httpd_req_t *req) {
    uint8_t token[32];
    bool ok = get_authenticated_token(req, token);
    secure_zero(token, sizeof(token));
    return ok;
}

esp_err_t auth_logout(httpd_req_t *req) {
    uint8_t token[32];
    if (parse_session_cookie(req, token)) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
        for (size_t i = 0; i < AUTH_MAX_SESSIONS; ++i) {
            if (s_sessions[i].in_use && constant_time_equal(s_sessions[i].token, token, 32)) {
                secure_zero(s_sessions[i].token, sizeof(s_sessions[i].token));
                s_sessions[i].in_use = false;
                s_sessions[i].last_seen_ms = 0;
                break;
            }
        }
        xSemaphoreGive(s_lock);
        secure_zero(token, sizeof(token));
    }
    return ESP_OK;
}

esp_err_t auth_get_me_json(httpd_req_t *req, char *out, size_t out_len) {
    return auth_request_authenticated(req) ?
           ((snprintf(out, out_len, "{\"authenticated\":true}") < (int)out_len) ? ESP_OK : ESP_ERR_INVALID_SIZE) :
           ESP_ERR_NOT_FOUND;
}

esp_err_t auth_get_password_info_json(httpd_req_t *req, char *out, size_t out_len) {
    if (!auth_request_authenticated(req)) return ESP_ERR_NOT_FOUND;
    uint8_t salt[16];
    esp_err_t err = random_bytes(salt, sizeof(salt));
    if (err != ESP_OK) return err;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint32_t iterations = s_iterations;
    xSemaphoreGive(s_lock);
    char salt_hex[AUTH_HEX_16_LEN + 1];
    hex_encode(salt, sizeof(salt), salt_hex, sizeof(salt_hex));
    secure_zero(salt, sizeof(salt));
    int n = snprintf(out, out_len, "{\"salt\":\"%s\",\"iterations\":%u}",
                     salt_hex, (unsigned)iterations);
    return (n >= 0 && (size_t)n < out_len) ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

esp_err_t auth_change_password(httpd_req_t *req, const uint8_t salt[16], const uint8_t verifier[32]) {
    if (!salt || !verifier) return ESP_ERR_INVALID_ARG;
    uint8_t current[32];
    if (!get_authenticated_token(req, current)) return ESP_ERR_NOT_FOUND;
    secure_zero(current, sizeof(current));

    esp_err_t err = save_credentials(salt, verifier, s_iterations);
    if (err != ESP_OK) return err;

    uint8_t keep[32];
    if (!parse_session_cookie(req, keep)) return ESP_ERR_NOT_FOUND;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    memcpy(s_salt, salt, sizeof(s_salt));
    memcpy(s_verifier, verifier, sizeof(s_verifier));
    invalidate_other_sessions_locked(keep);
    xSemaphoreGive(s_lock);
    secure_zero(keep, sizeof(keep));
    return ESP_OK;
}

esp_err_t auth_set_session_cookie(httpd_req_t *req, const char session_hex[AUTH_HEX_32_LEN + 1], char *cookie_header, size_t cookie_header_len) {
    if (!req || !session_hex || !cookie_header || cookie_header_len == 0) return ESP_ERR_INVALID_ARG;
    int n = snprintf(cookie_header, cookie_header_len,
                     "ESPJSession=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200",
                     session_hex);
    if (n < 0 || (size_t)n >= cookie_header_len) return ESP_ERR_INVALID_SIZE;
    return httpd_resp_set_hdr(req, "Set-Cookie", cookie_header);
}

esp_err_t auth_clear_session_cookie(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Set-Cookie", "ESPJSession=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    return ESP_OK;
}
