#include "wifi.h"

#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_system.h"
#include "nvs.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

static const char *TAG = "wifi";

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
#define WIFI_STA_RETRIES 8
#define WIFI_STA_TIMEOUT_MS 15000
#define WIFI_MAX_SSID_LEN 32
#define WIFI_MAX_PASSWORD_LEN 63
#define WIFI_AP_SSID_MAX_LEN 32
#define WIFI_AP_PASSWORD_LEN 12
#define WIFI_PROV_NVS_NAMESPACE "wifi_prov"
#define WIFI_PROV_NVS_AP_PASSWORD "ap_pass"

static EventGroupHandle_t s_wifi_event_group;
static esp_event_handler_instance_t s_any_id;
static esp_event_handler_instance_t s_got_ip;
static bool s_provisioning;
static int s_retry;
static bool s_wifi_started;
static char s_ap_ssid[WIFI_AP_SSID_MAX_LEN + 1];
static char s_ap_password[WIFI_AP_PASSWORD_LEN + 1];

static bool valid_ssid(const char *ssid) {
    return ssid && strlen(ssid) > 0 && strlen(ssid) <= WIFI_MAX_SSID_LEN;
}

static bool valid_password(const char *password) {
    if (!password) return false;
    size_t len = strlen(password);
    // Empty means an open target network. Otherwise WPA-Personal passwords
    // are limited to 8..63 bytes by the Wi-Fi driver.
    return len == 0 || (len >= 8 && len <= WIFI_MAX_PASSWORD_LEN);
}

static void handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    (void)arg;

    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        if (!s_provisioning) esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_provisioning) return;
        if (s_retry < WIFI_STA_RETRIES) {
            ++s_retry;
            ESP_LOGW(TAG, "Wi-Fi disconnected; retry %d/%d", s_retry, WIFI_STA_RETRIES);
            esp_wifi_connect();
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *event = (const ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static esp_err_t ensure_ap_credentials(void) {
    uint8_t mac[6] = {0};
    esp_err_t err = esp_wifi_get_mac(WIFI_IF_STA, mac);
    if (err != ESP_OK) return err;

    int n = snprintf(s_ap_ssid, sizeof(s_ap_ssid), "ESP-JS-OS-%02X%02X%02X", mac[3], mac[4], mac[5]);
    if (n < 0 || (size_t)n >= sizeof(s_ap_ssid)) return ESP_ERR_INVALID_SIZE;

    nvs_handle_t nvs = 0;
    err = nvs_open(WIFI_PROV_NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;

    size_t pass_len = sizeof(s_ap_password);
    err = nvs_get_str(nvs, WIFI_PROV_NVS_AP_PASSWORD, s_ap_password, &pass_len);
    if (err == ESP_OK && pass_len == WIFI_AP_PASSWORD_LEN + 1) {
        nvs_close(nvs);
        return ESP_OK;
    }

    if (err != ESP_ERR_NVS_NOT_FOUND && err != ESP_OK) {
        nvs_close(nvs);
        return err;
    }

    // Generate a unique per-device setup password once and keep it in NVS.
    // It is deliberately independent of the user's home Wi-Fi password.
    uint8_t random_bytes[6];
    esp_fill_random(random_bytes, sizeof(random_bytes));
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < sizeof(random_bytes); ++i) {
        s_ap_password[i * 2] = hex[random_bytes[i] >> 4];
        s_ap_password[i * 2 + 1] = hex[random_bytes[i] & 0x0F];
    }
    s_ap_password[WIFI_AP_PASSWORD_LEN] = '\0';

    err = nvs_set_str(nvs, WIFI_PROV_NVS_AP_PASSWORD, s_ap_password);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

static esp_err_t start_provisioning_ap(void) {
    esp_err_t err = ensure_ap_credentials();
    if (err != ESP_OK) return err;

    s_provisioning = true;
    s_retry = 0;
    xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);

    wifi_config_t ap_config = {0};
    memcpy(ap_config.ap.ssid, s_ap_ssid, strlen(s_ap_ssid));
    ap_config.ap.ssid_len = strlen(s_ap_ssid);
    memcpy(ap_config.ap.password, s_ap_password, strlen(s_ap_password));
    ap_config.ap.channel = 1;
    ap_config.ap.max_connection = 4;
    ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    ap_config.ap.pmf_cfg.required = false;
    ap_config.ap.pmf_cfg.capable = true;

    // If STA Wi-Fi was already running, stop it completely before switching
    // into provisioning mode. This cancels any in-flight connection attempt
    // before the AP+STA interface is started. On first boot the driver has
    // not been started yet, so there is no station state to tear down.
    if (s_wifi_started) {
        ESP_ERROR_CHECK(esp_wifi_stop());
        s_wifi_started = false;
    }

    // Keep both interfaces enabled while provisioning so the saved STA
    // configuration can be replaced with esp_wifi_set_config(WIFI_IF_STA,...)
    // and the setup portal can run on the AP interface.
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    s_wifi_started = true;

    ESP_LOGW(TAG, "Wi-Fi provisioning mode enabled");
    ESP_LOGW(TAG, "Connect to SSID: %s", s_ap_ssid);
    ESP_LOGW(TAG, "Provisioning AP password: %s", s_ap_password);
    ESP_LOGW(TAG, "Open http://192.168.4.1/ to configure Wi-Fi");
    return ESP_ERR_INVALID_STATE;
}

static void restart_task(void *arg) {
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
    vTaskDelete(NULL);
}

esp_err_t wifi_init_sta(void) {
    if (!s_wifi_event_group) {
        s_wifi_event_group = xEventGroupCreate();
        if (!s_wifi_event_group) return ESP_ERR_NO_MEM;
    }

    s_provisioning = false;
    s_retry = 0;

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    if (!esp_netif_create_default_wifi_sta()) return ESP_ERR_NO_MEM;
    if (!esp_netif_create_default_wifi_ap()) return ESP_ERR_NO_MEM;

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_FLASH));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &handler, NULL, &s_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &handler, NULL, &s_got_ip));

    wifi_config_t wifi_config = {0};
    ESP_ERROR_CHECK(esp_wifi_get_config(WIFI_IF_STA, &wifi_config));

    if (wifi_config.sta.ssid[0] == '\0') {
        return start_provisioning_ap();
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    s_wifi_started = true;

    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE,
        pdFALSE,
        pdMS_TO_TICKS(WIFI_STA_TIMEOUT_MS));

    if (bits & WIFI_CONNECTED_BIT) {
        return ESP_OK;
    }

    ESP_LOGW(TAG, "Saved Wi-Fi network could not be reached; falling back to provisioning");
    return start_provisioning_ap();
}

bool wifi_is_provisioning(void) {
    return s_provisioning;
}

esp_err_t wifi_provision_credentials(const char *ssid, const char *password) {
    if (!s_provisioning || !valid_ssid(ssid) || !valid_password(password)) {
        return ESP_ERR_INVALID_ARG;
    }

    wifi_config_t sta_config = {0};
    memcpy(sta_config.sta.ssid, ssid, strlen(ssid));
    memcpy(sta_config.sta.password, password, strlen(password));
    sta_config.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    sta_config.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    sta_config.sta.threshold.authmode = strlen(password) == 0 ? WIFI_AUTH_OPEN : WIFI_AUTH_WPA2_PSK;
    sta_config.sta.pmf_cfg.capable = true;
    sta_config.sta.pmf_cfg.required = false;

    // With CONFIG_ESP_WIFI_NVS_ENABLED=y, esp_wifi_set_config persists this
    // STA configuration in the standard ESP-IDF Wi-Fi NVS storage.
    esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Could not save Wi-Fi configuration: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "Wi-Fi credentials saved for SSID '%s'; rebooting", ssid);
    BaseType_t ok = xTaskCreate(restart_task, "wifi_reboot", 2048, NULL, 2, NULL);
    return ok == pdPASS ? ESP_OK : ESP_ERR_NO_MEM;
}
