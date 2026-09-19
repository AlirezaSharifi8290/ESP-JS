#include "esp_log.h"
#include "nvs_flash.h"

#include "auth.h"
#include "runner.h"
#include "storage.h"
#include "web.h"
#include "wifi.h"

static const char *TAG = "esp-js-os";

static void print_setup_code(void) { auth_log_setup_code(); }

void app_main(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    } else {
        ESP_ERROR_CHECK(err);
    }

    ESP_ERROR_CHECK(storage_init());
    ESP_ERROR_CHECK(auth_init());
    ESP_ERROR_CHECK(runner_init());

    err = wifi_init_sta();
    if (err != ESP_OK && !wifi_is_provisioning()) {
        ESP_LOGE(TAG, "Wi-Fi initialization failed: %s", esp_err_to_name(err));
        return;
    }

    ESP_ERROR_CHECK(auth_crypto_init());
    if (!auth_is_configured()) print_setup_code();

    ESP_ERROR_CHECK(web_start());
    if (wifi_is_provisioning()) {
        ESP_LOGI(TAG, "Provisioning portal ready at http://192.168.4.1/");
    } else {
        ESP_LOGI(TAG, "ESP-JS OS ready. Open the assigned IP shown above in a browser.");
    }
}
