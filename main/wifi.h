#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

// Returns ESP_OK when the saved STA configuration connected successfully.
// When provisioning is needed, this starts the protected setup SoftAP and
// returns ESP_ERR_INVALID_STATE. Callers should keep the HTTP server alive.
esp_err_t wifi_init_sta(void);

bool wifi_is_provisioning(void);

// Save new STA credentials into the ESP-IDF Wi-Fi NVS configuration.
// A reboot is scheduled after a successful save.
esp_err_t wifi_provision_credentials(const char *ssid, const char *password);
