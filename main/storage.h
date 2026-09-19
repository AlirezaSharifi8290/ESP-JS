#pragma once
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

#define APP_NAME_MAX 32
#define APP_PATH_MAX 512

esp_err_t storage_init(void);
bool storage_valid_name(const char *name);
esp_err_t storage_list_apps(char *out, size_t out_len);
esp_err_t storage_read_code(const char *name, char **out_code, size_t *out_len);
esp_err_t storage_write_code(const char *name, const char *code, size_t len);
esp_err_t storage_delete_app(const char *name);
esp_err_t storage_app_exists(const char *name, bool *exists);
