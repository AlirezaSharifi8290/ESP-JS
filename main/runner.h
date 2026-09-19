#pragma once
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

esp_err_t runner_init(void);
esp_err_t runner_start(const char *name);
esp_err_t runner_request_stop(void);
bool runner_is_running(void);
bool runner_stop_requested(void);
bool runner_is_app_running(const char *name);
const char *runner_current_app(void);
const char *runner_last_error(void);
void runner_status_json(char *out, size_t out_len);
