#include "runner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "driver/gpio.h"
#include "elk.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "storage.h"

static const char *TAG = "runner";
#define APP_TASK_STACK CONFIG_APP_RUNNER_STACK
#define APP_TASK_PRIORITY 4
#define APP_LOG_MAX 160

static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static TaskHandle_t s_task = NULL;
static volatile bool s_running = false;
static volatile bool s_stop_requested = false;
static char s_current[APP_NAME_MAX + 1] = {0};
static char s_error[APP_LOG_MAX] = "";

static bool valid_gpio(int pin) {
    return pin >= 0 && pin <= 39;
}

static bool valid_output_gpio(int pin) {
    if (!valid_gpio(pin)) return false;
    if (pin >= 34) return false;
    // Classic ESP32 flash-connected GPIOs. Avoid these in apps.
    if (pin >= 6 && pin <= 11) return false;
    return true;
}

static jsval_t js_print(struct js *js, jsval_t *args, int nargs) {
    if (nargs != 1) return js_mkerr(js, "print(message) expected");
    const char *s = js_str(js, args[0]);
    ESP_LOGI(TAG, "[APP] %s", s ? s : "<null>");
    return js_mkundef();
}

static jsval_t js_gpio_mode(struct js *js, jsval_t *args, int nargs) {
    if (!js_chkargs(args, nargs, "ds")) return js_mkerr(js, "gpio_mode(pin, mode) expected");
    int pin = (int) js_getnum(args[0]);
    size_t mode_len = 0;
    char *mode = js_getstr(js, args[1], &mode_len);
    if (!mode || pin < 0 || pin > 39) return js_mkerr(js, "invalid gpio");

    gpio_config_t cfg = {0};
    cfg.pin_bit_mask = 1ULL << pin;
    cfg.pull_up_en = GPIO_PULLUP_DISABLE;
    cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    cfg.intr_type = GPIO_INTR_DISABLE;

    if (mode_len == 6 && memcmp(mode, "output", 6) == 0) {
        if (!valid_output_gpio(pin)) return js_mkerr(js, "gpio not safe for output");
        cfg.mode = GPIO_MODE_OUTPUT;
    } else if (mode_len == 5 && memcmp(mode, "input", 5) == 0) {
        cfg.mode = GPIO_MODE_INPUT;
    } else if (mode_len == 11 && memcmp(mode, "input_pullup", 11) == 0) {
        cfg.mode = GPIO_MODE_INPUT;
        cfg.pull_up_en = GPIO_PULLUP_ENABLE;
    } else if (mode_len == 13 && memcmp(mode, "input_pulldown", 13) == 0) {
        cfg.mode = GPIO_MODE_INPUT;
        cfg.pull_down_en = GPIO_PULLDOWN_ENABLE;
    } else {
        return js_mkerr(js, "unknown gpio mode");
    }

    esp_err_t err = gpio_config(&cfg);
    return err == ESP_OK ? js_mktrue() : js_mkerr(js, "gpio config failed");
}

static jsval_t js_gpio_write(struct js *js, jsval_t *args, int nargs) {
    if (!js_chkargs(args, nargs, "db")) return js_mkerr(js, "gpio_write(pin, level) expected");
    int pin = (int) js_getnum(args[0]);
    if (!valid_output_gpio(pin)) return js_mkerr(js, "gpio not safe for output");
    esp_err_t err = gpio_set_level((gpio_num_t) pin, js_getbool(args[1]) ? 1 : 0);
    return err == ESP_OK ? js_mktrue() : js_mkerr(js, "gpio write failed");
}

static jsval_t js_gpio_read(struct js *js, jsval_t *args, int nargs) {
    if (!js_chkargs(args, nargs, "d")) return js_mkerr(js, "gpio_read(pin) expected");
    int pin = (int) js_getnum(args[0]);
    if (!valid_gpio(pin)) return js_mkerr(js, "invalid gpio");
    return js_mknum((double) gpio_get_level((gpio_num_t) pin));
}

static jsval_t js_delay_ms(struct js *js, jsval_t *args, int nargs) {
    if (!js_chkargs(args, nargs, "d")) return js_mkerr(js, "delay_ms(ms) expected");
    double d = js_getnum(args[0]);
    if (d < 0 || d > 600000) return js_mkerr(js, "delay out of range");
    uint32_t ms = (uint32_t) d;
    while (ms > 0) {
        if (s_stop_requested) return js_mkfalse();
        uint32_t slice = ms > 50 ? 50 : ms;
        vTaskDelay(pdMS_TO_TICKS(slice));
        ms -= slice;
    }
    return js_mktrue();
}

static jsval_t js_app_should_stop(struct js *js, jsval_t *args, int nargs) {
    (void) args;
    if (nargs != 0) return js_mkerr(js, "app_should_stop() expected");
    return s_stop_requested ? js_mktrue() : js_mkfalse();
}

static jsval_t js_millis(struct js *js, jsval_t *args, int nargs) {
    if (nargs != 0) return js_mkerr(js, "millis() expected");
    return js_mknum((double) (esp_timer_get_time() / 1000ULL));
}

static void set_error(const char *msg) {
    taskENTER_CRITICAL(&s_lock);
    strncpy(s_error, msg ? msg : "unknown error", sizeof(s_error) - 1);
    s_error[sizeof(s_error) - 1] = '\0';
    taskEXIT_CRITICAL(&s_lock);
}

static void app_task(void *arg) {
    char name[APP_NAME_MAX + 1];
    strncpy(name, (const char *) arg, sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';
    free(arg);

    char *code = NULL;
    size_t code_len = 0;
    esp_err_t err = storage_read_code(name, &code, &code_len);
    if (err != ESP_OK) {
        set_error("could not read app code");
        goto done;
    }

    size_t arena_size = CONFIG_APP_JS_ARENA_SIZE;
    void *arena = heap_caps_malloc(arena_size, MALLOC_CAP_8BIT);
    if (!arena) {
        set_error("not enough RAM for JS arena");
        free(code);
        goto done;
    }

    struct js *js = js_create(arena, arena_size);
    if (!js) {
        set_error("JS arena too small");
        free(arena);
        free(code);
        goto done;
    }

    js_setmaxcss(js, 2048);
    js_setgct(js, arena_size * 3 / 4);

    jsval_t glob = js_glob(js);
    js_set(js, glob, "print", js_mkfun(js_print));
    js_set(js, glob, "gpio_mode", js_mkfun(js_gpio_mode));
    js_set(js, glob, "gpio_write", js_mkfun(js_gpio_write));
    js_set(js, glob, "gpio_read", js_mkfun(js_gpio_read));
    js_set(js, glob, "delay_ms", js_mkfun(js_delay_ms));
    js_set(js, glob, "app_should_stop", js_mkfun(js_app_should_stop));
    js_set(js, glob, "millis", js_mkfun(js_millis));

    ESP_LOGI(TAG, "Starting app '%s' (%u bytes)", name, (unsigned) code_len);
    jsval_t result = js_eval(js, code, code_len);
    if (js_type(result) == JS_ERR) {
        set_error(js_str(js, result));
    } else if (s_stop_requested) {
        set_error("stop requested");
    } else {
        set_error("");
        ESP_LOGI(TAG, "App '%s' finished: %s", name, js_str(js, result));
    }

    free(arena);
    free(code);

done:
    taskENTER_CRITICAL(&s_lock);
    s_running = false;
    s_stop_requested = false;
    s_current[0] = '\0';
    s_task = NULL;
    taskEXIT_CRITICAL(&s_lock);
    vTaskDelete(NULL);
}

esp_err_t runner_init(void) {
    s_error[0] = '\0';
    s_current[0] = '\0';
    return ESP_OK;
}

esp_err_t runner_start(const char *name) {
    if (!storage_valid_name(name)) return ESP_ERR_INVALID_ARG;

    taskENTER_CRITICAL(&s_lock);
    if (s_running) {
        taskEXIT_CRITICAL(&s_lock);
        return ESP_ERR_INVALID_STATE;
    }
    s_running = true;
    s_stop_requested = false;
    strncpy(s_current, name, sizeof(s_current) - 1);
    s_current[sizeof(s_current) - 1] = '\0';
    s_error[0] = '\0';
    taskEXIT_CRITICAL(&s_lock);

    bool exists = false;
    esp_err_t err = storage_app_exists(name, &exists);
    if (err != ESP_OK || !exists) {
        taskENTER_CRITICAL(&s_lock);
        s_running = false;
        s_current[0] = '\0';
        taskEXIT_CRITICAL(&s_lock);
        return ESP_ERR_NOT_FOUND;
    }

    char *copy = strdup(name);
    if (!copy) {
        taskENTER_CRITICAL(&s_lock);
        s_running = false;
        s_current[0] = '\0';
        taskEXIT_CRITICAL(&s_lock);
        return ESP_ERR_NO_MEM;
    }

    BaseType_t ok = xTaskCreate(app_task, "js_app", APP_TASK_STACK, copy,
                                APP_TASK_PRIORITY, &s_task);
    if (ok != pdPASS) {
        free(copy);
        taskENTER_CRITICAL(&s_lock);
        s_running = false;
        s_current[0] = '\0';
        taskEXIT_CRITICAL(&s_lock);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

esp_err_t runner_request_stop(void) {
    taskENTER_CRITICAL(&s_lock);
    if (!s_running) {
        taskEXIT_CRITICAL(&s_lock);
        return ESP_ERR_INVALID_STATE;
    }
    s_stop_requested = true;
    taskEXIT_CRITICAL(&s_lock);
    return ESP_OK;
}

bool runner_is_running(void) {
    taskENTER_CRITICAL(&s_lock);
    bool value = s_running;
    taskEXIT_CRITICAL(&s_lock);
    return value;
}

bool runner_stop_requested(void) {
    taskENTER_CRITICAL(&s_lock);
    bool value = s_stop_requested;
    taskEXIT_CRITICAL(&s_lock);
    return value;
}

bool runner_is_app_running(const char *name) {
    if (!name) return false;
    taskENTER_CRITICAL(&s_lock);
    bool value = s_running && strcmp(s_current, name) == 0;
    taskEXIT_CRITICAL(&s_lock);
    return value;
}
const char *runner_current_app(void) { return s_current; }
const char *runner_last_error(void) { return s_error; }

static size_t json_escape(const char *src, char *dst, size_t cap) {
    size_t j = 0;
    if (cap == 0) return 0;
    for (size_t i = 0; src && src[i] && j + 2 < cap; i++) {
        unsigned char c = (unsigned char) src[i];
        if (c == '\"' || c == '\\') {
            dst[j++] = '\\';
            dst[j++] = (char) c;
        } else if (c == '\n') {
            dst[j++] = '\\'; dst[j++] = 'n';
        } else if (c == '\r') {
            dst[j++] = '\\'; dst[j++] = 'r';
        } else if (c == '\t') {
            dst[j++] = '\\'; dst[j++] = 't';
        } else if (c < 0x20) {
            dst[j++] = '?';
        } else {
            dst[j++] = (char) c;
        }
    }
    dst[j] = '\0';
    return j;
}

void runner_status_json(char *out, size_t out_len) {
    bool running;
    bool stop_requested;
    char app[APP_NAME_MAX + 1];
    char error[APP_LOG_MAX];
    char e_app[APP_NAME_MAX * 2 + 2];
    char e_error[APP_LOG_MAX * 2 + 2];
    taskENTER_CRITICAL(&s_lock);
    running = s_running;
    stop_requested = s_stop_requested;
    strncpy(app, s_current, sizeof(app) - 1);
    app[sizeof(app) - 1] = '\0';
    strncpy(error, s_error, sizeof(error) - 1);
    error[sizeof(error) - 1] = '\0';
    taskEXIT_CRITICAL(&s_lock);
    json_escape(app, e_app, sizeof(e_app));
    json_escape(error, e_error, sizeof(e_error));
    snprintf(out, out_len,
             "{\"running\":%s,\"stopRequested\":%s,\"app\":\"%s\",\"error\":\"%s\"}",
             running ? "true" : "false",
             stop_requested ? "true" : "false",
             e_app, e_error);
}
