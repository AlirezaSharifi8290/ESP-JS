#include "storage.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/unistd.h>

#include "cJSON.h"
#include "esp_log.h"
#include "esp_littlefs.h"

static const char *TAG = "storage";
#define MOUNT "/littlefs"
#define MAX_APPS 64
static const size_t MAX_CODE = CONFIG_APP_MAX_CODE_SIZE;

static void app_dir(const char *name, char *out, size_t out_len) {
    snprintf(out, out_len, "%s/apps/%s", MOUNT, name);
}

static void code_path(const char *name, char *out, size_t out_len) {
    snprintf(out, out_len, "%s/apps/%s/main.js", MOUNT, name);
}

static bool append_suffix(char *out, size_t out_len, const char *base, const char *suffix) {
    size_t base_len = strlen(base);
    size_t suffix_len = strlen(suffix);
    if (base_len + suffix_len + 1 > out_len) return false;
    memcpy(out, base, base_len);
    memcpy(out + base_len, suffix, suffix_len + 1);
    return true;
}

static bool append_child(char *out, size_t out_len, const char *base, const char *child) {
    size_t base_len = strlen(base);
    size_t child_len = strlen(child);
    if (base_len + 1 + child_len + 1 > out_len) return false;
    memcpy(out, base, base_len);
    out[base_len] = '/';
    memcpy(out + base_len + 1, child, child_len + 1);
    return true;
}

bool storage_valid_name(const char *name) {
    size_t n;
    if (!name) return false;
    n = strlen(name);
    if (n == 0 || n > APP_NAME_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) {
            return false;
        }
    }
    return true;
}

esp_err_t storage_init(void) {
    esp_vfs_littlefs_conf_t conf = {
        .base_path = MOUNT,
        .partition_label = "littlefs",
        .format_if_mount_failed = true,
        .dont_mount = false,
    };

    esp_err_t err = esp_vfs_littlefs_register(&conf);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "LittleFS mount failed: %s", esp_err_to_name(err));
        return err;
    }

    struct stat st;
    if (stat(MOUNT "/apps", &st) != 0) {
        if (mkdir(MOUNT "/apps", 0775) != 0 && errno != EEXIST) {
            ESP_LOGE(TAG, "mkdir /apps failed: %s", strerror(errno));
            return ESP_FAIL;
        }
    }
    ESP_LOGI(TAG, "LittleFS mounted");
    return ESP_OK;
}

esp_err_t storage_app_exists(const char *name, bool *exists) {
    if (!storage_valid_name(name) || !exists) return ESP_ERR_INVALID_ARG;
    char path[APP_PATH_MAX];
    code_path(name, path, sizeof(path));
    struct stat st;
    *exists = stat(path, &st) == 0 && S_ISREG(st.st_mode);
    return ESP_OK;
}

esp_err_t storage_read_code(const char *name, char **out_code, size_t *out_len) {
    if (!storage_valid_name(name) || !out_code || !out_len) return ESP_ERR_INVALID_ARG;
    *out_code = NULL;
    *out_len = 0;

    char path[APP_PATH_MAX];
    code_path(name, path, sizeof(path));
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) return ESP_ERR_NOT_FOUND;
    if (st.st_size <= 0 || (size_t)st.st_size > MAX_CODE) return ESP_ERR_INVALID_SIZE;

    FILE *f = fopen(path, "rb");
    if (!f) return ESP_FAIL;
    size_t len = (size_t)st.st_size;
    char *buf = calloc(1, len + 1);
    if (!buf) {
        fclose(f);
        return ESP_ERR_NO_MEM;
    }
    size_t got = fread(buf, 1, len, f);
    fclose(f);
    if (got != len) {
        free(buf);
        return ESP_FAIL;
    }
    buf[len] = '\0';
    *out_code = buf;
    *out_len = len;
    return ESP_OK;
}

esp_err_t storage_write_code(const char *name, const char *code, size_t len) {
    if (!storage_valid_name(name) || !code) return ESP_ERR_INVALID_ARG;
    if (len == 0 || len > MAX_CODE) return ESP_ERR_INVALID_SIZE;

    char dir[APP_PATH_MAX];
    char path[APP_PATH_MAX];
    app_dir(name, dir, sizeof(dir));
    code_path(name, path, sizeof(path));

    if (mkdir(dir, 0775) != 0 && errno != EEXIST) return ESP_FAIL;

    char tmp[APP_PATH_MAX];
    if (!append_suffix(tmp, sizeof(tmp), dir, "/.main.js.tmp")) return ESP_ERR_INVALID_SIZE;
    FILE *f = fopen(tmp, "wb");
    if (!f) return ESP_FAIL;
    size_t written = fwrite(code, 1, len, f);
    fflush(f);
    fclose(f);
    if (written != len) {
        unlink(tmp);
        return ESP_FAIL;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return ESP_FAIL;
    }

    char manifest[APP_PATH_MAX];
    if (!append_suffix(manifest, sizeof(manifest), dir, "/manifest.json")) return ESP_ERR_INVALID_SIZE;
    FILE *m = fopen(manifest, "wb");
    if (!m) {
        ESP_LOGW(TAG, "could not write manifest for %s", name);
        return ESP_OK;
    }
    int written_manifest = fprintf(m, "{\"name\":\"%s\",\"version\":\"1.0.0\",\"entry\":\"main.js\"}\n", name);
    int close_result = fclose(m);
    if (written_manifest < 0 || close_result != 0) {
        ESP_LOGW(TAG, "could not finish manifest for %s", name);
    }
    return ESP_OK;
}

static esp_err_t delete_tree(const char *dir_path) {
    DIR *dir = opendir(dir_path);
    if (!dir) return ESP_FAIL;
    struct dirent *ent;
    size_t count = 0;
    while ((ent = readdir(dir)) != NULL) {
        if (count >= MAX_APPS) break;
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char path[APP_PATH_MAX];
        if (!append_child(path, sizeof(path), dir_path, ent->d_name)) {
            closedir(dir);
            return ESP_ERR_INVALID_SIZE;
        }
        struct stat st;
        if (stat(path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            delete_tree(path);
            rmdir(path);
        } else {
            unlink(path);
        }
    }
    closedir(dir);
    return rmdir(dir_path) == 0 ? ESP_OK : ESP_FAIL;
}

esp_err_t storage_delete_app(const char *name) {
    if (!storage_valid_name(name)) return ESP_ERR_INVALID_ARG;
    char dir[APP_PATH_MAX];
    app_dir(name, dir, sizeof(dir));
    struct stat st;
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) return ESP_ERR_NOT_FOUND;
    return delete_tree(dir);
}

esp_err_t storage_list_apps(char *out, size_t out_len) {
    if (!out || out_len < 3) return ESP_ERR_INVALID_ARG;
    cJSON *arr = cJSON_CreateArray();
    if (!arr) return ESP_ERR_NO_MEM;

    DIR *dir = opendir(MOUNT "/apps");
    if (!dir) {
        cJSON_Delete(arr);
        return ESP_FAIL;
    }

    struct dirent *ent;
    size_t count = 0;
    while ((ent = readdir(dir)) != NULL) {
        if (count >= MAX_APPS) break;
        if (!storage_valid_name(ent->d_name)) continue;
        bool exists = false;
        storage_app_exists(ent->d_name, &exists);
        if (!exists) continue;
        cJSON *item = cJSON_CreateString(ent->d_name);
        if (!item || !cJSON_AddItemToArray(arr, item)) {
            cJSON_Delete(item);
            closedir(dir);
            cJSON_Delete(arr);
            return ESP_ERR_NO_MEM;
        }
        count++;
    }
    closedir(dir);

    char *printed = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    if (!printed) return ESP_ERR_NO_MEM;
    size_t len = strlen(printed);
    if (len + 1 > out_len) {
        free(printed);
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(out, printed, len + 1);
    free(printed);
    return ESP_OK;
}
