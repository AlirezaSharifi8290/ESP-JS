cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp_js_os)

# Seed the LittleFS partition with a directory named /apps containing the
# initial example applications. littlefs_create_partition_image mirrors the
# contents of the supplied source directory into the filesystem root, so the
# source directory itself must contain the desired "apps" and "www" directories.
littlefs_create_partition_image(littlefs data FLASH_IN_PROJECT)
