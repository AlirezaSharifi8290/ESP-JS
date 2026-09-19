if(NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/elk.c" OR NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/elk.h")
    message(FATAL_ERROR "Elk sources are missing. Run tools/fetch_elk.ps1 (Windows) or tools/fetch_elk.sh (Linux/macOS) before building.")
endif()

idf_component_register(
    SRCS "elk.c"
    INCLUDE_DIRS "."
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE JS_EXPR_MAX=24)
# GCC 13+ diagnoses an upstream Elk js_eval pattern as -Wdangling-pointer.
# ESP-IDF enables -Werror globally, so keep this warning non-fatal for Elk only.
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-error=dangling-pointer)
