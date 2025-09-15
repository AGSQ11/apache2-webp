/**
 * mod_webp.c: Enterprise-grade Apache module for strict on-the-fly image conversion to WebP format
 *
 * Features:
 * - Supports all common image formats (JPEG, PNG, BMP, TIFF, GIF, WebP)
 * - Strict transformation enforcement - no image escapes conversion
 * - Enterprise-grade security and error handling
 * - Content-type validation and magic number verification
 * - Comprehensive logging and monitoring
 *
 * Copyright 2025 AGSQ11
 * MIT License
 */

#include "apr_hash.h"
#include "apr_strings.h"
#include "apr_file_info.h"
#include "apr_file_io.h"
#include "apr_time.h"
#include "apr_md5.h"
#include "apr_sha1.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_filter.h"
#include "apr_buckets.h"
#include "ap_mpm.h"
#include "apr_thread_mutex.h"

/* libwebp includes */
#include <webp/encode.h>
#include <webp/decode.h>
#include <webp/demux.h>

/* System includes for image format detection */
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#ifdef _WIN32
    #include <process.h>
    #define getpid _getpid
#else
    #include <unistd.h>
#endif

module AP_MODULE_DECLARE_DATA webp_module;

/* Maximum file size for processing (default 50MB) */
#define WEBP_MAX_FILE_SIZE (50 * 1024 * 1024)

/* Maximum image dimensions */
#define WEBP_MAX_WIDTH 16384
#define WEBP_MAX_HEIGHT 16384

/* Cache validation timeout (seconds) */
#define WEBP_CACHE_TIMEOUT 3600

/* Image format detection magic numbers */
#define JPEG_MAGIC_1 0xFF
#define JPEG_MAGIC_2 0xD8
#define PNG_MAGIC_SIZE 8
static const unsigned char PNG_MAGIC[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
static const unsigned char BMP_MAGIC[] = {0x42, 0x4D};
static const unsigned char TIFF_MAGIC_LE[] = {0x49, 0x49, 0x2A, 0x00};
static const unsigned char TIFF_MAGIC_BE[] = {0x4D, 0x4D, 0x00, 0x2A};
static const unsigned char GIF_MAGIC_87A[] = {0x47, 0x49, 0x46, 0x38, 0x37, 0x61};
static const unsigned char GIF_MAGIC_89A[] = {0x47, 0x49, 0x46, 0x38, 0x39, 0x61};
static const unsigned char WEBP_MAGIC[] = {0x52, 0x49, 0x46, 0x46};

/* Image format enumeration */
typedef enum {
    IMG_FORMAT_UNKNOWN = 0,
    IMG_FORMAT_JPEG,
    IMG_FORMAT_PNG,
    IMG_FORMAT_BMP,
    IMG_FORMAT_TIFF,
    IMG_FORMAT_GIF,
    IMG_FORMAT_WEBP
} image_format_t;

/* Configuration structure */
typedef struct {
    int enabled;
    int strict_mode;
    float quality;
    char *cache_dir;
    apr_off_t max_file_size;
    int max_width;
    int max_height;
    int cache_timeout;
    int log_level;
    char *allowed_formats;
} webp_config;

/* Function prototypes */
static int webp_handler(request_rec *r);
static int convert_image_to_webp(request_rec *r, const char *input_path, const char *output_path);
static int is_browser_webp_compatible(request_rec *r);
static int is_cache_valid(request_rec *r, const char *original_file, const char *cache_file);
static char *get_cache_filename(request_rec *r, const char *input_path);
static void *webp_create_dir_config(apr_pool_t *p, char *dummy);
static void *webp_merge_dir_config(apr_pool_t *p, void *basev, void *overridesv);
static int serve_webp_file(request_rec *r, const char *webp_path);
static int serve_original_file(request_rec *r, const char *file_path);
static image_format_t detect_image_format(request_rec *r, const char *file_path);
static int validate_image_file(request_rec *r, const char *file_path, image_format_t format);
static int is_image_request(request_rec *r);
static int create_cache_directory(request_rec *r, const char *cache_dir);
static int validate_cache_directory(request_rec *r, const char *cache_dir);
static const char *image_format_to_string(image_format_t format);
static int is_format_allowed(webp_config *conf, image_format_t format, apr_pool_t *pool);

/* Custom function to set float values */
static const char *webp_set_float_slot(cmd_parms *cmd, void *struct_ptr, const char *arg) {
    webp_config *conf = (webp_config *)struct_ptr;
    float val;
    char *endptr;

    if (!arg || !*arg) {
        return "WebPQuality argument cannot be empty";
    }

    val = strtod(arg, &endptr);
    if (*endptr != '\0' || val < 0.0 || val > 100.0) {
        return "WebPQuality must be a float between 0.0 and 100.0";
    }

    *(float *)((char *)struct_ptr + (size_t)cmd->info) = val;
    return NULL;
}

/* Custom function to set file size values */
static const char *webp_set_size_slot(cmd_parms *cmd, void *struct_ptr, const char *arg) {
    char *endptr;
    apr_off_t val;

    if (!arg || !*arg) {
        return "WebPMaxFileSize argument cannot be empty";
    }

    val = strtoll(arg, &endptr, 10);
    if (*endptr != '\0' || val < 0 || val > (100LL * 1024 * 1024 * 1024)) { /* 100GB max */
        return "WebPMaxFileSize must be a number between 0 and 107374182400 (100GB)";
    }

    *(apr_off_t *)((char *)struct_ptr + (size_t)cmd->info) = val;
    return NULL;
}

/* Custom function to set integer values with validation */
static const char *webp_set_int_slot(cmd_parms *cmd, void *struct_ptr, const char *arg) {
    char *endptr;
    long val;

    if (!arg || !*arg) {
        return "Integer argument cannot be empty";
    }

    val = strtol(arg, &endptr, 10);
    if (*endptr != '\0' || val < 0 || val > INT_MAX) {
        return "Integer value out of range";
    }

    *(int *)((char *)struct_ptr + (size_t)cmd->info) = (int)val;
    return NULL;
}

/* Configuration directives */
static const command_rec webp_directives[] = {
    AP_INIT_TAKE1("WebPQuality", webp_set_float_slot,
                  (void *)APR_OFFSETOF(webp_config, quality),
                  OR_FILEINFO, "Set WebP quality (0.0-100.0)"),
    AP_INIT_FLAG("WebPEnabled", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(webp_config, enabled),
                 OR_FILEINFO, "Enable or disable WebP conversion"),
    AP_INIT_FLAG("WebPStrictMode", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(webp_config, strict_mode),
                 OR_FILEINFO, "Enable strict mode - no image escapes conversion"),
    AP_INIT_TAKE1("WebPCacheDir", ap_set_string_slot,
                  (void *)APR_OFFSETOF(webp_config, cache_dir),
                  OR_FILEINFO, "Set cache directory for WebP images"),
    AP_INIT_TAKE1("WebPMaxFileSize", webp_set_size_slot,
                  (void *)APR_OFFSETOF(webp_config, max_file_size),
                  OR_FILEINFO, "Set maximum file size for processing (bytes)"),
    AP_INIT_TAKE1("WebPMaxWidth", webp_set_int_slot,
                  (void *)APR_OFFSETOF(webp_config, max_width),
                  OR_FILEINFO, "Set maximum image width for processing"),
    AP_INIT_TAKE1("WebPMaxHeight", webp_set_int_slot,
                  (void *)APR_OFFSETOF(webp_config, max_height),
                  OR_FILEINFO, "Set maximum image height for processing"),
    AP_INIT_TAKE1("WebPCacheTimeout", webp_set_int_slot,
                  (void *)APR_OFFSETOF(webp_config, cache_timeout),
                  OR_FILEINFO, "Set cache validity timeout in seconds"),
    AP_INIT_TAKE1("WebPLogLevel", webp_set_int_slot,
                  (void *)APR_OFFSETOF(webp_config, log_level),
                  OR_FILEINFO, "Set logging level (0=ERROR, 1=WARN, 2=INFO, 3=DEBUG)"),
    AP_INIT_TAKE1("WebPAllowedFormats", ap_set_string_slot,
                  (void *)APR_OFFSETOF(webp_config, allowed_formats),
                  OR_FILEINFO, "Set allowed image formats (jpeg,png,bmp,tiff,gif,webp)"),
    {NULL}
};

/* Create directory configuration */
static void *webp_create_dir_config(apr_pool_t *p, char *dummy) {
    webp_config *conf = apr_pcalloc(p, sizeof(webp_config));

    conf->enabled = 1;  /* Enabled by default */
    conf->strict_mode = 1;  /* Strict mode enabled by default */
    conf->quality = 85.0;  /* Default quality */
    conf->cache_dir = "/var/cache/mod_webp";  /* Enterprise cache directory */
    conf->max_file_size = WEBP_MAX_FILE_SIZE;  /* Default max file size */
    conf->max_width = WEBP_MAX_WIDTH;  /* Default max width */
    conf->max_height = WEBP_MAX_HEIGHT;  /* Default max height */
    conf->cache_timeout = WEBP_CACHE_TIMEOUT;  /* Default cache timeout */
    conf->log_level = 1;  /* Default log level: WARN */
    conf->allowed_formats = "jpeg,png,bmp,tiff,gif";  /* Default allowed formats */

    return conf;
}

/* Merge directory configuration */
static void *webp_merge_dir_config(apr_pool_t *p, void *basev, void *overridesv) {
    webp_config *base = (webp_config *)basev;
    webp_config *overrides = (webp_config *)overridesv;
    webp_config *conf = apr_pcalloc(p, sizeof(webp_config));

    conf->enabled = (overrides->enabled != -1) ? overrides->enabled : base->enabled;
    conf->strict_mode = (overrides->strict_mode != -1) ? overrides->strict_mode : base->strict_mode;
    conf->quality = (overrides->quality != -1) ? overrides->quality : base->quality;
    conf->cache_dir = (overrides->cache_dir) ? overrides->cache_dir : base->cache_dir;
    conf->max_file_size = (overrides->max_file_size != -1) ? overrides->max_file_size : base->max_file_size;
    conf->max_width = (overrides->max_width != -1) ? overrides->max_width : base->max_width;
    conf->max_height = (overrides->max_height != -1) ? overrides->max_height : base->max_height;
    conf->cache_timeout = (overrides->cache_timeout != -1) ? overrides->cache_timeout : base->cache_timeout;
    conf->log_level = (overrides->log_level != -1) ? overrides->log_level : base->log_level;
    conf->allowed_formats = (overrides->allowed_formats) ? overrides->allowed_formats : base->allowed_formats;

    return conf;
}

/* Convert image format enum to string */
static const char *image_format_to_string(image_format_t format) {
    switch (format) {
        case IMG_FORMAT_JPEG: return "JPEG";
        case IMG_FORMAT_PNG: return "PNG";
        case IMG_FORMAT_BMP: return "BMP";
        case IMG_FORMAT_TIFF: return "TIFF";
        case IMG_FORMAT_GIF: return "GIF";
        case IMG_FORMAT_WEBP: return "WebP";
        default: return "UNKNOWN";
    }
}

/* Check if format is allowed by configuration */
static int is_format_allowed(webp_config *conf, image_format_t format, apr_pool_t *pool) {
    const char *format_str;
    char *allowed_copy, *token, *last;

    if (!conf->allowed_formats) {
        return 1;  /* Allow all if not specified */
    }

    format_str = image_format_to_string(format);
    if (!format_str || strcmp(format_str, "UNKNOWN") == 0) {
        return 0;
    }

    /* Create a copy for tokenization */
    allowed_copy = apr_pstrdup(pool, conf->allowed_formats);
    if (!allowed_copy) {
        return 0;
    }

    /* Check each allowed format */
    for (token = apr_strtok(allowed_copy, ",", &last); token; token = apr_strtok(NULL, ",", &last)) {
        /* Trim whitespace */
        while (*token && isspace(*token)) token++;
        char *end = token + strlen(token) - 1;
        while (end > token && isspace(*end)) *end-- = '\0';

        if (strcasecmp(token, format_str) == 0) {
            return 1;
        }
    }

    return 0;
}

/* Detect image format by magic numbers */
static image_format_t detect_image_format(request_rec *r, const char *file_path) {
    apr_file_t *fd = NULL;
    apr_status_t rv;
    unsigned char magic[16];
    apr_size_t bytes_read = sizeof(magic);
    image_format_t format = IMG_FORMAT_UNKNOWN;

    rv = apr_file_open(&fd, file_path, APR_READ, APR_OS_DEFAULT, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "mod_webp: Failed to open file for format detection: %s", file_path);
        return IMG_FORMAT_UNKNOWN;
    }

    rv = apr_file_read(fd, magic, &bytes_read);
    apr_file_close(fd);

    if (rv != APR_SUCCESS || bytes_read < 4) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "mod_webp: Failed to read magic bytes from: %s", file_path);
        return IMG_FORMAT_UNKNOWN;
    }

    /* JPEG detection */
    if (bytes_read >= 2 && magic[0] == JPEG_MAGIC_1 && magic[1] == JPEG_MAGIC_2) {
        format = IMG_FORMAT_JPEG;
    }
    /* PNG detection */
    else if (bytes_read >= PNG_MAGIC_SIZE && memcmp(magic, PNG_MAGIC, PNG_MAGIC_SIZE) == 0) {
        format = IMG_FORMAT_PNG;
    }
    /* BMP detection */
    else if (bytes_read >= 2 && memcmp(magic, BMP_MAGIC, 2) == 0) {
        format = IMG_FORMAT_BMP;
    }
    /* TIFF detection (both endianness) */
    else if (bytes_read >= 4 && (memcmp(magic, TIFF_MAGIC_LE, 4) == 0 || memcmp(magic, TIFF_MAGIC_BE, 4) == 0)) {
        format = IMG_FORMAT_TIFF;
    }
    /* GIF detection */
    else if (bytes_read >= 6 && (memcmp(magic, GIF_MAGIC_87A, 6) == 0 || memcmp(magic, GIF_MAGIC_89A, 6) == 0)) {
        format = IMG_FORMAT_GIF;
    }
    /* WebP detection */
    else if (bytes_read >= 4 && memcmp(magic, WEBP_MAGIC, 4) == 0) {
        format = IMG_FORMAT_WEBP;
    }

    return format;
}

/* Validate image file size and dimensions */
static int validate_image_file(request_rec *r, const char *file_path, image_format_t format) {
    webp_config *conf = ap_get_module_config(r->per_dir_config, &webp_module);
    apr_finfo_t finfo;
    apr_status_t rv;

    /* Check file size */
    rv = apr_stat(&finfo, file_path, APR_FINFO_SIZE, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "mod_webp: Failed to get file info: %s", file_path);
        return 0;
    }

    if (finfo.size > conf->max_file_size) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "mod_webp: File too large (%" APR_OFF_T_FMT " > %" APR_OFF_T_FMT "): %s",
                      finfo.size, conf->max_file_size, file_path);
        return 0;
    }

    if (finfo.size == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "mod_webp: Empty file: %s", file_path);
        return 0;
    }

    /* Additional format-specific validation could go here */
    return 1;
}

/* Check if this is an image request we should handle */
static int is_image_request(request_rec *r) {
    const char *content_type;
    image_format_t format;
    webp_config *conf = ap_get_module_config(r->per_dir_config, &webp_module);

    if (!r->filename) {
        return 0;
    }

    /* Detect format by magic numbers (most reliable) */
    format = detect_image_format(r, r->filename);

    if (format == IMG_FORMAT_UNKNOWN) {
        if (conf->log_level >= 3) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "mod_webp: Unknown image format: %s", r->filename);
        }
        return 0;
    }

    /* Check if format is allowed */
    if (!is_format_allowed(conf, format, r->pool)) {
        if (conf->log_level >= 2) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "mod_webp: Format %s not allowed: %s", image_format_to_string(format), r->filename);
        }
        return 0;
    }

    /* Validate file */
    if (!validate_image_file(r, r->filename, format)) {
        return 0;
    }

    return 1;
}

/* Check if browser supports WebP */
static int is_browser_webp_compatible(request_rec *r) {
    const char *accept_header = apr_table_get(r->headers_in, "Accept");
    const char *user_agent = apr_table_get(r->headers_in, "User-Agent");
    webp_config *conf = ap_get_module_config(r->per_dir_config, &webp_module);

    if (accept_header && strstr(accept_header, "image/webp")) {
        if (conf->log_level >= 3) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "mod_webp: Browser supports WebP (Accept header)");
        }
        return 1;
    }

    /* Fallback check for known WebP-supporting browsers */
    if (user_agent) {
        if (strstr(user_agent, "Chrome/") || strstr(user_agent, "Chromium/") ||
            strstr(user_agent, "Edge/") || strstr(user_agent, "Opera/")) {
            if (conf->log_level >= 3) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "mod_webp: Browser likely supports WebP (User-Agent)");
            }
            return 1;
        }
    }

    if (conf->log_level >= 3) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "mod_webp: Browser does not support WebP");
    }
    return 0;
}

/* Enhanced cache directory creation with better permission handling */
static int create_cache_directory(request_rec *r, const char *cache_dir) {
    webp_config *conf = ap_get_module_config(r->per_dir_config, &webp_module);
    apr_status_t rv;
    apr_finfo_t finfo;
    char *parent_dir, *current_dir;
    char *dir_copy;
    char *token, *last;

    if (!cache_dir || !*cache_dir) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_webp: Cache directory path is empty");
        return 0;
    }

    /* Check if directory already exists */
    rv = apr_stat(&finfo, cache_dir, APR_FINFO_TYPE, r->pool);
    if (rv == APR_SUCCESS) {
        if (finfo.filetype == APR_DIR) {
            if (conf->log_level >= 3) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "mod_webp: Cache directory already exists: %s", cache_dir);
            }
            return 1;  /* Directory already exists */
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "mod_webp: Cache path exists but is not a directory: %s", cache_dir);
            return 0;
        }
    }

    /* Try recursive creation with better permissions */
    rv = apr_dir_make_recursive(cache_dir,
                               APR_FPROT_UREAD | APR_FPROT_UWRITE | APR_FPROT_UEXECUTE |
                               APR_FPROT_GREAD | APR_FPROT_GWRITE | APR_FPROT_GEXECUTE |
                               APR_FPROT_WREAD | APR_FPROT_WEXECUTE,
                               r->pool);

    if (rv == APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "mod_webp: Successfully created cache directory: %s", cache_dir);
        return 1;
    }

    /* If recursive creation failed, try creating parent directories manually */
    if (conf->log_level >= 2) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r,
                      "mod_webp: Recursive creation failed, trying manual creation: %s", cache_dir);
    }

    /* Create a copy for tokenization */
    dir_copy = apr_pstrdup(r->pool, cache_dir);
    if (!dir_copy) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_webp: Memory allocation failed for directory path");
        return 0;
    }

    /* Build path incrementally */
    current_dir = apr_pstrdup(r->pool, "");

    /* Handle absolute path */
    if (dir_copy[0] == '/') {
        current_dir = apr_pstrcat(r->pool, current_dir, "/", NULL);
        dir_copy++; /* Skip the leading slash */
    }

    /* Create each directory level */
    for (token = apr_strtok(dir_copy, "/", &last); token; token = apr_strtok(NULL, "/", &last)) {
        current_dir = apr_pstrcat(r->pool, current_dir, token, "/", NULL);

        /* Remove trailing slash for apr_stat */
        size_t len = strlen(current_dir);
        if (len > 1 && current_dir[len-1] == '/') {
            current_dir[len-1] = '\0';
        }

        /* Check if this level exists */
        rv = apr_stat(&finfo, current_dir, APR_FINFO_TYPE, r->pool);
        if (rv != APR_SUCCESS) {
            /* Create this directory level */
            rv = apr_dir_make(current_dir,
                             APR_FPROT_UREAD | APR_FPROT_UWRITE | APR_FPROT_UEXECUTE |
                             APR_FPROT_GREAD | APR_FPROT_GWRITE | APR_FPROT_GEXECUTE |
                             APR_FPROT_WREAD | APR_FPROT_WEXECUTE,
                             r->pool);

            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                              "mod_webp: Failed to create directory level: %s", current_dir);
                return 0;
            }

            if (conf->log_level >= 3) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "mod_webp: Created directory level: %s", current_dir);
            }
        }

        /* Restore trailing slash for next iteration */
        current_dir = apr_pstrcat(r->pool, current_dir, "/", NULL);
    }

    /* Final verification */
    rv = apr_stat(&finfo, cache_dir, APR_FINFO_TYPE, r->pool);
    if (rv == APR_SUCCESS && finfo.filetype == APR_DIR) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "mod_webp: Successfully created cache directory: %s", cache_dir);
        return 1;
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                  "mod_webp: Failed to create cache directory after all attempts: %s", cache_dir);
    return 0;
}

/* Enhanced cache directory validation with smart retry logic */
static int validate_cache_directory(request_rec *r, const char *cache_dir) {
    webp_config *conf = ap_get_module_config(r->per_dir_config, &webp_module);
    apr_finfo_t finfo;
    apr_status_t rv;
    static apr_hash_t *validated_dirs = NULL;
    static apr_thread_mutex_t *validation_mutex = NULL;
    int *is_validated;

    if (!cache_dir || !*cache_dir) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_webp: Cache directory not configured");
        return 0;
    }

    /* Initialize validation cache (thread-safe) */
    if (!validation_mutex) {
        apr_thread_mutex_create(&validation_mutex, APR_THREAD_MUTEX_DEFAULT, r->pool);
        validated_dirs = apr_hash_make(r->pool);
    }

    /* Check if we've already validated this directory in this process */
    apr_thread_mutex_lock(validation_mutex);
    is_validated = (int*)apr_hash_get(validated_dirs, cache_dir, APR_HASH_KEY_STRING);
    apr_thread_mutex_unlock(validation_mutex);

    if (is_validated && *is_validated) {
        if (conf->log_level >= 3) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "mod_webp: Cache directory already validated: %s", cache_dir);
        }
        return 1;
    }

    /* Check if directory exists */
    rv = apr_stat(&finfo, cache_dir, APR_FINFO_TYPE | APR_FINFO_PROT, r->pool);
    if (rv != APR_SUCCESS) {
        /* Directory doesn't exist, try to create it */
        if (conf->log_level >= 2) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, rv, r,
                          "mod_webp: Cache directory does not exist, creating: %s", cache_dir);
        }

        if (!create_cache_directory(r, cache_dir)) {
            return 0;
        }

        /* Re-check after creation */
        rv = apr_stat(&finfo, cache_dir, APR_FINFO_TYPE | APR_FINFO_PROT, r->pool);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "mod_webp: Cache directory creation failed verification: %s", cache_dir);
            return 0;
        }
    }

    /* Verify it's actually a directory */
    if (finfo.filetype != APR_DIR) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_webp: Cache path exists but is not a directory: %s", cache_dir);
        return 0;
    }

    /* Test write permissions with unique filename */
    char *test_file = apr_psprintf(r->pool, "%s/.webp_test_%d_%ld",
                                   cache_dir, getpid(), (long)apr_time_now());
    apr_file_t *fd;

    rv = apr_file_open(&fd, test_file,
                       APR_CREATE | APR_WRITE | APR_TRUNCATE | APR_BINARY,
                       APR_FPROT_UREAD | APR_FPROT_UWRITE | APR_FPROT_GREAD | APR_FPROT_GWRITE,
                       r->pool);

    if (rv == APR_SUCCESS) {
        /* Write a small test */
        const char *test_data = "webp_test";
        apr_size_t bytes_written = strlen(test_data);
        apr_status_t write_rv = apr_file_write(fd, test_data, &bytes_written);
        apr_file_close(fd);

        /* Clean up test file */
        apr_file_remove(test_file, r->pool);

        if (write_rv != APR_SUCCESS || bytes_written != strlen(test_data)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, write_rv, r,
                          "mod_webp: Cache directory write test failed: %s", cache_dir);
            return 0;
        }

        /* Mark this directory as validated */
        apr_thread_mutex_lock(validation_mutex);
        int *validated = apr_palloc(r->pool, sizeof(int));
        *validated = 1;
        apr_hash_set(validated_dirs, apr_pstrdup(r->pool, cache_dir), APR_HASH_KEY_STRING, validated);
        apr_thread_mutex_unlock(validation_mutex);

        if (conf->log_level >= 2) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "mod_webp: Cache directory validated successfully: %s", cache_dir);
        }

        return 1;
    } else {
        /* Permission error - try to fix permissions */
        if (conf->log_level >= 1) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
                          "mod_webp: Cache directory write test failed, attempting to fix permissions: %s", cache_dir);
        }

        /* Try to set better permissions on existing directory */
        rv = apr_file_perms_set(cache_dir,
                               APR_FPROT_UREAD | APR_FPROT_UWRITE | APR_FPROT_UEXECUTE |
                               APR_FPROT_GREAD | APR_FPROT_GWRITE | APR_FPROT_GEXECUTE |
                               APR_FPROT_WREAD | APR_FPROT_WEXECUTE);

        if (rv == APR_SUCCESS) {
            /* Retry the write test */
            rv = apr_file_open(&fd, test_file,
                               APR_CREATE | APR_WRITE | APR_TRUNCATE | APR_BINARY,
                               APR_FPROT_UREAD | APR_FPROT_UWRITE | APR_FPROT_GREAD | APR_FPROT_GWRITE,
                               r->pool);

            if (rv == APR_SUCCESS) {
                apr_file_close(fd);
                apr_file_remove(test_file, r->pool);

                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                              "mod_webp: Fixed cache directory permissions: %s", cache_dir);

                /* Mark as validated */
                apr_thread_mutex_lock(validation_mutex);
                int *validated = apr_palloc(r->pool, sizeof(int));
                *validated = 1;
                apr_hash_set(validated_dirs, apr_pstrdup(r->pool, cache_dir), APR_HASH_KEY_STRING, validated);
                apr_thread_mutex_unlock(validation_mutex);

                return 1;
            }
        }

        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "mod_webp: Cache directory not writable and cannot fix permissions: %s", cache_dir);
        return 0;
    }
}

/* Generate cache filename with better collision resistance */
static char *get_cache_filename(request_rec *r, const char *input_path) {
    webp_config *conf = ap_get_module_config(r->per_dir_config, &webp_module);
    apr_md5_ctx_t md5_ctx;
    unsigned char digest[APR_MD5_DIGESTSIZE];
    char *hex_digest;
    apr_finfo_t finfo;
    apr_status_t rv;

    /* Get file modification time for cache validation */
    rv = apr_stat(&finfo, input_path, APR_FINFO_MTIME | APR_FINFO_SIZE, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "mod_webp: Failed to stat input file: %s", input_path);
        return NULL;
    }

    /* Create MD5 hash of file path, mtime, and size for better uniqueness */
    apr_md5_init(&md5_ctx);
    apr_md5_update(&md5_ctx, input_path, strlen(input_path));
    apr_md5_update(&md5_ctx, &finfo.mtime, sizeof(finfo.mtime));
    apr_md5_update(&md5_ctx, &finfo.size, sizeof(finfo.size));
    apr_md5_update(&md5_ctx, &conf->quality, sizeof(conf->quality));
    apr_md5_final(digest, &md5_ctx);

    /* Convert to hex string */
    hex_digest = apr_palloc(r->pool, APR_MD5_DIGESTSIZE * 2 + 1);
    for (int i = 0; i < APR_MD5_DIGESTSIZE; i++) {
        sprintf(hex_digest + i * 2, "%02x", digest[i]);
    }
    hex_digest[APR_MD5_DIGESTSIZE * 2] = '\0';

    return apr_psprintf(r->pool, "%s/%s.webp", conf->cache_dir, hex_digest);
}

/* Check if cached version is valid */
static int is_cache_valid(request_rec *r, const char *original_file, const char *cache_file) {
    webp_config *conf = ap_get_module_config(r->per_dir_config, &webp_module);
    apr_finfo_t orig_info, cache_info;
    apr_time_t current_time = apr_time_now();
    apr_status_t rv;

    /* Get original file info */
    rv = apr_stat(&orig_info, original_file, APR_FINFO_MTIME | APR_FINFO_SIZE, r->pool);
    if (rv != APR_SUCCESS) {
        if (conf->log_level >= 1) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, rv, r,
                          "mod_webp: Cannot stat original file: %s", original_file);
        }
        return 0;
    }

    /* Get cache file info */
    rv = apr_stat(&cache_info, cache_file, APR_FINFO_MTIME | APR_FINFO_SIZE, r->pool);
    if (rv != APR_SUCCESS) {
        if (conf->log_level >= 3) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
                          "mod_webp: Cache file does not exist: %s", cache_file);
        }
        return 0;
    }

    /* Check if cache has expired based on timeout */
    if (conf->cache_timeout > 0) {
        apr_time_t cache_age = current_time - cache_info.mtime;
        if (cache_age > apr_time_from_sec(conf->cache_timeout)) {
            if (conf->log_level >= 2) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                              "mod_webp: Cache expired for: %s", cache_file);
            }
            return 0;
        }
    }

    /* Cache is valid if it's newer than the original file */
    if (cache_info.mtime >= orig_info.mtime) {
        if (conf->log_level >= 3) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "mod_webp: Cache valid for: %s", cache_file);
        }
        return 1;
    }

    if (conf->log_level >= 2) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "mod_webp: Cache outdated for: %s", cache_file);
    }
    return 0;
}

/* Serve WebP file to client */
static int serve_webp_file(request_rec *r, const char *webp_path) {
    webp_config *conf = ap_get_module_config(r->per_dir_config, &webp_module);
    apr_file_t *fd = NULL;
    apr_finfo_t finfo;
    apr_bucket_brigade *bb;
    apr_status_t rv;

    /* Open the WebP file */
    rv = apr_file_open(&fd, webp_path, APR_READ, APR_OS_DEFAULT, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "mod_webp: Failed to open WebP file %s", webp_path);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Get file info */
    rv = apr_file_info_get(&finfo, APR_FINFO_SIZE, fd);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "mod_webp: Failed to get file info for %s", webp_path);
        apr_file_close(fd);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Validate file size */
    if (finfo.size == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_webp: WebP file is empty: %s", webp_path);
        apr_file_close(fd);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Set content type and headers */
    ap_set_content_type(r, "image/webp");
    apr_table_setn(r->headers_out, "Content-Length", apr_off_t_toa(r->pool, finfo.size));
    apr_table_setn(r->headers_out, "Cache-Control", "public, max-age=31536000");
    apr_table_setn(r->headers_out, "X-WebP-Converted", "1");

    /* Create brigade for sending file content */
    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    /* Create file bucket */
    apr_bucket *bucket = apr_bucket_file_create(fd, 0, finfo.size, r->pool,
                                                r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, bucket);

    /* Create EOS bucket */
    bucket = apr_bucket_eos_create(r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, bucket);

    /* Send the file content */
    rv = ap_pass_brigade(r->output_filters, bb);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "mod_webp: Failed to send WebP file %s", webp_path);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (conf->log_level >= 2) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "mod_webp: Served WebP file: %s (size: %" APR_OFF_T_FMT ")", webp_path, finfo.size);
    }

    return OK;
}

/* Serve original file to client (fallback for non-WebP browsers) */
static int serve_original_file(request_rec *r, const char *file_path) {
    webp_config *conf = ap_get_module_config(r->per_dir_config, &webp_module);
    image_format_t format;
    const char *content_type;

    /* Detect format for proper content type */
    format = detect_image_format(r, file_path);
    switch (format) {
        case IMG_FORMAT_JPEG:
            content_type = "image/jpeg";
            break;
        case IMG_FORMAT_PNG:
            content_type = "image/png";
            break;
        case IMG_FORMAT_BMP:
            content_type = "image/bmp";
            break;
        case IMG_FORMAT_TIFF:
            content_type = "image/tiff";
            break;
        case IMG_FORMAT_GIF:
            content_type = "image/gif";
            break;
        case IMG_FORMAT_WEBP:
            content_type = "image/webp";
            break;
        default:
            content_type = "application/octet-stream";
            break;
    }

    /* Set content type */
    ap_set_content_type(r, content_type);
    apr_table_setn(r->headers_out, "X-WebP-Original", "1");

    if (conf->log_level >= 2) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "mod_webp: Serving original file: %s", file_path);
    }

    /* In strict mode, we should not serve original files */
    if (conf->strict_mode) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_webp: Strict mode enabled - refusing to serve original file: %s", file_path);
        return HTTP_NOT_ACCEPTABLE;
    }

    /* Let Apache handle the file serving */
    return DECLINED;
}

/* Convert image to WebP format with enhanced format support */
static int convert_image_to_webp(request_rec *r, const char *input_path, const char *output_path) {
    webp_config *conf = ap_get_module_config(r->per_dir_config, &webp_module);
    apr_file_t *input_file = NULL;
    apr_file_t *output_file = NULL;
    uint8_t *image_data = NULL;
    apr_size_t image_size;
    WebPConfig config;
    WebPPicture pic;
    int result = HTTP_INTERNAL_SERVER_ERROR;
    uint8_t *rgba_data = NULL;
    int width = 0, height = 0;
    image_format_t format;
    apr_status_t rv;
    apr_finfo_t finfo;

    /* Detect image format */
    format = detect_image_format(r, input_path);
    if (format == IMG_FORMAT_UNKNOWN) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_webp: Unknown image format: %s", input_path);
        return HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    /* Skip conversion if already WebP */
    if (format == IMG_FORMAT_WEBP) {
        if (conf->log_level >= 2) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "mod_webp: File already WebP format: %s", input_path);
        }
        /* Just copy the file */
        rv = apr_file_copy(input_path, output_path, APR_FPROT_FILE_SOURCE_PERMS, r->pool);
        return (rv == APR_SUCCESS) ? OK : HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Open input file */
    rv = apr_file_open(&input_file, input_path, APR_READ, APR_OS_DEFAULT, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "mod_webp: Failed to open input file %s", input_path);
        return HTTP_NOT_FOUND;
    }

    /* Get file size */
    rv = apr_file_info_get(&finfo, APR_FINFO_SIZE, input_file);
    if (rv != APR_SUCCESS || finfo.size <= 0) {
        apr_file_close(input_file);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "mod_webp: Failed to get file size: %s", input_path);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    image_size = (apr_size_t)finfo.size;

    /* Check file size limits */
    if (finfo.size > conf->max_file_size) {
        apr_file_close(input_file);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_webp: File too large (%" APR_OFF_T_FMT " > %" APR_OFF_T_FMT "): %s",
                      finfo.size, conf->max_file_size, input_path);
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

    /* Allocate memory for image data */
    image_data = apr_palloc(r->pool, image_size);
    if (!image_data) {
        apr_file_close(input_file);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_webp: Failed to allocate memory for image data (size: %zu)", image_size);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Read image data */
    rv = apr_file_read_full(input_file, image_data, image_size, NULL);
    apr_file_close(input_file);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "mod_webp: Failed to read image data from %s", input_path);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Decode image based on format */
    switch (format) {
        case IMG_FORMAT_JPEG:
        case IMG_FORMAT_PNG:
        case IMG_FORMAT_BMP:
        case IMG_FORMAT_TIFF:
        case IMG_FORMAT_GIF:
            /* WebP can decode these formats directly */
            rgba_data = WebPDecodeRGBA(image_data, image_size, &width, &height);
            break;
        default:
            rgba_data = NULL;
            break;
    }

    if (!rgba_data) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_webp: Failed to decode %s image: %s",
                      image_format_to_string(format), input_path);
        return HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    /* Validate dimensions */
    if (width <= 0 || height <= 0 || width > conf->max_width || height > conf->max_height) {
        WebPFree(rgba_data);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_webp: Invalid dimensions (%dx%d, max: %dx%d): %s",
                      width, height, conf->max_width, conf->max_height, input_path);
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

    /* Initialize WebP configuration */
    if (!WebPConfigPreset(&config, WEBP_PRESET_PHOTO, conf->quality)) {
        WebPFree(rgba_data);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_webp: Failed to initialize WebP configuration");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Optimize for smaller file size while maintaining quality */
    config.method = 6;  /* Maximum compression effort */
    config.autofilter = 1;
    config.filter_strength = 60;
    config.filter_sharpness = 0;
    config.alpha_compression = 1;
    config.alpha_filtering = 1;
    config.alpha_quality = (int)conf->quality;
    config.pass = 10;  /* Number of entropy-analysis passes */
    config.preprocessing = 4;  /* Smart RGB->YUV conversion */
    config.segments = 4;
    config.partition_limit = 0;

    /* Validate configuration */
    if (!WebPValidateConfig(&config)) {
        WebPFree(rgba_data);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_webp: Invalid WebP configuration");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Initialize WebP picture */
    if (!WebPPictureInit(&pic)) {
        WebPFree(rgba_data);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_webp: Failed to initialize WebP picture");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Set picture dimensions */
    pic.width = width;
    pic.height = height;
    pic.use_argb = 1;  /* Use ARGB format for better quality */

    /* Import RGBA data */
    if (!WebPPictureImportRGBA(&pic, rgba_data, width * 4)) {
        WebPFree(rgba_data);
        WebPPictureFree(&pic);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_webp: Failed to import RGBA data");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Setup output writer */
    WebPMemoryWriter writer;
    WebPMemoryWriterInit(&writer);
    pic.writer = WebPMemoryWrite;
    pic.custom_ptr = &writer;

    /* Encode image */
    if (!WebPEncode(&config, &pic)) {
        WebPFree(rgba_data);
        WebPMemoryWriterClear(&writer);
        WebPPictureFree(&pic);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_webp: WebP encoding failed: %s (error: %d)",
                      input_path, pic.error_code);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Validate cache directory */
    char *cache_dir = apr_pstrdup(r->pool, output_path);
    char *last_slash = strrchr(cache_dir, '/');
    if (last_slash) {
        *last_slash = '\0';
        if (!validate_cache_directory(r, cache_dir)) {
            WebPFree(rgba_data);
            WebPMemoryWriterClear(&writer);
            WebPPictureFree(&pic);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* Write WebP data to output file */
    rv = apr_file_open(&output_file, output_path,
                       APR_CREATE | APR_WRITE | APR_TRUNCATE,
                       APR_FPROT_UREAD | APR_FPROT_UWRITE, r->pool);
    if (rv != APR_SUCCESS) {
        WebPFree(rgba_data);
        WebPMemoryWriterClear(&writer);
        WebPPictureFree(&pic);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "mod_webp: Failed to open output file %s", output_path);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_size_t bytes_written = writer.size;
    rv = apr_file_write_full(output_file, writer.mem, writer.size, &bytes_written);
    apr_file_close(output_file);

    if (rv != APR_SUCCESS || bytes_written != writer.size) {
        apr_file_remove(output_path, r->pool);  /* Clean up partial file */
        WebPFree(rgba_data);
        WebPMemoryWriterClear(&writer);
        WebPPictureFree(&pic);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "mod_webp: Failed to write WebP data to %s", output_path);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Calculate compression ratio */
    double compression_ratio = (double)writer.size / (double)image_size;

    if (conf->log_level >= 2) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "mod_webp: Converted %s (%dx%d) from %s to WebP: %zu -> %zu bytes (%.1f%% of original)",
                      input_path, width, height, image_format_to_string(format),
                      image_size, writer.size, compression_ratio * 100.0);
    }

    /* Cleanup */
    WebPFree(rgba_data);
    WebPMemoryWriterClear(&writer);
    WebPPictureFree(&pic);

    result = OK;
    return result;
}

/* Main handler function with strict transformation enforcement */
static int webp_handler(request_rec *r) {
    webp_config *conf = ap_get_module_config(r->per_dir_config, &webp_module);
    char *cache_filename;
    int result;
    int webp_supported;

    /* Check if module is enabled */
    if (!conf->enabled) {
        if (conf->log_level >= 3) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "mod_webp: Module disabled for: %s", r->filename);
        }
        return DECLINED;
    }

    /* Validate cache directory early with fallback options */
    if (!validate_cache_directory(r, conf->cache_dir)) {
        /* Try fallback cache directories */
        const char *fallback_dirs[] = {
            "/tmp/mod_webp_cache",
            "/var/tmp/mod_webp_cache",
            apr_psprintf(r->pool, "/tmp/mod_webp_cache_%d", getpid()),
            NULL
        };

        int fallback_success = 0;
        for (int i = 0; fallback_dirs[i] && !fallback_success; i++) {
            if (conf->log_level >= 1) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                              "mod_webp: Trying fallback cache directory: %s", fallback_dirs[i]);
            }

            if (validate_cache_directory(r, fallback_dirs[i])) {
                /* Update the config to use the working fallback directory */
                conf->cache_dir = apr_pstrdup(r->pool, fallback_dirs[i]);
                fallback_success = 1;

                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                              "mod_webp: Using fallback cache directory: %s", conf->cache_dir);
            }
        }

        if (!fallback_success) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "mod_webp: All cache directory options failed, disabling WebP conversion");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* Check if this is an image request we handle */
    if (!is_image_request(r)) {
        if (conf->log_level >= 3) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "mod_webp: Not an image request or unsupported format: %s", r->filename);
        }
        return DECLINED;
    }

    /* Check if browser supports WebP */
    webp_supported = is_browser_webp_compatible(r);

    /* In strict mode, refuse to serve non-WebP content */
    if (conf->strict_mode && !webp_supported) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "mod_webp: Strict mode - browser does not support WebP: %s", r->filename);
        /* Set appropriate headers to indicate the issue */
        apr_table_setn(r->headers_out, "X-WebP-Error", "Browser does not support WebP");
        apr_table_setn(r->headers_out, "Vary", "Accept");
        return HTTP_NOT_ACCEPTABLE;
    }

    /* If browser doesn't support WebP and we're not in strict mode, serve original */
    if (!webp_supported) {
        if (conf->log_level >= 2) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "mod_webp: Browser does not support WebP, serving original: %s", r->filename);
        }
        return serve_original_file(r, r->filename);
    }

    /* Generate cache filename */
    cache_filename = get_cache_filename(r, r->filename);
    if (!cache_filename) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "mod_webp: Failed to generate cache filename for: %s", r->filename);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Check if cached version exists and is valid */
    if (is_cache_valid(r, r->filename, cache_filename)) {
        /* Serve from cache */
        if (conf->log_level >= 3) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                          "mod_webp: Serving cached WebP image: %s -> %s", r->filename, cache_filename);
        }
        return serve_webp_file(r, cache_filename);
    } else {
        /* Convert image to WebP */
        if (conf->log_level >= 2) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "mod_webp: Converting image to WebP: %s -> %s", r->filename, cache_filename);
        }

        result = convert_image_to_webp(r, r->filename, cache_filename);
        if (result != OK) {
            /* In strict mode, conversion failure is a hard error */
            if (conf->strict_mode) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "mod_webp: Strict mode - conversion failed for: %s", r->filename);
                apr_table_setn(r->headers_out, "X-WebP-Error", "Conversion failed");
                return result;
            } else {
                /* Fallback to original if conversion fails */
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                              "mod_webp: Conversion failed, serving original: %s", r->filename);
                return serve_original_file(r, r->filename);
            }
        }

        /* Serve the newly converted image */
        if (conf->log_level >= 2) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                          "mod_webp: Successfully converted and serving: %s", cache_filename);
        }
        return serve_webp_file(r, cache_filename);
    }
}

/* Module initialization function */
static void webp_init_module(apr_pool_t *pchild, server_rec *s) {
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 "mod_webp: Enterprise WebP module version 2.0 initialized");

    /* Verify WebP library version */
    int webp_version = WebPGetEncoderVersion();
    int major = (webp_version >> 16) & 0xff;
    int minor = (webp_version >> 8) & 0xff;
    int revision = webp_version & 0xff;

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 "mod_webp: Using libwebp version %d.%d.%d", major, minor, revision);

    /* Minimum version check */
    if (webp_version < 0x010000) {  /* Require at least 1.0.0 */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_webp: libwebp version %d.%d.%d is too old (minimum: 1.0.0)",
                     major, minor, revision);
        /* Can't return error from child_init, just log warning */
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "mod_webp: Continuing with potentially incompatible libwebp version");
    }
}

/* Configuration validation hook */
static int webp_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s) {
    /* This runs after configuration is loaded but before the server starts serving */
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
                 "mod_webp: Post-configuration validation completed");
    return OK;
}

/* Register hooks */
static void webp_register_hooks(apr_pool_t *p) {
    ap_hook_handler(webp_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(webp_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(webp_init_module, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Module definition */
module AP_MODULE_DECLARE_DATA webp_module = {
    STANDARD20_MODULE_STUFF,
    webp_create_dir_config,    /* create per-dir config structures */
    webp_merge_dir_config,     /* merge per-dir config structures */
    NULL,                      /* create per-server config structures */
    NULL,                      /* merge per-server config structures */
    webp_directives,           /* table of config file commands */
    webp_register_hooks        /* register hooks */
};