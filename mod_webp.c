/**
 * mod_webp_safe.c: Crash-proof Apache module for WebP conversion
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
#include "ap_config.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_filter.h"
#include "apr_buckets.h"

/* libwebp includes */
#include <webp/encode.h>
#include <webp/decode.h>

/* System includes */
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

/* Image format detection magic numbers */
#define JPEG_MAGIC_1 0xFF
#define JPEG_MAGIC_2 0xD8
#define PNG_MAGIC_SIZE 8
static const unsigned char PNG_MAGIC[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
static const unsigned char BMP_MAGIC[] = {0x42, 0x4D};
static const unsigned char WEBP_MAGIC[] = {0x52, 0x49, 0x46, 0x46};

/* Image format enumeration */
typedef enum {
    IMG_FORMAT_UNKNOWN = 0,
    IMG_FORMAT_JPEG,
    IMG_FORMAT_PNG,
    IMG_FORMAT_BMP,
    IMG_FORMAT_WEBP
} image_format_t;

/* Configuration structure */
typedef struct {
    int enabled;
    int strict_mode;
    float quality;
    char *cache_dir;
    apr_off_t max_file_size;
    int log_level;
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
static int ensure_cache_directory(request_rec *r, const char *cache_dir);
static const char *image_format_to_string(image_format_t format);

/* Custom function to set float values */
static const char *webp_set_float_slot(cmd_parms *cmd, void *struct_ptr, const char *arg) {
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
    if (*endptr != '\0' || val < 0 || val > (100LL * 1024 * 1024 * 1024)) {
        return "WebPMaxFileSize must be a number between 0 and 107374182400 (100GB)";
    }

    *(apr_off_t *)((char *)struct_ptr + (size_t)cmd->info) = val;
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
    AP_INIT_TAKE1("WebPLogLevel", ap_set_int_slot,
                  (void *)APR_OFFSETOF(webp_config, log_level),
                  OR_FILEINFO, "Set logging level (0=ERROR, 1=WARN, 2=INFO, 3=DEBUG)"),
    {NULL}
};

/* Create directory configuration */
static void *webp_create_dir_config(apr_pool_t *p, char *dummy) {
    webp_config *conf = apr_pcalloc(p, sizeof(webp_config));

    conf->enabled = 1;
    conf->strict_mode = 0;
    conf->quality = 85.0;
    conf->cache_dir = "/tmp/mod_webp_cache";
    conf->max_file_size = WEBP_MAX_FILE_SIZE;
    conf->log_level = 1;

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
    conf->log_level = (overrides->log_level != -1) ? overrides->log_level : base->log_level;

    return conf;
}

/* Convert image format enum to string */
static const char *image_format_to_string(image_format_t format) {
    switch (format) {
        case IMG_FORMAT_JPEG: return "JPEG";
        case IMG_FORMAT_PNG: return "PNG";
        case IMG_FORMAT_BMP: return "BMP";
        case IMG_FORMAT_WEBP: return "WebP";
        default: return "UNKNOWN";
    }
}

/* Detect image format by magic numbers */
static image_format_t detect_image_format(request_rec *r, const char *file_path) {
    apr_file_t *fd = NULL;
    apr_status_t rv;
    unsigned char magic[16];
    apr_size_t bytes_read = sizeof(magic);
    image_format_t format = IMG_FORMAT_UNKNOWN;

    if (!file_path || !*file_path) {
        return IMG_FORMAT_UNKNOWN;
    }

    rv = apr_file_open(&fd, file_path, APR_READ, APR_OS_DEFAULT, r->pool);
    if (rv != APR_SUCCESS) {
        return IMG_FORMAT_UNKNOWN;
    }

    rv = apr_file_read(fd, magic, &bytes_read);
    apr_file_close(fd);

    if (rv != APR_SUCCESS || bytes_read < 4) {
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
    /* WebP detection */
    else if (bytes_read >= 4 && memcmp(magic, WEBP_MAGIC, 4) == 0) {
        format = IMG_FORMAT_WEBP;
    }

    return format;
}

/* Validate image file size */
static int validate_image_file(request_rec *r, const char *file_path, image_format_t format) {
    webp_config *conf = ap_get_module_config(r->per_dir_config, &webp_module);
    apr_finfo_t finfo;
    apr_status_t rv;

    if (!file_path || !*file_path) {
        return 0;
    }

    rv = apr_stat(&finfo, file_path, APR_FINFO_SIZE, r->pool);
    if (rv != APR_SUCCESS) {
        return 0;
    }

    if (finfo.size > conf->max_file_size) {
        if (conf->log_level >= 1) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "mod_webp: File too large (%" APR_OFF_T_FMT " > %" APR_OFF_T_FMT "): %s",
                          finfo.size, conf->max_file_size, file_path);
        }
        return 0;
    }

    return (finfo.size > 0);
}

/* Check if this is an image request we should handle */
static int is_image_request(request_rec *r) {
    image_format_t format;

    if (!r || !r->filename) {
        return 0;
    }

    format = detect_image_format(r, r->filename);
    if (format == IMG_FORMAT_UNKNOWN || format == IMG_FORMAT_WEBP) {
        return 0;
    }

    return validate_image_file(r, r->filename, format);
}

/* Check if browser supports WebP */
static int is_browser_webp_compatible(request_rec *r) {
    const char *accept_header;

    if (!r) {
        return 0;
    }

    accept_header = apr_table_get(r->headers_in, "Accept");
    return (accept_header && strstr(accept_header, "image/webp")) ? 1 : 0;
}

/* Simple cache directory creation */
static int ensure_cache_directory(request_rec *r, const char *cache_dir) {
    apr_status_t rv;
    apr_finfo_t finfo;

    if (!cache_dir || !*cache_dir) {
        return 0;
    }

    /* Check if directory exists */
    rv = apr_stat(&finfo, cache_dir, APR_FINFO_TYPE, r->pool);
    if (rv == APR_SUCCESS && finfo.filetype == APR_DIR) {
        return 1;
    }

    /* Try to create directory */
    rv = apr_dir_make_recursive(cache_dir,
                               APR_FPROT_UREAD | APR_FPROT_UWRITE | APR_FPROT_UEXECUTE |
                               APR_FPROT_GREAD | APR_FPROT_GWRITE | APR_FPROT_GEXECUTE,
                               r->pool);

    return (rv == APR_SUCCESS) ? 1 : 0;
}

/* Generate cache filename */
static char *get_cache_filename(request_rec *r, const char *input_path) {
    webp_config *conf = ap_get_module_config(r->per_dir_config, &webp_module);
    apr_md5_ctx_t md5_ctx;
    unsigned char digest[APR_MD5_DIGESTSIZE];
    char *hex_digest;
    apr_finfo_t finfo;
    apr_status_t rv;

    if (!input_path || !*input_path || !conf || !conf->cache_dir) {
        return NULL;
    }

    rv = apr_stat(&finfo, input_path, APR_FINFO_MTIME | APR_FINFO_SIZE, r->pool);
    if (rv != APR_SUCCESS) {
        return NULL;
    }

    /* Create MD5 hash */
    apr_md5_init(&md5_ctx);
    apr_md5_update(&md5_ctx, input_path, strlen(input_path));
    apr_md5_update(&md5_ctx, &finfo.mtime, sizeof(finfo.mtime));
    apr_md5_update(&md5_ctx, &finfo.size, sizeof(finfo.size));
    apr_md5_update(&md5_ctx, &conf->quality, sizeof(conf->quality));
    apr_md5_final(digest, &md5_ctx);

    /* Convert to hex string */
    hex_digest = apr_palloc(r->pool, APR_MD5_DIGESTSIZE * 2 + 1);
    if (!hex_digest) {
        return NULL;
    }

    for (int i = 0; i < APR_MD5_DIGESTSIZE; i++) {
        sprintf(hex_digest + i * 2, "%02x", digest[i]);
    }
    hex_digest[APR_MD5_DIGESTSIZE * 2] = '\0';

    return apr_psprintf(r->pool, "%s/%s.webp", conf->cache_dir, hex_digest);
}

/* Check if cached version is valid */
static int is_cache_valid(request_rec *r, const char *original_file, const char *cache_file) {
    apr_finfo_t orig_info, cache_info;
    apr_status_t rv;

    if (!original_file || !cache_file) {
        return 0;
    }

    rv = apr_stat(&orig_info, original_file, APR_FINFO_MTIME, r->pool);
    if (rv != APR_SUCCESS) {
        return 0;
    }

    rv = apr_stat(&cache_info, cache_file, APR_FINFO_MTIME, r->pool);
    if (rv != APR_SUCCESS) {
        return 0;
    }

    return (cache_info.mtime >= orig_info.mtime) ? 1 : 0;
}

/* Serve WebP file to client */
static int serve_webp_file(request_rec *r, const char *webp_path) {
    apr_file_t *fd = NULL;
    apr_finfo_t finfo;
    apr_bucket_brigade *bb;
    apr_status_t rv;

    if (!webp_path || !*webp_path) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rv = apr_file_open(&fd, webp_path, APR_READ, APR_OS_DEFAULT, r->pool);
    if (rv != APR_SUCCESS) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rv = apr_file_info_get(&finfo, APR_FINFO_SIZE, fd);
    if (rv != APR_SUCCESS || finfo.size == 0) {
        apr_file_close(fd);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_set_content_type(r, "image/webp");
    apr_table_setn(r->headers_out, "Content-Length", apr_off_t_toa(r->pool, finfo.size));
    apr_table_setn(r->headers_out, "X-WebP-Converted", "1");

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    if (!bb) {
        apr_file_close(fd);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_bucket *bucket = apr_bucket_file_create(fd, 0, finfo.size, r->pool,
                                                r->connection->bucket_alloc);
    if (!bucket) {
        apr_file_close(fd);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    APR_BRIGADE_INSERT_TAIL(bb, bucket);

    bucket = apr_bucket_eos_create(r->connection->bucket_alloc);
    if (!bucket) {
        apr_file_close(fd);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    APR_BRIGADE_INSERT_TAIL(bb, bucket);

    rv = ap_pass_brigade(r->output_filters, bb);
    return (rv == APR_SUCCESS) ? OK : HTTP_INTERNAL_SERVER_ERROR;
}

/* Serve original file (fallback) */
static int serve_original_file(request_rec *r, const char *file_path) {
    webp_config *conf = ap_get_module_config(r->per_dir_config, &webp_module);

    if (conf && conf->strict_mode) {
        return HTTP_NOT_ACCEPTABLE;
    }

    return DECLINED;
}

/* Convert image to WebP format */
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

    if (!input_path || !output_path || !conf) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    format = detect_image_format(r, input_path);
    if (format == IMG_FORMAT_UNKNOWN) {
        return HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (format == IMG_FORMAT_WEBP) {
        rv = apr_file_copy(input_path, output_path, APR_FPROT_FILE_SOURCE_PERMS, r->pool);
        return (rv == APR_SUCCESS) ? OK : HTTP_INTERNAL_SERVER_ERROR;
    }

    rv = apr_file_open(&input_file, input_path, APR_READ, APR_OS_DEFAULT, r->pool);
    if (rv != APR_SUCCESS) {
        return HTTP_NOT_FOUND;
    }

    rv = apr_file_info_get(&finfo, APR_FINFO_SIZE, input_file);
    if (rv != APR_SUCCESS || finfo.size <= 0 || finfo.size > conf->max_file_size) {
        apr_file_close(input_file);
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

    image_size = (apr_size_t)finfo.size;
    image_data = apr_palloc(r->pool, image_size);
    if (!image_data) {
        apr_file_close(input_file);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rv = apr_file_read_full(input_file, image_data, image_size, NULL);
    apr_file_close(input_file);
    if (rv != APR_SUCCESS) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Decode image */
    rgba_data = WebPDecodeRGBA(image_data, image_size, &width, &height);
    if (!rgba_data || width <= 0 || height <= 0) {
        if (conf->log_level >= 1) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "mod_webp: Failed to decode %s image: %s",
                          image_format_to_string(format), input_path);
        }
        return HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    /* Initialize WebP configuration */
    if (!WebPConfigPreset(&config, WEBP_PRESET_PHOTO, conf->quality)) {
        WebPFree(rgba_data);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!WebPValidateConfig(&config)) {
        WebPFree(rgba_data);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Initialize WebP picture */
    if (!WebPPictureInit(&pic)) {
        WebPFree(rgba_data);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    pic.width = width;
    pic.height = height;

    if (!WebPPictureImportRGBA(&pic, rgba_data, width * 4)) {
        WebPFree(rgba_data);
        WebPPictureFree(&pic);
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
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Write WebP data to output file */
    rv = apr_file_open(&output_file, output_path,
                       APR_CREATE | APR_WRITE | APR_TRUNCATE,
                       APR_FPROT_UREAD | APR_FPROT_UWRITE, r->pool);
    if (rv != APR_SUCCESS) {
        WebPFree(rgba_data);
        WebPMemoryWriterClear(&writer);
        WebPPictureFree(&pic);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_size_t bytes_written = writer.size;
    rv = apr_file_write_full(output_file, writer.mem, writer.size, &bytes_written);
    apr_file_close(output_file);

    if (rv != APR_SUCCESS || bytes_written != writer.size) {
        apr_file_remove(output_path, r->pool);
        result = HTTP_INTERNAL_SERVER_ERROR;
    } else {
        result = OK;
    }

    /* Cleanup */
    WebPFree(rgba_data);
    WebPMemoryWriterClear(&writer);
    WebPPictureFree(&pic);

    return result;
}

/* Main handler function */
static int webp_handler(request_rec *r) {
    webp_config *conf = ap_get_module_config(r->per_dir_config, &webp_module);
    char *cache_filename;
    int result;
    int webp_supported;

    if (!conf || !conf->enabled || !r || !r->filename) {
        return DECLINED;
    }

    if (!is_image_request(r)) {
        return DECLINED;
    }

    webp_supported = is_browser_webp_compatible(r);

    if (conf->strict_mode && !webp_supported) {
        apr_table_setn(r->headers_out, "X-WebP-Error", "Browser does not support WebP");
        return HTTP_NOT_ACCEPTABLE;
    }

    if (!webp_supported) {
        return serve_original_file(r, r->filename);
    }

    if (!ensure_cache_directory(r, conf->cache_dir)) {
        /* Try fallback cache directories */
        const char *fallback_dirs[] = {
            "/tmp/mod_webp_cache",
            "/var/tmp/mod_webp_cache",
            NULL
        };

        for (int i = 0; fallback_dirs[i]; i++) {
            if (ensure_cache_directory(r, fallback_dirs[i])) {
                conf->cache_dir = apr_pstrdup(r->pool, fallback_dirs[i]);
                break;
            }
        }

        if (!ensure_cache_directory(r, conf->cache_dir)) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    cache_filename = get_cache_filename(r, r->filename);
    if (!cache_filename) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (is_cache_valid(r, r->filename, cache_filename)) {
        return serve_webp_file(r, cache_filename);
    } else {
        result = convert_image_to_webp(r, r->filename, cache_filename);
        if (result != OK) {
            if (conf->strict_mode) {
                return result;
            } else {
                return serve_original_file(r, r->filename);
            }
        }
        return serve_webp_file(r, cache_filename);
    }
}

/* Register hooks */
static void webp_register_hooks(apr_pool_t *p) {
    ap_hook_handler(webp_handler, NULL, NULL, APR_HOOK_MIDDLE);
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