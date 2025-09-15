/**
 * mod_webp.c: Apache module for on-the-fly image conversion to WebP format
 *
 * Copyright 2025 AGSQ11
 * MIT License
 */

#include "apr_hash.h"
#include "apr_strings.h"
#include "apr_file_info.h"
#include "apr_file_io.h"
#include "apr_time.h"
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

/* libwebp includes */
#include <webp/encode.h>
#include <webp/decode.h>

module AP_MODULE_DECLARE_DATA webp_module;

/* Configuration structure */
typedef struct {
    int enabled;
    float quality;
    char *cache_dir;
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

/* Configuration directives */
static const command_rec webp_directives[] = {
    AP_INIT_TAKE1("WebPQuality", ap_set_float_slot,
                  (void *)APR_OFFSETOF(webp_config, quality),
                  OR_FILEINFO, "Set WebP quality (0.0-100.0)"),
    AP_INIT_FLAG("WebPEnabled", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(webp_config, enabled),
                 OR_FILEINFO, "Enable or disable WebP conversion"),
    AP_INIT_TAKE1("WebPCacheDir", ap_set_string_slot,
                  (void *)APR_OFFSETOF(webp_config, cache_dir),
                  OR_FILEINFO, "Set cache directory for WebP images"),
    {NULL}
};

/* Create directory configuration */
static void *webp_create_dir_config(apr_pool_t *p, char *dummy) {
    webp_config *conf = apr_pcalloc(p, sizeof(webp_config));
    
    conf->enabled = 1;  /* Enabled by default */
    conf->quality = 80.0;  /* Default quality */
    conf->cache_dir = "/tmp/webp_cache";  /* Default cache directory */
    
    return conf;
}

/* Merge directory configuration */
static void *webp_merge_dir_config(apr_pool_t *p, void *basev, void *overridesv) {
    webp_config *base = (webp_config *)basev;
    webp_config *overrides = (webp_config *)overridesv;
    webp_config *conf = apr_pcalloc(p, sizeof(webp_config));
    
    conf->enabled = (overrides->enabled != -1) ? overrides->enabled : base->enabled;
    conf->quality = (overrides->quality != -1) ? overrides->quality : base->quality;
    conf->cache_dir = (overrides->cache_dir) ? overrides->cache_dir : base->cache_dir;
    
    return conf;
}

/* Check if browser supports WebP */
static int is_browser_webp_compatible(request_rec *r) {
    const char *accept_header = apr_table_get(r->headers_in, "Accept");
    
    if (accept_header && strstr(accept_header, "image/webp")) {
        return 1;
    }
    
    return 0;
}

/* Generate cache filename */
static char *get_cache_filename(request_rec *r, const char *input_path) {
    webp_config *conf = ap_get_module_config(r->per_dir_config, &webp_module);
    unsigned long hash = 0;
    const char *p;
    
    /* Simple hash function for the filename */
    for (p = input_path; *p; p++) {
        hash = hash * 31 + *p;
    }
    
    return apr_psprintf(r->pool, "%s/%lu.webp", conf->cache_dir, hash);
}

/* Check if cached version is valid */
static int is_cache_valid(request_rec *r, const char *original_file, const char *cache_file) {
    apr_finfo_t orig_info, cache_info;
    
    /* Get original file info */
    if (apr_stat(&orig_info, original_file, APR_FINFO_MTIME, r->pool) != APR_SUCCESS) {
        return 0;
    }
    
    /* Get cache file info */
    if (apr_stat(&cache_info, cache_file, APR_FINFO_MTIME, r->pool) != APR_SUCCESS) {
        return 0;
    }
    
    /* Cache is valid if it's newer than the original file */
    return (cache_info.mtime >= orig_info.mtime);
}

/* Serve WebP file to client */
static int serve_webp_file(request_rec *r, const char *webp_path) {
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
    
    /* Set content type */
    ap_set_content_type(r, "image/webp");
    
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
    
    return OK;
}

/* Convert image to WebP format */
static int convert_image_to_webp(request_rec *r, const char *input_path, const char *output_path) {
    webp_config *conf = ap_get_module_config(r->per_dir_config, &webp_module);
    FILE *input_file = NULL;
    uint8_t *image_data = NULL;
    size_t image_size;
    WebPConfig config;
    WebPPicture pic;
    int result = HTTP_INTERNAL_SERVER_ERROR;
    uint8_t *rgba_data = NULL;
    int width = 0, height = 0;
    VP8StatusCode decode_status;
    
    /* Open input file */
    input_file = fopen(input_path, "rb");
    if (!input_file) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                      "mod_webp: Failed to open input file %s", input_path);
        return HTTP_NOT_FOUND;
    }
    
    /* Get file size */
    fseek(input_file, 0, SEEK_END);
    image_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);
    
    /* Allocate memory for image data */
    image_data = apr_palloc(r->pool, image_size);
    if (!image_data) {
        fclose(input_file);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                      "mod_webp: Failed to allocate memory for image data");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    /* Read image data */
    if (fread(image_data, 1, image_size, input_file) != image_size) {
        fclose(input_file);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                      "mod_webp: Failed to read image data from %s", input_path);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    fclose(input_file);
    
    /* Try to decode as JPEG first */
    rgba_data = WebPDecodeRGBA(image_data, image_size, &width, &height);
    if (!rgba_data) {
        /* Try to decode as PNG */
        rgba_data = WebPDecodeRGBA(image_data, image_size, &width, &height);
        if (!rgba_data) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                          "mod_webp: Failed to decode image %s", input_path);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    
    /* Initialize WebP configuration */
    if (!WebPConfigPreset(&config, WEBP_PRESET_PHOTO, conf->quality)) {
        WebPFree(rgba_data);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                      "mod_webp: Failed to initialize WebP configuration");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    
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
    if (WebPEncode(&config, &pic)) {
        /* Write WebP data to output file */
        FILE *output_file = fopen(output_path, "wb");
        if (output_file) {
            if (fwrite(writer.mem, 1, writer.size, output_file) == writer.size) {
                result = OK;
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                              "mod_webp: Failed to write WebP data to %s", output_path);
            }
            fclose(output_file);
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                          "mod_webp: Failed to open output file %s", output_path);
        }
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, 
                      "mod_webp: Failed to encode image to WebP format");
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
    apr_finfo_t cache_info;
    
    /* Check if module is enabled */
    if (!conf->enabled) {
        return DECLINED;
    }
    
    /* Check if browser supports WebP */
    if (!is_browser_webp_compatible(r)) {
        return DECLINED;
    }
    
    /* Check if this is an image request we handle */
    if (r->filename && 
        (strstr(r->filename, ".jpg") || strstr(r->filename, ".jpeg") || 
         strstr(r->filename, ".png"))) {
        
        /* Generate cache filename */
        cache_filename = get_cache_filename(r, r->filename);
        
        /* Check if cached version exists and is valid */
        if (is_cache_valid(r, r->filename, cache_filename)) {
            /* Serve from cache */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                          "mod_webp: Serving cached WebP image %s", cache_filename);
            return serve_webp_file(r, cache_filename);
        } else {
            /* Convert image to WebP */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
                          "mod_webp: Converting image %s to WebP", r->filename);
            
            result = convert_image_to_webp(r, r->filename, cache_filename);
            if (result != OK) {
                return result;
            }
            
            /* Serve the newly converted image */
            return serve_webp_file(r, cache_filename);
        }
    }
    
    return DECLINED;
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