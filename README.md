# Enterprise Apache2 WebP Module

An enterprise-grade Apache2 module that provides strict, secure, and comprehensive automatic image conversion to WebP format. This module ensures that **NO IMAGE ESCAPES TRANSFORMATION** when properly configured, making it ideal for production environments that require guaranteed WebP delivery.

## 🚀 Enhanced Features

### Core Functionality
- **Universal Image Support**: Converts JPEG, PNG, BMP, TIFF, GIF to WebP format
- **Strict Mode Enforcement**: Ensures NO images escape conversion (enterprise-grade)
- **Magic Number Detection**: Secure format detection using file signatures
- **Intelligent Caching**: MD5-based cache validation with configurable timeouts
- **Production-Ready Logging**: Configurable log levels (ERROR, WARN, INFO, DEBUG)

### Security & Enterprise Features
- **Content-Type Validation**: Prevents file type confusion attacks
- **File Size Limits**: Configurable maximum file size and dimensions
- **Cache Directory Validation**: Automatic creation and permission checking
- **Comprehensive Error Handling**: Detailed error reporting and fallback mechanisms
- **Format Whitelisting**: Configurable allowed image formats
- **HTTP Headers**: Proper caching and security headers

## Requirements

- Apache 2.4+
- libwebp development libraries
- Apache development tools (apxs)

## Installation

### Ubuntu/Debian

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install apache2-dev libwebp-dev

# Build and install the module
./build.sh
sudo make install
```

### CentOS/RHEL

```bash
# Install dependencies
sudo yum install httpd-devel libwebp-devel

# Build and install the module
./build.sh
sudo make install
```

### Windows

```cmd
# Install Apache with development headers (e.g., from ApacheLounge)
# Install libwebp development libraries

# Build the module
build.bat
nmake -f Makefile.win install
```

## Configuration

### Basic Configuration

```apache
# Load the module
LoadModule webp_module modules/mod_webp.so

# Basic WebP conversion
<Directory "/var/www/images">
    WebPEnabled On
    WebPStrictMode Off          # Allow fallback to original
    WebPQuality 85.0
    WebPCacheDir /var/cache/mod_webp
    WebPMaxFileSize 52428800    # 50MB
    WebPLogLevel 2              # INFO level
    WebPAllowedFormats "jpeg,png,bmp,tiff,gif"

    # Apply to all image files
    <FilesMatch "\.(jpe?g|png|bmp|tiff?|gif|webp)$">
        SetHandler webp-handler
    </FilesMatch>
</Directory>
```

### Enterprise Strict Mode Configuration

```apache
# ENTERPRISE MODE - NO IMAGES ESCAPE CONVERSION
<Directory "/var/www/enterprise">
    WebPEnabled On
    WebPStrictMode On           # STRICT: NO fallback allowed
    WebPQuality 90.0            # High quality
    WebPCacheDir /var/cache/mod_webp_enterprise
    WebPMaxFileSize 104857600   # 100MB
    WebPMaxWidth 32768
    WebPMaxHeight 32768
    WebPCacheTimeout 7200       # 2 hours
    WebPLogLevel 1              # WARN level for production
    WebPAllowedFormats "jpeg,png,bmp,tiff,gif"

    <FilesMatch "\.(jpe?g|png|bmp|tiff?|gif)$">
        SetHandler webp-handler

        # Security: Block non-WebP browsers in strict mode
        SetEnvIf Accept "image/webp" webp_supported
        Order allow,deny
        Allow from env=webp_supported
        Deny from all
        ErrorDocument 403 "WebP support required"
    </FilesMatch>
</Directory>
```

### Advanced Configuration Directives

| Directive | Default | Description |
|-----------|---------|-------------|
| `WebPEnabled` | On | Enable/disable WebP conversion |
| `WebPStrictMode` | On | Strict mode: no images escape conversion |
| `WebPQuality` | 85.0 | WebP quality (0.0-100.0) |
| `WebPCacheDir` | `/var/cache/mod_webp` | Cache directory path |
| `WebPMaxFileSize` | 52428800 | Maximum file size (bytes) |
| `WebPMaxWidth` | 16384 | Maximum image width |
| `WebPMaxHeight` | 16384 | Maximum image height |
| `WebPCacheTimeout` | 3600 | Cache validity (seconds) |
| `WebPLogLevel` | 1 | Log level (0=ERROR, 1=WARN, 2=INFO, 3=DEBUG) |
| `WebPAllowedFormats` | "jpeg,png,bmp,tiff,gif" | Allowed input formats |

### Cache Directory Setup

```bash
# Create enterprise cache directory
sudo mkdir -p /var/cache/mod_webp_enterprise
sudo chown www-data:www-data /var/cache/mod_webp_enterprise
sudo chmod 755 /var/cache/mod_webp_enterprise
```

## How It Works

### Standard Mode (WebPStrictMode Off)
1. Browser requests an image (JPEG, PNG, BMP, TIFF, GIF)
2. Module detects image format using magic number validation
3. Checks browser WebP support via Accept header
4. If WebP supported: converts and serves WebP
5. If WebP not supported: serves original format
6. Caches converted images with MD5-based filenames

### Strict Mode (WebPStrictMode On) - **Enterprise Grade**
1. Browser requests an image
2. Module validates image format and security constraints
3. **STRICT ENFORCEMENT**: Only WebP-capable browsers get content
4. Non-WebP browsers receive HTTP 406 Not Acceptable
5. **NO IMAGES ESCAPE**: All images MUST be converted to WebP
6. Failed conversions return errors (no fallback)
7. Comprehensive logging for security auditing

## Browser Support & Strict Mode Behavior

### WebP-Compatible Browsers (Allowed in Strict Mode)
- Chrome 32+ ✅
- Firefox 65+ ✅
- Edge 18+ ✅
- Opera 19+ ✅
- Safari 14+ ✅

### Non-WebP Browsers (Blocked in Strict Mode)
- Internet Explorer ❌ → HTTP 406
- Old Safari versions ❌ → HTTP 406
- Legacy browsers ❌ → HTTP 406

### Detection Methods
1. **Primary**: `Accept: image/webp` header
2. **Fallback**: User-Agent string analysis
3. **Strict Mode**: No fallback - WebP required

## 🔧 Enterprise Deployment

### Production Configuration Examples

See included configuration files:
- `enterprise.conf` - Full enterprise configuration with strict mode
- `test-strict.conf` - Strict mode testing configuration
- `test.conf` - Basic compatibility mode configuration

### Monitoring & Logging

```apache
# Enable detailed logging
LogLevel info ssl:warn webp:debug

# Separate log files for WebP operations
ErrorLog /var/log/apache2/webp_error.log
CustomLog /var/log/apache2/webp_access.log combined

# Monitor rejected requests in strict mode
CustomLog /var/log/apache2/webp_rejected.log combined env=!webp_supported
```

### Performance Tuning

```apache
# High-traffic optimizations
WebPCacheTimeout 86400      # 24-hour cache
WebPQuality 85.0           # Balance quality/size
WebPMaxFileSize 20971520   # 20MB limit

# CDN-friendly headers
Header set Cache-Control "public, max-age=31536000, immutable"
Header set Vary "Accept"
```

## 🔒 Security Features

### Input Validation
- **Magic Number Verification**: Prevents file type confusion attacks
- **File Size Limits**: Configurable maximum file sizes
- **Dimension Limits**: Maximum width/height validation
- **Format Whitelisting**: Restrict allowed input formats

### Cache Security
- **Secure Filenames**: MD5-based cache file naming
- **Directory Validation**: Automatic permission checking
- **Atomic Writes**: Prevents partial file corruption
- **Cleanup on Failure**: Removes incomplete conversions

### HTTP Security Headers
```apache
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
```

## 🛠️ Troubleshooting

### Common Issues

#### Module Won't Load
```bash
# Check module dependencies
ldd /usr/lib/apache2/modules/mod_webp.so

# Verify libwebp version
apachectl -M | grep webp
```

#### Images Not Converting
1. **Check WebP Support Detection**:
   ```bash
   curl -H "Accept: image/webp" http://your-site/image.jpg -v
   ```

2. **Verify File Permissions**:
   ```bash
   ls -la /var/cache/mod_webp/
   sudo -u www-data touch /var/cache/mod_webp/test
   ```

3. **Debug Logging**:
   ```apache
   WebPLogLevel 3  # Enable debug logging
   ```

#### Strict Mode Rejections
```apache
# Monitor rejected requests
tail -f /var/log/apache2/webp_rejected.log

# Check browser support
grep "HTTP_NOT_ACCEPTABLE" /var/log/apache2/error.log
```

### Error Codes

| HTTP Status | Meaning | Solution |
|-------------|---------|----------|
| 406 Not Acceptable | Browser doesn't support WebP (strict mode) | Upgrade browser or disable strict mode |
| 413 Request Entity Too Large | File exceeds size limits | Increase `WebPMaxFileSize` |
| 415 Unsupported Media Type | Invalid image format | Check `WebPAllowedFormats` |
| 500 Internal Server Error | Conversion failed | Check error logs, verify libwebp |

### Performance Monitoring

```bash
# Monitor cache hit rates
awk '/webp.*cache/ {hit++} /webp.*convert/ {miss++} END {print "Hit rate:", hit/(hit+miss)*100"%"}' /var/log/apache2/access.log

# Track conversion times
grep "mod_webp.*Converted" /var/log/apache2/error.log | awk '{print $NF}' | sort -n

# Monitor disk usage
du -sh /var/cache/mod_webp*
```

## 🧪 Testing

### Basic Functionality Test
```bash
# Test WebP conversion
curl -H "Accept: image/webp" -o test.webp http://your-site/image.jpg
file test.webp  # Should show "RIFF (little-endian) data, Web/P image"

# Test strict mode rejection
curl -H "Accept: image/jpeg" http://your-site/image.jpg -v  # Should return 406
```

### Load Testing
```bash
# Test cache performance
ab -n 1000 -c 10 -H "Accept: image/webp" http://your-site/image.jpg

# Test strict mode under load
ab -n 100 -c 5 -H "Accept: image/jpeg" http://your-site/image.jpg
```

## 📊 Enterprise Benefits

### Bandwidth Savings
- **30-50% smaller files** compared to JPEG
- **20-30% smaller files** compared to PNG
- **Consistent quality** at lower file sizes

### Performance Improvements
- **Faster page load times** due to smaller images
- **Reduced CDN costs** from bandwidth savings
- **Better user experience** on mobile networks

### Security Compliance
- **Strict content type enforcement**
- **No file type confusion vulnerabilities**
- **Comprehensive audit logging**
- **Controlled format acceptance**

## License

MIT License - See [LICENSE](LICENSE) file for details.

Copyright (c) 2025 AGSQ11 - Enterprise-grade WebP conversion for Apache2