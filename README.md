# Apache2 WebP Module

An Apache2 module that automatically converts images (JPEG, PNG) to WebP format on-the-fly, caches the converted images, and serves them with the proper MIME type while maintaining the original URI.

## Features

- Automatically converts JPEG and PNG images to WebP format
- Caches converted images to avoid repeated processing
- Serves WebP images with `image/webp` MIME type
- Maintains original URIs (no URL changes required)
- Configurable quality settings
- Browser compatibility detection

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

Add the following to your Apache configuration:

```apache
# Enable WebP conversion for image directories
<Directory "/var/www/images">
    # Enable WebP conversion
    WebPEnabled On
    
    # Set WebP quality (0-100)
    WebPQuality 85.0
    
    # Set cache directory for converted images
    WebPCacheDir /tmp/webp_cache
    
    # Apply to image files
    <FilesMatch "\.(jpe?g|png)$">
        # Set handler for image conversion
        SetHandler webp-handler
    </FilesMatch>
</Directory>
```

Make sure the cache directory exists and is writable by the Apache user:

```bash
mkdir -p /tmp/webp_cache
chown www-data:www-data /tmp/webp_cache
chmod 755 /tmp/webp_cache
```

## How It Works

1. When a browser requests an image (JPEG or PNG), the module checks if the browser supports WebP
2. If WebP is supported, the module checks for a cached WebP version
3. If no valid cache exists, the original image is converted to WebP format
4. The WebP image is served with the `image/webp` MIME type
5. The converted image is cached for future requests

## Browser Support

The module automatically detects browser WebP support by checking the `Accept` header. 
Browsers that don't support WebP will receive the original image format as usual.

## License

MIT License - See [LICENSE](LICENSE) file for details.

This Apache module automatically converts JPEG and PNG images to WebP format on-the-fly, reducing bandwidth usage while maintaining image quality.

## Features

- Automatically converts JPEG and PNG images to WebP format
- Caches converted images to avoid repeated conversions
- Respects browser WebP support through Accept header detection
- Configurable quality settings
- Works with existing Apache configurations

## Requirements

- Apache 2.4+
- libwebp development libraries
- Apache development headers (apxs)

### Ubuntu/Debian
```bash
sudo apt-get install libwebp-dev apache2-dev
```

### CentOS/RHEL
```bash
sudo yum install libwebp-devel httpd-devel
```

### Windows
- Apache with development headers (e.g., from ApacheLounge)
- libwebp development libraries for Windows

## Building

### Linux/Unix
```bash
./build.sh
# or manually:
make
```

### Windows
```cmd
build.bat
# or manually:
nmake -f Makefile.win
```

## Installation

After building, install the module:

```bash
sudo make install
# or on Windows:
# nmake -f Makefile.win install
```

This will install the module and automatically add a LoadModule directive to your Apache configuration.

## Configuration

Add the following to your Apache configuration (httpd.conf or virtual host config):

```apache
# Enable WebP conversion for image directories
<Directory "/var/www/images">
    # Enable WebP conversion
    WebPEnabled On
    
    # Set WebP quality (0-100)
    WebPQuality 85.0
    
    # Set cache directory for converted images
    WebPCacheDir /tmp/webp_cache
    
    # Apply to image files
    <FilesMatch "\.(jpe?g|png)$">
        SetHandler webp-handler
    </FilesMatch>
</Directory>
```

Create the cache directory and ensure Apache has write permissions:
```bash
mkdir -p /tmp/webp_cache
chown www-data:www-data /tmp/webp_cache
chmod 755 /tmp/webp_cache
```

## How It Works

1. When a browser requests a JPEG or PNG image, the module checks if the browser supports WebP by examining the Accept header
2. If WebP is supported, the module checks if a cached WebP version exists
3. If no cached version exists or the cached version is outdated, the original image is converted to WebP
4. The WebP version is served with the correct Content-Type header
5. Subsequent requests for the same image will use the cached version

## Browser Support

The module respects browser WebP support by checking the Accept header. Browsers that don't support WebP will receive the original image format.

WebP support:
- Chrome 32+ (enabled by default)
- Firefox 65+ (enabled by default)
- Edge 18+ (enabled by default)
- Opera 19+ (enabled by default)
- Safari (limited support)

## Performance Considerations

- The first request to convert an image may take longer as the conversion happens on-the-fly
- Subsequent requests use cached versions for better performance
- Adjust the WebPQuality setting to balance file size and image quality
- Monitor disk usage as cached files accumulate over time

## Troubleshooting

### Module won't load
Ensure that the module is correctly compiled for your Apache version and architecture.

### Images not converting
Check that:
1. WebPEnabled is set to On
2. The browser supports WebP (check Accept header)
3. The cache directory is writable by Apache
4. The requested files match the FilesMatch pattern

### Log messages
Check Apache error logs for any mod_webp related messages:
```bash
tail -f /var/log/apache2/error.log
```

## License

MIT License

Copyright (c) 2025 AGSQ11

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.