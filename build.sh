#!/bin/bash
# build.sh - Build script for mod_webp

echo "Building mod_webp Apache module..."

# Check if apxs is available
if ! command -v apxs &> /dev/null; then
    echo "Error: apxs not found. Please install Apache development package:"
    echo "  Ubuntu/Debian: sudo apt-get install apache2-dev"
    echo "  CentOS/RHEL: sudo yum install httpd-devel"
    exit 1
fi

# Check if libwebp development files are available
if ! pkg-config --exists libwebp &> /dev/null; then
    echo "Warning: libwebp development files not found via pkg-config"
    echo "You might need to install libwebp development package:"
    echo "  Ubuntu/Debian: sudo apt-get install libwebp-dev"
    echo "  CentOS/RHEL: sudo yum install libwebp-devel"
fi

# Build the module
make

if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo "To install the module, run: sudo make install"
else
    echo "Build failed!"
    exit 1
fi