# Makefile for mod_webp Apache module

# Compiler and linker
CC = gcc
APXS = apxs

# Installation directory
APACHE_MODULES_DIR = /usr/lib/apache2/modules

# Default paths for libwebp
WEBP_INCLUDE = /usr/include
WEBP_LIB = /usr/lib

# Check if pkg-config is available for libwebp
ifeq ($(shell pkg-config --exists libwebp 2>/dev/null && echo 1),1)
	WEBP_CFLAGS = $(shell pkg-config --cflags libwebp)
	WEBP_LIBS = $(shell pkg-config --libs libwebp)
else
	WEBP_CFLAGS = -I$(WEBP_INCLUDE)
	WEBP_LIBS = -L$(WEBP_LIB) -lwebp
endif

# Default target
all: mod_webp.so

# Build the module
mod_webp.so: mod_webp.c
	$(APXS) -c mod_webp.c $(WEBP_CFLAGS) $(WEBP_LIBS)

# Install the module
install: mod_webp.so
	$(APXS) -i -a mod_webp.la

# Clean build files
clean:
	rm -f *.o *.lo *.la *.slo
	rm -f *.so

# Debug build
debug: CFLAGS += -DDEBUG -g
debug: mod_webp.so

# Test compile only
test-compile:
	$(APXS) -c -Wc,-Wall mod_webp.c $(WEBP_CFLAGS) $(WEBP_LIBS)

.PHONY: all install clean debug test-compile