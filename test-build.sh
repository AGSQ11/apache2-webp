#!/bin/bash
# test-build.sh - Test script to verify module compiles correctly

echo "Testing mod_webp compilation..."

# Check prerequisites
if ! command -v apxs &> /dev/null; then
    echo "SKIP: apxs not found, cannot test compilation"
    exit 0
fi

# Try to compile (but don't install)
if make clean && make test-compile; then
    echo "PASS: Module compiles successfully"
    make clean
    exit 0
else
    echo "FAIL: Module compilation failed"
    make clean
    exit 1
fi