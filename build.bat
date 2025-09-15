@echo off
REM build.bat - Build script for mod_webp on Windows

echo Building mod_webp Apache module...

REM Check if apxs is available
where apxs >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: apxs not found. Please ensure Apache development tools are installed and in PATH
    echo You might need to install Apache from ApacheLounge with development headers
    exit /b 1
)

REM Build the module
nmake -f Makefile.win

if %errorlevel% equ 0 (
    echo Build successful!
    echo To install the module, run: nmake -f Makefile.win install
) else (
    echo Build failed!
    exit /b 1
)