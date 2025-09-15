@echo off
REM test-build.bat - Test script to verify module compiles correctly on Windows

echo Testing mod_webp compilation...

REM Check prerequisites
where apxs >nul 2>&1
if %errorlevel% neq 0 (
    echo SKIP: apxs not found, cannot test compilation
    exit /b 0
)

REM Try to compile (but don't install)
nmake -f Makefile.win clean
nmake -f Makefile.win test-compile

if %errorlevel% equ 0 (
    echo PASS: Module compiles successfully
    nmake -f Makefile.win clean
    exit /b 0
) else (
    echo FAIL: Module compilation failed
    nmake -f Makefile.win clean
    exit /b 1
)