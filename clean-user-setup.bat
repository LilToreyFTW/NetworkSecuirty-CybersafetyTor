@echo off
REM ADDED: Batch clean script for all builds
echo === Cleaning All Builds ===
echo.

REM ADDED: Clean main dist
if exist "dist" (
    echo Cleaning main dist...
    rmdir /s /q dist
)

REM ADDED: Clean router dist
if exist "dist-router" (
    echo Cleaning router dist...
    rmdir /s /q dist-router
)

REM ADDED: Clean NetworkSecurityMonitor bin/obj
if exist "NetworkSecurityMonitor\bin" (
    echo Cleaning NetworkSecurityMonitor bin...
    rmdir /s /q NetworkSecurityMonitor\bin
)
if exist "NetworkSecurityMonitor\obj" (
    echo Cleaning NetworkSecurityMonitor obj...
    rmdir /s /q NetworkSecurityMonitor\obj
)

REM ADDED: Clean RouterIntegration bin/obj
if exist "RouterIntegration\bin" (
    echo Cleaning RouterIntegration bin...
    rmdir /s /q RouterIntegration\bin
)
if exist "RouterIntegration\obj" (
    echo Cleaning RouterIntegration obj...
    rmdir /s /q RouterIntegration\obj
)

REM ADDED: Clean Frontend node_modules (optional)
if exist "Frontend\node_modules" (
    echo Cleaning Frontend node_modules...
    rmdir /s /q Frontend\node_modules
)

echo.
echo === Clean Complete! ===
echo.
pause
