@echo off
REM ADDED: Batch clean script for User Setup builds
echo === Cleaning User Setup Builds ===
echo.

REM ADDED: Clean user setup dist
if exist "..\dist-user-setup" (
    echo Cleaning user setup dist...
    rmdir /s /q ..\dist-user-setup
)

REM ADDED: Clean bin/obj
if exist "bin" (
    echo Cleaning bin...
    rmdir /s /q bin
)
if exist "obj" (
    echo Cleaning obj...
    rmdir /s /q obj
)

REM ADDED: Clean UserConfig.json
if exist "UserConfig.json" (
    echo Cleaning user configuration...
    del UserConfig.json
)

echo.
echo === Clean Complete! ===
echo.
pause
