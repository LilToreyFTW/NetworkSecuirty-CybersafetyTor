@echo off
REM ADDED: Simple batch file to run the Network Security Monitor (User Setup Version)
echo === Network Security Monitor (User Setup Version) ===
echo.

if exist "..\dist-user-setup\NetworkSecurityMonitor.exe" (
    echo Starting Network Security Monitor...
    echo.
    echo This version includes interactive IP setup for new users!
    echo.
    echo Press Ctrl+C to stop
    echo.
    ..\dist-user-setup\NetworkSecurityMonitor.exe
) else (
    echo Executable not found!
    echo.
    echo Building first... Please wait...
    call build-user-setup.bat
    echo.
    if exist "..\dist-user-setup\NetworkSecurityMonitor.exe" (
        echo Starting Network Security Monitor...
        ..\dist-user-setup\NetworkSecurityMonitor.exe
    ) else (
        echo Build failed! Please check the errors above.
        pause
        exit /b 1
    )
)

