@echo off
REM ADDED: Simple batch file to run the Network Security Monitor
echo === Network Security Monitor ===
echo.

if exist "dist\NetworkSecurityMonitor.exe" (
    echo Starting Network Security Monitor...
    echo.
    echo Dashboard: http://localhost:3000
    echo Backend: http://localhost:5000
    echo.
    echo Press Ctrl+C to stop
    echo.
    dist\NetworkSecurityMonitor.exe
) else (
    echo Executable not found!
    echo.
    echo Building first... Please wait...
    call build.bat
    echo.
    if exist "dist\NetworkSecurityMonitor.exe" (
        echo Starting Network Security Monitor...
        dist\NetworkSecurityMonitor.exe
    ) else (
        echo Build failed! Please check the errors above.
        pause
        exit /b 1
    )
)

