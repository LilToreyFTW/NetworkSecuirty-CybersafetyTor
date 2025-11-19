@echo off
REM ADDED: Batch build script for Network Security Monitor (User Setup Version)
echo === Building Network Security Monitor (User Setup Version) ===
echo.

REM ADDED: Build C# backend
echo [1/3] Building C# backend...
dotnet restore
if %errorlevel% neq 0 (
    echo Failed to restore packages!
    pause
    exit /b 1
)

dotnet build -c Release
if %errorlevel% neq 0 (
    echo Build failed!
    pause
    exit /b 1
)

REM ADDED: Publish as single executable
echo.
echo [2/3] Publishing executable...
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o ../dist-user-setup
if %errorlevel% neq 0 (
    echo Publish failed!
    pause
    exit /b 1
)

REM ADDED: Build TypeScript frontend
echo.
echo [3/3] Building TypeScript frontend...
cd ..\Frontend
if exist "node_modules" (
    echo Node modules already installed, skipping npm install...
) else (
    npm install
    if %errorlevel% neq 0 (
        echo Failed to install npm packages!
        cd ..
        pause
        exit /b 1
    )
)

npm run build
if %errorlevel% neq 0 (
    echo Frontend build failed!
    cd ..\NetworkSecurityMonitor-UserSetup
    pause
    exit /b 1
)

cd ..\NetworkSecurityMonitor-UserSetup

REM ADDED: Copy frontend build to dist-user-setup
echo.
echo Copying frontend to dist-user-setup...
if exist "..\dist-user-setup\Frontend" (
    rmdir /s /q "..\dist-user-setup\Frontend"
)
xcopy /e /i /y "..\Frontend\dist" "..\dist-user-setup\Frontend"

echo.
echo === Build Complete! ===
echo Executable location: ..\dist-user-setup\NetworkSecurityMonitor.exe
echo Frontend location: ..\dist-user-setup\Frontend\
echo.
echo To run: ..\dist-user-setup\NetworkSecurityMonitor.exe
echo.
pause
