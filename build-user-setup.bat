@echo off
REM ADDED: Batch build script for Network Security Monitor
echo === Building Network Security Monitor ===
echo.

REM ADDED: Build C# backend
echo [1/3] Building C# backend...
cd NetworkSecurityMonitor
dotnet restore
if %errorlevel% neq 0 (
    echo Failed to restore packages!
    cd ..
    pause
    exit /b 1
)

dotnet build -c Release
if %errorlevel% neq 0 (
    echo Build failed!
    cd ..
    pause
    exit /b 1
)

REM ADDED: Publish as single executable
echo.
echo [2/3] Publishing executable...
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o ../dist
if %errorlevel% neq 0 (
    echo Publish failed!
    cd ..
    pause
    exit /b 1
)

cd ..

REM ADDED: Build TypeScript frontend
echo.
echo [3/3] Building TypeScript frontend...
cd Frontend
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
    cd ..
    pause
    exit /b 1
)

cd ..

REM ADDED: Copy frontend build to dist
echo.
echo Copying frontend to dist...
if exist "dist\Frontend" (
    rmdir /s /q "dist\Frontend"
)
xcopy /e /i /y "Frontend\dist" "dist\Frontend"

echo.
echo === Build Complete! ===
echo Executable location: dist\NetworkSecurityMonitor.exe
echo Frontend location: dist\Frontend\
echo.
echo To run: .\dist\NetworkSecurityMonitor.exe
echo.
pause
