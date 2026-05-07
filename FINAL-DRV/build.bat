@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "ROOT=%~dp0.."
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

cd /d "%ROOT%"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo Error: vswhere.exe not found. Install Visual Studio Build Tools or a VS SKU with MSBuild.
  pause
)

set "MSBUILD_EXE="
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
  set "MSBUILD_EXE=%%i"
  goto :msbuild_found
)
echo Error: MSBuild.exe not found via vswhere.
pause

:msbuild_found
if not defined MSBUILD_EXE (
  echo Error: MSBuild path is empty.
  pause
)

where cmake >nul 2>&1
if errorlevel 1 (
  echo Error: cmake not found in PATH. Install CMake and add it to PATH.
  pause
)

echo [1/3] Building FINAL-DRV (Release ^| x64)...
"%MSBUILD_EXE%" "%ROOT%\FINAL-DRV\driver.vcxproj" /m /v:minimal /p:Configuration=Release /p:Platform=x64
if errorlevel 1 pause

set "DRV_SYS=%ROOT%\FINAL-DRV\x64\Release\driver.sys"

if not exist "%DRV_SYS%" (
  echo Error: driver output not found: "%DRV_SYS%"
  pause
)

echo Copying driver.sys to "FINAL-DRV\driver.sys" ...

robocopy "C:\Users\nigga\Desktop\Scootware-Master\Driver\FINAL-DRV\x64\Release" "C:\Users\nigga\Desktop\Scootware-Master\BIN" driver.sys

echo.
echo Done. driver.sys:   "%ROOT%\driver.sys"
pause

:try_cmake
set "SRC=%~1"
set "BLD=%~2"
cmake -S "%SRC%" -B "%BLD%" -A x64
if errorlevel 1 (
  echo CMake configure failed. Clearing build dir and retrying...
  rd /s /q "%BLD%" 2>nul
  mkdir "%BLD%" 2>nul
  cmake -S "%SRC%" -B "%BLD%" -A x64
  if errorlevel 1 (
    echo If you moved the project folder, run:  build.bat clean
    pause
  )
)
pause

:build_cmake
set "BLD2=%~1"
set "CFG2=%~2"
cmake --build "%BLD2%" --config %CFG2% -- /m /v:minimal
if errorlevel 1 (
  echo CMake build failed. If you moved the repo, run: build.bat clean
  pause
)
pause
