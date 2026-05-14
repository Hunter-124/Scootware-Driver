@echo off
setlocal EnableExtensions EnableDelayedExpansion

:: PROJ_DIR = directory containing this script (FINAL-DRV\)
set "PROJ_DIR=%~dp0"
if "%PROJ_DIR:~-1%"=="\" set "PROJ_DIR=%PROJ_DIR:~0,-1%"

:: BIN output sits two levels up from FINAL-DRV: Driver\..\..\BIN = Scootware-Master\BIN
set "BIN_DIR=%PROJ_DIR%\..\..\..\BIN"

:: ── Locate MSBuild via vswhere ────────────────────────────────────────────────
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo ERROR: vswhere.exe not found. Install Visual Studio Build Tools.
  pause
)

set "MSBUILD_EXE="
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
  if not defined MSBUILD_EXE set "MSBUILD_EXE=%%i"
)

if not defined MSBUILD_EXE (
  echo ERROR: MSBuild.exe not found via vswhere.
  pause
)

echo MSBuild: %MSBUILD_EXE%

:: ── Build FINAL-DRV Release|x64 ───────────────────────────────────────────────
echo.
echo [1/2] Building FINAL-DRV (Release ^| x64)...
"%MSBUILD_EXE%" "%PROJ_DIR%\driver.vcxproj" /m /v:minimal /p:Configuration=Release /p:Platform=x64
if errorlevel 1 (
  echo ERROR: driver.vcxproj build failed.
  pause
)

set "DRV_SYS=%PROJ_DIR%\x64\Release\driver.sys"
if not exist "%DRV_SYS%" (
  echo ERROR: driver.sys not produced at: %DRV_SYS%
  pause
)

:: ── Copy to BIN ────────────────────────────────────────────────────────────────
echo.
echo [2/2] Copying driver.sys to BIN...
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"
copy /y "%DRV_SYS%" "%BIN_DIR%\driver.sys" >nul
if errorlevel 1 (
  echo ERROR: copy to BIN failed.
  pause
)

echo.
echo Done.
echo   Built:  %DRV_SYS%
echo   Output: %BIN_DIR%\driver.sys
pause
