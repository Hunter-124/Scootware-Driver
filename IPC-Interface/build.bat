@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem ---------------------------------------------------------------------------
rem build.bat - Build the driver speed-test binary (scootware.exe).
rem
rem The driver only attaches to a process named in IPC_APP_NAME
rem (default "scootware.exe"), so the produced exe MUST keep that name.
rem ---------------------------------------------------------------------------

set "TEST_ROOT=%~dp0"
if "%TEST_ROOT:~-1%"=="\" set "TEST_ROOT=%TEST_ROOT:~0,-1%"

cd /d "%TEST_ROOT%"

where cmake >nul 2>&1
if errorlevel 1 (
  echo [-] cmake not found in PATH. Install CMake and ensure it is on PATH.
  pause
)

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo [-] vswhere.exe not found. Install Visual Studio Build Tools or a VS SKU with MSBuild.
  pause
)

set "MSBUILD_EXE="
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
  set "MSBUILD_EXE=%%i"
  goto :msbuild_ok
)
echo [-] MSBuild.exe not found via vswhere.
pause

:msbuild_ok

set "BUILD_DIR=%TEST_ROOT%\build"
set "CONFIG=Release"

rem Allow "build.bat clean" to blow away the build dir.
if /I "%~1"=="clean" (
  echo [*] Removing "%BUILD_DIR%"...
  rd /s /q "%BUILD_DIR%" 2>nul
  echo [+] Clean done.
  pause
)

rem Allow "build.bat debug" to build a Debug configuration.
if /I "%~1"=="debug" set "CONFIG=Debug"

echo [*] Configuring speed-test ^(%CONFIG% ^| x64^)...
cmake -S "%TEST_ROOT%" -B "%BUILD_DIR%" -A x64
if errorlevel 1 (
  echo [!] CMake configure failed ^(often stale cache after moving the repo^). Clearing "%BUILD_DIR%" and retrying...
  rd /s /q "%BUILD_DIR%" 2>nul
  mkdir "%BUILD_DIR%" 2>nul
  cmake -S "%TEST_ROOT%" -B "%BUILD_DIR%" -A x64
  if errorlevel 1 pause
)

echo [*] Building speed-test...
cmake --build "%BUILD_DIR%" --config %CONFIG% -- /m /v:minimal
if errorlevel 1 pause

set "SCOOTWARE_EXE=%BUILD_DIR%\%CONFIG%\scootware.exe"

if not exist "%SCOOTWARE_EXE%" (
  echo [-] ERROR: Expected output not found:
  echo     %SCOOTWARE_EXE%
  pause
)

echo [*] Copying scootware.exe to "%TEST_ROOT%"...
copy /Y "%SCOOTWARE_EXE%" "..\%TEST_ROOT%\" >nul
robocopy "C:\Users\nigga\Desktop\Scootware-Master\Driver\IPC-Interface\build\Release" "C:\Users\nigga\Desktop\Scootware-Master\BIN" scootware.exe
if errorlevel 1 pause

echo.
echo [+] Done. scootware.exe is in "%TEST_ROOT%"
echo     Run as Administrator (with driver.sys loaded) to start the benchmark:
echo         scootware.exe --quick
echo         scootware.exe --csv results.csv
pause
