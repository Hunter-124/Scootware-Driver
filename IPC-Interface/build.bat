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

call "%TEST_ROOT%\..\..\build\lib\env.bat"
if errorlevel 1 (
  if not "!SCOOTWARE_NO_PAUSE!"=="1" pause
  pause
)

where cmake >nul 2>&1
if errorlevel 1 (
  echo [-] cmake not found in PATH. Install CMake and ensure it is on PATH.
  if not "!SCOOTWARE_NO_PAUSE!"=="1" pause
  pause
)

set "BUILD_DIR=%TEST_ROOT%\build"
set "CONFIG=Release"

if /I "%~1"=="clean" (
  echo [*] Removing "%BUILD_DIR%"...
  rd /s /q "%BUILD_DIR%" 2>nul
  echo [+] Clean done.
  pause
)

if /I "%~1"=="debug" set "CONFIG=Debug"

echo [*] Configuring speed-test ^(%CONFIG% ^| x64^)...
cmake -S "%TEST_ROOT%" -B "%BUILD_DIR%" -A x64
if errorlevel 1 (
  echo [!] CMake configure failed ^(often stale cache after moving the repo^). Clearing "%BUILD_DIR%" and retrying...
  rd /s /q "%BUILD_DIR%" 2>nul
  mkdir "%BUILD_DIR%" 2>nul
  cmake -S "%TEST_ROOT%" -B "%BUILD_DIR%" -A x64
  if errorlevel 1 (
    if not "!SCOOTWARE_NO_PAUSE!"=="1" pause
    pause
  )
)

echo [*] Building speed-test...
cmake --build "%BUILD_DIR%" --config %CONFIG% -- /m /v:minimal
if errorlevel 1 (
  if not "!SCOOTWARE_NO_PAUSE!"=="1" pause
  pause
)

set "SCOOTWARE_EXE=%BUILD_DIR%\%CONFIG%\scootware.exe"

if not exist "%SCOOTWARE_EXE%" (
  echo [-] ERROR: Expected output not found:
  echo     %SCOOTWARE_EXE%
  if not "!SCOOTWARE_NO_PAUSE!"=="1" pause
  pause
)

echo [*] Copying scootware.exe to "%TEST_ROOT%\"...
copy /Y "%SCOOTWARE_EXE%" "%TEST_ROOT%\scootware.exe" >nul
if errorlevel 1 (
  echo [-] copy to project folder failed.
  if not "!SCOOTWARE_NO_PAUSE!"=="1" pause
  pause
)

robocopy "%BUILD_DIR%\%CONFIG%" "%BIN%" scootware.exe /NFL /NDL /NJH /NJS /nc /ns /np >nul
if errorlevel 8 (
  echo [-] robocopy to BIN failed.
  if not "!SCOOTWARE_NO_PAUSE!"=="1" pause
  pause
)

echo.
echo [+] Done. scootware.exe is in "%TEST_ROOT%" and "%BIN%"
echo     Run as Administrator (with driver loaded) to start the benchmark:
echo         scootware.exe --quick
echo         scootware.exe --csv results.csv
pause
