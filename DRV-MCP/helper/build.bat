@echo off
REM ─────────────────────────────────────────────────────────────────────
REM  Build scootware_helper.c → scootware.exe using cl.exe from VS 2022.
REM  Output filename MUST be scootware.exe (matches IPC_APP_NAME in the
REM  driver header). Drop the binary next to this script.
REM ─────────────────────────────────────────────────────────────────────

setlocal

REM Find a Visual Studio install with vcvarsall.bat. Prefer 2022 Community.
set "VCVARS="
for %%E in (
  "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"
  "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat"
  "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
  "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
  "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
  "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat"
) do (
  if exist %%E (
    set "VCVARS=%%E"
    goto :found
  )
)

echo [-] Could not find vcvarsall.bat. Install Visual Studio 2022 with
echo     "Desktop development with C++" workload, or run this script from
echo     a Developer Command Prompt for VS 2022.
exit /b 1

:found
echo [+] Using %VCVARS%
call %VCVARS% x64 >nul
if errorlevel 1 (
  echo [-] vcvarsall.bat failed
  exit /b 1
)

cd /d "%~dp0"

if exist scootware.exe del scootware.exe
if exist scootware_helper.obj del scootware_helper.obj

REM Compile the C++ stdio IPC bridge. We pull in shared_memory_ipc.h
REM from FINAL-DRV via /I — keep the include path centralized so we
REM never have a stale local copy of the IPC layout.
cl /nologo /W3 /O2 /MT /EHsc /std:c++17 ^
    /I "..\..\FINAL-DRV" ^
    /Fe:scootware.exe scootware_helper.cpp ^
    kernel32.lib user32.lib advapi32.lib ^
    /link /SUBSYSTEM:CONSOLE /ENTRY:wmainCRTStartup
if errorlevel 1 (
  echo [-] Build failed
  exit /b 1
)

if exist scootware_helper.obj del scootware_helper.obj
if exist scootware.exp del scootware.exp
if exist scootware.lib del scootware.lib

echo [+] Built %~dp0scootware.exe
