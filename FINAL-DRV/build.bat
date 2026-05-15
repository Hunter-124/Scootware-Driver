@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem ---------------------------------------------------------------------------
rem  Build kernel driver (Release | x64), copy to repo BIN as driver.sys
rem  and drv.sys (mapper / PCOMP expect drv.sys).
rem
rem  Prerequisites: Visual Studio with MSBuild; optional SCOOTWARE_NO_PAUSE=1
rem ---------------------------------------------------------------------------

set "PROJ_DIR=%~dp0"
if "%PROJ_DIR:~-1%"=="\" set "PROJ_DIR=%PROJ_DIR:~0,-1%"

call "%PROJ_DIR%\..\..\build\lib\env.bat"
if errorlevel 1 (
  if not "!SCOOTWARE_NO_PAUSE!"=="1" pause
  exit /b 1
)

echo MSBuild: %MSBUILD_EXE%
echo BIN:      %BIN%

echo.
echo [1/2] Building FINAL-DRV (Release ^| x64)...
"%MSBUILD_EXE%" "%PROJ_DIR%\driver.vcxproj" /m /v:minimal /p:Configuration=Release /p:Platform=x64
if errorlevel 1 (
  echo ERROR: driver.vcxproj build failed.
  if not "!SCOOTWARE_NO_PAUSE!"=="1" pause
  exit /b 1
)

set "DRV_SYS=%PROJ_DIR%\x64\Release\driver.sys"
if not exist "%DRV_SYS%" (
  echo ERROR: driver.sys not produced at: %DRV_SYS%
  if not "!SCOOTWARE_NO_PAUSE!"=="1" pause
  exit /b 1
)

echo.
echo [2/2] Publishing driver.sys and drv.sys to BIN...
copy /y "%DRV_SYS%" "%BIN%\driver.sys" >nul
if errorlevel 1 (
  echo ERROR: copy driver.sys to BIN failed.
  if not "!SCOOTWARE_NO_PAUSE!"=="1" pause
  exit /b 1
)

copy /y "%DRV_SYS%" "%BIN%\drv.sys" >nul
if errorlevel 1 (
  echo ERROR: copy drv.sys alias to BIN failed.
  if not "!SCOOTWARE_NO_PAUSE!"=="1" pause
  exit /b 1
)

echo.
echo Done.
echo   Built:  %DRV_SYS%
echo   Output: %BIN%\driver.sys
echo           %BIN%\drv.sys ^(alias for mapper / PCOMP^)
exit /b 0
