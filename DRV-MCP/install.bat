@echo off
REM ─────────────────────────────────────────────────────────────────────
REM  Install the drv-mcp server: build the helper, install Python deps,
REM  register the server with Claude Code.
REM ─────────────────────────────────────────────────────────────────────

setlocal
cd /d "%~dp0"

echo [*] Step 1/3: Building scootware.exe helper...
call helper\build.bat
if errorlevel 1 (
  echo [-] Helper build failed.
  exit /b 1
)

echo.
echo [*] Step 2/3: Installing Python dependencies...
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo [-] pip install failed.
  exit /b 1
)

echo.
echo [*] Step 3/3: Registering MCP server with Claude Code...
where claude >nul 2>&1
if errorlevel 1 (
  echo [!] claude CLI not on PATH. Add the server manually:
  echo.
  echo     claude mcp add scootware-driver -- python -m drv_mcp
  echo.
  echo Or edit ^%%USERPROFILE^%%\.claude.json to include:
  echo.
  echo     "scootware-driver": {
  echo         "type": "stdio",
  echo         "command": "python",
  echo         "args": ["-m", "drv_mcp"],
  echo         "cwd": "%~dp0"
  echo     }
  goto :done
)

claude mcp add scootware-driver -- python -m drv_mcp
if errorlevel 1 (
  echo [-] claude mcp add failed. Run it manually.
  exit /b 1
)

:done
echo.
echo [+] Install complete.
echo [+] Helper:        %~dp0helper\scootware.exe
echo [+] Server module: drv_mcp (run: python -m drv_mcp)
echo.
echo Reminder: load drv.sys before using the MCP, otherwise tool calls
echo will block until the handshake timeout.
