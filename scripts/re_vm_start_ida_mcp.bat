@echo off
setlocal
set PATH=C:\Users\john\AppData\Local\Programs\Python\Python312\Scripts;%PATH%
cd /d C:\re-mcps\ida-pro-mcp
start "idalib-mcp-server" /MIN cmd /c "uv run idalib-mcp --host 127.0.0.1 --port 8744 > C:\re-mcps\idalib-mcp.log 2>&1"
endlocal

