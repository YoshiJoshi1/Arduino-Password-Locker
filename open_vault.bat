@echo off
setlocal

cd /d "%~dp0"

set "PY_CMD="
set "PY_ARGS="

if exist ".venv\Scripts\python.exe" (
    set "PY_CMD=%~dp0.venv\Scripts\python.exe"
) else (
    where python >nul 2>nul
    if %ERRORLEVEL% EQU 0 (
        set "PY_CMD=python"
    ) else (
        set "PY_CMD=py"
        set "PY_ARGS=-3"
    )
)

"%PY_CMD%" %PY_ARGS% -c "import serial, cryptography" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Required Python packages not found for this interpreter.
    echo Installing: pyserial cryptography
    "%PY_CMD%" %PY_ARGS% -m pip install --upgrade pip
    "%PY_CMD%" %PY_ARGS% -m pip install pyserial cryptography
)

"%PY_CMD%" %PY_ARGS% "vault_cli.py"

echo.
pause
