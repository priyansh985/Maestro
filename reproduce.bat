@echo off
REM reproduce.bat - Windows wrapper around reproduce.sh.
REM Requires Git-Bash or WSL. If unavailable, runs the Python steps directly.
setlocal
set ROOT=%~dp0
cd /d "%ROOT%"

if exist ".venv\Scripts\python.exe" (
  set PY=.venv\Scripts\python.exe
) else (
  set PY=python
)

if "%SKIP_INSTALL%" neq "1" (
  echo [reproduce] creating venv in .venv ...
  %PYTHON% -m venv .venv
  if exist ".venv\Scripts\pip" (
    .venv\Scripts\pip install --upgrade pip
    .venv\Scripts\pip install -e ".[dev]"
  )
)

if not exist "data\pcap" mkdir "data\pcap"
if not exist "data\memory" mkdir "data\memory"
if not exist "results" mkdir "results"

echo [reproduce] Validating configs/threats.yaml against Eq.(1) ...
%PY% -m maestro.scripts.validate_threats

echo [reproduce] Running unit tests ...
%PY% -m pytest -q

echo [reproduce] Running TC1 + TC2 + Table 4 + Table 5 ...
%PY% -m maestro.experiments.runner

echo [reproduce] Done. See results\ for tables and logs.
endlocal
