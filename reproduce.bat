@echo off
REM reproduce.bat - Windows reproduction pipeline for arXiv:2508.10043.
REM Creates .venv, installs the package, validates threats, runs tests, then
REM runs TC1 + TC2 + Table 4 + Table 5. Set SKIP_INSTALL=1 to reuse an env.
setlocal enabledelayedexpansion
set "ROOT=%~dp0"
cd /d "%ROOT%"

if "%SKIP_INSTALL%"=="1" goto :dirs

echo [reproduce] creating venv in .venv ...
python -m venv .venv
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -e ".[dev]"

:dirs
if exist ".venv\Scripts\python.exe" (
  set "PY=.venv\Scripts\python.exe"
) else (
  set "PY=python"
)

if not exist "data\pcap" mkdir "data\pcap"
if not exist "data\memory" mkdir "data\memory"
if not exist "results" mkdir "results"

echo [reproduce] Validating configs/threats.yaml against Eq.(1) ...
"!PY!" -m maestro.scripts.validate_threats || goto :fail

echo [reproduce] Running unit tests ...
"!PY!" -m pytest -q || goto :fail

echo [reproduce] Running TC1 + TC2 + Table 4 + Table 5 ...
"!PY!" -m maestro.experiments.runner || goto :fail

echo [reproduce] Done. See results\ for tables and logs.
endlocal
exit /b 0

:fail
echo [reproduce] FAILED - see output above.
endlocal
exit /b 1
