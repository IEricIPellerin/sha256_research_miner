@echo off
setlocal
cd /d "%~dp0"

echo.
echo ========================================
echo MINER BITCOIN LIVE
echo ========================================
echo.

echo [1/2] Compilation...
cmake --build --preset windows-release
if errorlevel 1 goto :error

echo.
echo [2/2] Demarrage du miner...
echo.

build\windows-release\Release\sha256_research_miner.exe --config config\miner.json

set "RESULT=%ERRORLEVEL%"

echo.
echo ========================================
echo MINER ARRETE
echo Code de sortie : %RESULT%
echo ========================================
echo.
pause
exit /b %RESULT%

:error
echo.
echo ========================================
echo ECHEC DE COMPILATION - MINER NON LANCE
echo ========================================
echo.
pause
exit /b 1