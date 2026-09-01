@echo off
setlocal
cd /d "%~dp0"

echo.
echo ========================================
echo RECHERCHE SHA-256
echo ========================================
echo.

echo [1/2] Compilation...
cmake --build --preset windows-release
if errorlevel 1 goto :error

echo.
echo [2/2] Lancement de la recherche...
echo.

build\windows-release\Release\sha256_research_miner.exe --config config\reduced_rounds.json

set "RESULT=%ERRORLEVEL%"

echo.
echo ========================================
echo RECHERCHE TERMINEE
echo Code de sortie : %RESULT%
echo ========================================
echo.
pause
exit /b %RESULT%

:error
echo.
echo ========================================
echo ECHEC DE COMPILATION
echo ========================================
echo.
pause
exit /b 1