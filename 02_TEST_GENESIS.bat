@echo off
setlocal
cd /d "%~dp0"

echo.
echo ========================================
echo TEST GENESIS
echo ========================================
echo.

echo [1/3] Compilation...
cmake --build --preset windows-release
if errorlevel 1 goto :error

echo.
echo [2/3] Suppression du checkpoint historique...
if exist "state\historical_state.json" del /q "state\historical_state.json"

echo.
echo [3/3] Recherche du nonce gagnant Genesis...
echo.

build\windows-release\Release\sha256_research_miner.exe --config config\research.json

set "RESULT=%ERRORLEVEL%"

echo.
if "%RESULT%"=="0" (
    echo ========================================
    echo TEST GENESIS TERMINE AVEC SUCCES
    echo ========================================
) else (
    echo ========================================
    echo TEST GENESIS EN ECHEC
    echo Code de sortie : %RESULT%
    echo ========================================
)

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