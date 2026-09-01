@echo off
setlocal
cd /d "%~dp0"

echo.
echo ========================================
echo BUILD + TESTS
echo ========================================
echo.

cmake --build --preset windows-release
if errorlevel 1 goto :error

echo.
echo ========================================
echo TESTS
echo ========================================
echo.

ctest --preset windows-release
if errorlevel 1 goto :error

echo.
echo ========================================
echo BUILD ET TESTS REUSSIS
echo ========================================
echo.
pause
exit /b 0

:error
echo.
echo ========================================
echo ECHEC - VERIFIER LES ERREURS CI-DESSUS
echo ========================================
echo.
pause
exit /b 1