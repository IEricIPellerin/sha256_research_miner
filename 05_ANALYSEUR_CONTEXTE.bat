@echo off
setlocal
cd /d "%~dp0"
set "ANALYZER=build\windows-release\Release\sha256_context_analyzer.exe"

if not exist "%ANALYZER%" (
  echo [ERREUR] Analyseur absent. Lancez d'abord 01_BUILD_TESTS.bat.
  pause
  exit /b 1
)

if /i "%~1"=="--check" goto check
goto menu

:check
"%ANALYZER%" corpus
exit /b %errorlevel%

:menu
cls
echo ================================================================
echo       ANALYSEUR CONTEXTUEL SHA-256 - ESPACES COMPLETS B(J,e)
echo ================================================================
echo.
echo [1] QUICK  - exemple court, parametres visibles/modifiables
echo [2] PILOT  - exemple pilote, parametres visibles/modifiables
echo [3] FULL   - exemple par budget de temps, jamais 10 000 impose
echo [4] Reprendre la derniere campagne
echo [5] Analyser les resultats existants
echo [6] Taille personnalisee
echo [7] Smoke test tres court
echo [8] Resume du corpus Stratum
echo [0] Quitter
echo.
set /p "CHOICE=Choix: "

if "%CHOICE%"=="1" "%ANALYZER%" new --profile QUICK & goto done
if "%CHOICE%"=="2" "%ANALYZER%" new --profile PILOT & goto done
if "%CHOICE%"=="3" "%ANALYZER%" new --profile FULL & goto done
if "%CHOICE%"=="4" "%ANALYZER%" resume & goto done
if "%CHOICE%"=="5" "%ANALYZER%" analyze & goto done
if "%CHOICE%"=="6" "%ANALYZER%" new --profile CUSTOM & goto done
if "%CHOICE%"=="7" "%ANALYZER%" smoke --benchmark-nonces 1048576 --smoke-nonces 65536 & goto done
if "%CHOICE%"=="8" "%ANALYZER%" corpus & goto done
if "%CHOICE%"=="0" exit /b 0
echo Choix invalide.
pause
goto menu

:done
echo.
pause
goto menu
