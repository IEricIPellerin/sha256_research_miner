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
echo [9] PHASE 2 - ranking intra-contexte (DISCOVERY seulement)
echo [10] PHASE 2 REFINEMENT - ridge/T30/max-stat (DISCOVERY seulement)
echo [11] PHASE 3 - T20 / Y-SORT / TRAJECTOIRES
echo [12] Reprendre la derniere campagne PHASE 3
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
if "%CHOICE%"=="9" goto phase2
if "%CHOICE%"=="10" goto phase2refinement
if "%CHOICE%"=="11" goto phase3
if "%CHOICE%"=="12" "%ANALYZER%" trajectory-resume & goto done
if "%CHOICE%"=="0" exit /b 0
echo Choix invalide.
pause
goto menu

:phase2
echo.
echo CAMPAGNE: ctx_20260904_165537_41323536 (figee)
echo MODE: PHASE 2A DISCOVERY ONLY
echo OBJECTIF PRIMAIRE: ranking des extranonce2 dans chaque contexte
echo Discovery utilise: oui
echo Validation utilisee: NON
echo Holdout utilise: NON
echo Aucun scan GPU: oui
echo Donnees sources modifiees: NON
echo.
set /p "CONFIRM2=Confirmer Phase 2A [O/N]: "
if /i "%CONFIRM2%"=="O" "%ANALYZER%" phase2 --campaign results\context_analysis\ctx_20260904_165537_41323536 --yes
if /i "%CONFIRM2%"=="OUI" "%ANALYZER%" phase2 --campaign results\context_analysis\ctx_20260904_165537_41323536 --yes
goto done

:phase2refinement
echo.
echo CAMPAGNE: ctx_20260904_165537_41323536 (figee)
echo MODE: PHASE 2A REFINEMENT DISCOVERY ONLY
echo SORTIE: phase2_discovery_v1_refinement (non ecrasable)
echo Validation utilisee: NON
echo Holdout utilise: NON
echo Aucun scan GPU/nonce: oui
echo Phase 2A historique modifiee: NON
echo.
set /p "CONFIRM2R=Confirmer le refinement discovery [O/N]: "
if /i "%CONFIRM2R%"=="O" "%ANALYZER%" phase2-refinement --campaign results\context_analysis\ctx_20260904_165537_41323536 --yes
if /i "%CONFIRM2R%"=="OUI" "%ANALYZER%" phase2-refinement --campaign results\context_analysis\ctx_20260904_165537_41323536 --yes
goto done

:phase3
echo.
echo MODE: PHASE 3 POST_SCAN TRAJECTORY
echo BJE = espace complet de 2^32 nonces
echo Seuil capture: T20
echo Stockage des 2^32 hashes: NON
echo Capture GPU: nonces T20 seulement
echo Analyse auto: DISCOVERY seulement
echo Validation: SCELLEE
echo Holdout: SCELLE
echo Phase 2 historique modifiee: NON
echo.
set "BJE_COUNT="
set /p "BJE_COUNT=Nombre de B(J,e) a scanner [16]: "
if not defined BJE_COUNT set "BJE_COUNT=16"
for /f "delims=0123456789" %%A in ("%BJE_COUNT%") do if not "%%A"=="" goto phase3invalid
set /a BJE_NUMBER=%BJE_COUNT% 2>nul
if %BJE_NUMBER% LEQ 0 goto phase3invalid
echo Ce nombre concerne les jobs GPU concurrents, pas les threads CPU.
set "GPU_WORKERS="
set /p "GPU_WORKERS=GPU workers simultanés [1]: "
if not defined GPU_WORKERS set "GPU_WORKERS=1"
for /f "delims=0123456789" %%A in ("%GPU_WORKERS%") do if not "%%A"=="" goto phase3workersinvalid
set /a GPU_WORKER_NUMBER=%GPU_WORKERS% 2>nul
if %GPU_WORKER_NUMBER% LEQ 0 goto phase3workersinvalid
"%ANALYZER%" trajectory-new --bje %BJE_COUNT% --gpu-workers %GPU_WORKERS%
goto done

:phase3invalid
echo [ERREUR] Le nombre de BJE doit etre un entier strictement positif.
pause
goto menu

:phase3workersinvalid
echo [ERREUR] Le nombre de GPU workers simultanés doit etre un entier strictement positif.
pause
goto menu

:done
echo.
pause
goto menu
