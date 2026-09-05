@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

title SHA256 Research Miner - Benchmark parallelisme

set "EXE=%CD%\build\windows-release\Release\sha256_context_analyzer.exe"
set "DEFAULT_CAMPAIGN=results\trajectory_analysis\traj_20260905_192802_2d5437b3"
set "LOGDIR=%CD%\benchmark_logs\parallelism"

echo.
echo ============================================================
echo   BENCHMARK PARALLELISME - SHA256 RESEARCH MINER
echo ============================================================
echo.
echo Ce script permet de tester n'importe quels nombres de workers/threads.
echo Exemple: 1 2 4 5 8 16 20 32
echo.

set "DO_BUILD="
set /p "DO_BUILD=Relancer 01_BUILD_TESTS.bat avant le benchmark ? [N]: "

if /I "%DO_BUILD%"=="O" goto do_build
if /I "%DO_BUILD%"=="OUI" goto do_build
if /I "%DO_BUILD%"=="Y" goto do_build
if /I "%DO_BUILD%"=="YES" goto do_build

goto after_build


:do_build
echo.
echo [BUILD] Lancement de 01_BUILD_TESTS.bat...
call "%CD%\01_BUILD_TESTS.bat"

if errorlevel 1 (
    echo.
    echo [ERREUR] Le build/tests a echoue.
    goto fatal
)


:after_build

if not exist "%EXE%" (
    echo.
    echo [ERREUR] Executable introuvable:
    echo %EXE%
    echo.
    echo Lance d'abord 01_BUILD_TESTS.bat.
    goto fatal
)

if not exist "%LOGDIR%" (
    mkdir "%LOGDIR%" >nul 2>&1
)

for /f %%T in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set "STAMP=%%T"

set "MASTERLOG=%LOGDIR%\benchmark_%STAMP%.log"

echo Benchmark demarre le %DATE% %TIME% > "%MASTERLOG%"
echo Executable: %EXE%>> "%MASTERLOG%"
echo.>> "%MASTERLOG%"


:menu
echo.
echo ============================================================
echo Choisis le type de benchmark
echo ============================================================
echo [1] GPU - tester une liste de GPU workers
echo [2] CPU - tester une liste de threads CPU
echo [3] GPU puis CPU
echo [4] Quitter
echo.

set "CHOICE="
set /p "CHOICE=Choix [1]: "

if not defined CHOICE set "CHOICE=1"

if "%CHOICE%"=="1" goto gpu
if "%CHOICE%"=="2" goto cpu
if "%CHOICE%"=="3" goto both
if "%CHOICE%"=="4" goto end

echo Choix invalide.
goto menu


:both
call :run_gpu
if errorlevel 1 goto fatal

call :run_cpu
if errorlevel 1 goto fatal

goto finished


:gpu
call :run_gpu
if errorlevel 1 goto fatal
goto finished


:cpu
call :run_cpu
if errorlevel 1 goto fatal
goto finished


:run_gpu
echo.
echo ============================================================
echo BENCHMARK GPU
echo ============================================================

set "CAMPAIGN="
set /p "CAMPAIGN=Campagne [%DEFAULT_CAMPAIGN%]: "

if not defined CAMPAIGN (
    set "CAMPAIGN=%DEFAULT_CAMPAIGN%"
)

set "CAMPAIGN=%CAMPAIGN:"=%"

if not exist "%CAMPAIGN%\manifest.json" (
    echo.
    echo [ERREUR] manifest.json introuvable dans:
    echo %CAMPAIGN%
    exit /b 1
)

set "BJE_COUNT="
set /p "BJE_COUNT=Nombre de BJE a utiliser [200]: "

if not defined BJE_COUNT (
    set "BJE_COUNT=200"
)

set "GPU_LIST="
set /p "GPU_LIST=GPU workers a tester [1 2 4 8 16 32]: "

if not defined GPU_LIST (
    set "GPU_LIST=1 2 4 8 16 32"
)

echo.>> "%MASTERLOG%"
echo ============================================================>> "%MASTERLOG%"
echo GPU BENCHMARK>> "%MASTERLOG%"
echo Campaign: %CAMPAIGN%>> "%MASTERLOG%"
echo BJE: %BJE_COUNT%>> "%MASTERLOG%"
echo Workers: %GPU_LIST%>> "%MASTERLOG%"
echo ============================================================>> "%MASTERLOG%"

echo.
echo Configuration GPU:
echo   Campagne : %CAMPAIGN%
echo   BJE      : %BJE_COUNT%
echo   Workers  : %GPU_LIST%
echo.

for %%W in (%GPU_LIST%) do (

    echo.
    echo ============================================================
    echo [GPU] Test avec %%W worker(s)
    echo ============================================================

    echo.>> "%MASTERLOG%"
    echo ---------- GPU workers=%%W ---------->> "%MASTERLOG%"

    powershell -NoProfile -Command ^
    "& '%EXE%' trajectory-throughput-benchmark --campaign '%CAMPAIGN%' --bje %BJE_COUNT% --gpu-workers %%W 2>&1 | Tee-Object -FilePath '%MASTERLOG%' -Append; $code=$LASTEXITCODE; exit $code"

    if errorlevel 1 (
        echo.
        echo [ERREUR] Le test GPU avec %%W worker(s) a echoue.
        echo [ERREUR] GPU workers=%%W>> "%MASTERLOG%"
        exit /b 1
    )
)

exit /b 0


:run_cpu
echo.
echo ============================================================
echo BENCHMARK CPU
echo ============================================================

set "NONCE_COUNT="
set /p "NONCE_COUNT=Nombre de nonces [67108864 = 2^26]: "

if not defined NONCE_COUNT (
    set "NONCE_COUNT=67108864"
)

set "CPU_LIST="
set /p "CPU_LIST=Threads CPU a tester [1 2 4 8 16 32]: "

if not defined CPU_LIST (
    set "CPU_LIST=1 2 4 8 16 32"
)

echo.>> "%MASTERLOG%"
echo ============================================================>> "%MASTERLOG%"
echo CPU BENCHMARK>> "%MASTERLOG%"
echo Nonces: %NONCE_COUNT%>> "%MASTERLOG%"
echo Threads: %CPU_LIST%>> "%MASTERLOG%"
echo ============================================================>> "%MASTERLOG%"

echo.
echo Configuration CPU:
echo   Nonces  : %NONCE_COUNT%
echo   Threads : %CPU_LIST%
echo.

for %%T in (%CPU_LIST%) do (

    echo.
    echo ============================================================
    echo [CPU] Test avec %%T thread(s)
    echo ============================================================

    echo.>> "%MASTERLOG%"
    echo ---------- CPU threads=%%T ---------->> "%MASTERLOG%"

    powershell -NoProfile -Command ^
    "& '%EXE%' trajectory-cpu-benchmark --threads %%T --nonce-count %NONCE_COUNT% 2>&1 | Tee-Object -FilePath '%MASTERLOG%' -Append; $code=$LASTEXITCODE; exit $code"

    if errorlevel 1 (
        echo.
        echo [ERREUR] Le test CPU avec %%T thread(s) a echoue.
        echo [ERREUR] CPU threads=%%T>> "%MASTERLOG%"
        exit /b 1
    )
)

exit /b 0


:finished
echo.
echo ============================================================
echo BENCHMARK TERMINE AVEC SUCCES
echo ============================================================
echo.
echo Log complet:
echo %MASTERLOG%
echo.
echo ============================================================
echo APPUYEZ SUR ENTREE POUR FERMER CETTE FENETRE
echo ============================================================
echo.

set "FERMER="
set /p "FERMER="
goto end


:fatal
echo.
echo ============================================================
echo LE BENCHMARK S'EST ARRETE SUR UNE ERREUR
echo ============================================================
echo.

if defined MASTERLOG (
    echo Log disponible ici:
    echo %MASTERLOG%
    echo.
)

echo ============================================================
echo APPUYEZ SUR ENTREE POUR FERMER CETTE FENETRE
echo ============================================================
echo.

set "FERMER="
set /p "FERMER="
goto end


:end
endlocal
exit /b 0