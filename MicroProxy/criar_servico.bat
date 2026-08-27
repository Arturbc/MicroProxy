@echo off
setlocal enabledelayedexpansion

echo ============================================
echo        CRIADOR DE SERVICO WINDOWS
echo ============================================

REM ==== VERIFICA SE ESTÁ RODANDO COMO ADMIN
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Solicitando privilegios de administrador...
    
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

REM ==== DETECTAR EXE NA MESMA PASTA ====
set "BINARY_PATH="

for %%f in ("%~dp0*.exe") do (
    set "BINARY_PATH=%%~f"
    set "SERVICE_NAME=%%~nf"
    goto :foundExe
)

:foundExe

REM ==== INPUT DO CAMINHO DO EXECUTAVEL ====
if defined BINARY_PATH (
    echo Executavel encontrado: %BINARY_PATH%
) else (
    echo ERRO: Executavel nao encontrado.
    pause
    exit /b 1
)

REM ==== DISPLAY NAME ====
set /p DISPLAY_NAME="Nome amigavel [%SERVICE_NAME%]: "
if "%DISPLAY_NAME%"=="" set "DISPLAY_NAME=%SERVICE_NAME%"

REM ==== DESCRICAO ====
set /p DESCRIPTION="Descricao (opcional): "

REM ==== DEPENDENCIAS ====
set /p DEPENDENCIES="Dependencias (separar por /) (opcional): "

REM ==== TIPO DE INICIALIZACAO ====
echo Tipos de inicializacao:
echo   auto     = Automatico
echo   demand   = Manual
echo   disabled = Desativado
set /p START_TYPE="Tipo [auto]: "
if "%START_TYPE%"=="" set "START_TYPE=auto"

REM ==== CRIACAO ====
echo.
echo Criando servico...

sc create "%SERVICE_NAME%" ^
    binPath= "%BINARY_PATH%" ^
    DisplayName= "%DISPLAY_NAME%" ^
    start= %START_TYPE% ^
    depend= "%DEPENDENCIES%"

if %ERRORLEVEL% NEQ 0 (
    echo ERRO ao criar servico.
    pause
    exit /b 1
)

REM ==== DESCRICAO ====
if not "%DESCRIPTION%"=="" (
    sc description "%SERVICE_NAME%" "%DESCRIPTION%"
)

echo.
echo Servico criado com sucesso!

echo.
echo IMPORTANTE:
echo Configure o usuario do servico antes de iniciar:
echo services.msc -> %SERVICE_NAME% -> Logon
echo.
pause