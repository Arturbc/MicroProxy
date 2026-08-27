@echo off
setlocal

echo ============================
echo     REMOVER SERVICO
echo ============================

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
if not defined BINARY_PATH (
    echo ERRO: Executavel de referencia nao encontrado.
    pause
    exit /b 1
)

echo.
echo Removendo servico %SERVICE_NAME%...

sc stop "%SERVICE_NAME%" >nul 2>&1
sc delete "%SERVICE_NAME%"

if %ERRORLEVEL% NEQ 0 (
    echo ERRO ao remover servico.
    pause
    exit /b 1
)

echo Servico removido com sucesso!
pause
