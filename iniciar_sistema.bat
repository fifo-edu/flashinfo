@echo off
setlocal
cd /d "%~dp0"

rem Ambiente criado com um Python que foi desinstalado ou atualizado: o .venv nao abre mais e e refeito.
if exist ".venv\Scripts\python.exe" (
  .venv\Scripts\python.exe -c "pass" >nul 2>&1
  if errorlevel 1 (
    echo O Python do sistema mudou: refazendo o ambiente...
    rmdir /s /q .venv
  )
)

if not exist ".venv\Scripts\python.exe" (
  echo Primeira execucao: preparando o sistema...
  py -3 -m venv .venv || goto :erro_python
)

.venv\Scripts\python.exe -c "import flask, pypdf, reportlab" >nul 2>&1
if errorlevel 1 (
  echo Atualizando os componentes do sistema...
  .venv\Scripts\python.exe -m pip install -r requirements.txt
  if errorlevel 1 echo Aviso: o sistema abrira, mas a impressao PDF pode ficar indisponivel ate concluir a atualizacao.
)

.venv\Scripts\python.exe -m py_compile app.py || goto :erro_aplicacao
start "Loja de Envios" .venv\Scripts\pythonw.exe app.py
exit /b 0

:erro_python
echo.
echo Nao foi possivel preparar o Python. Confirme se o Python 3 esta instalado.
pause
exit /b 1

:erro_aplicacao
echo.
echo O sistema encontrou um erro antes de abrir.
.venv\Scripts\python.exe app.py
pause
exit /b 1
