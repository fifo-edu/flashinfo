@echo off
cd /d "%~dp0"
py -3 -m venv .buildenv
call .buildenv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt pyinstaller
rem Usa o .spec em vez de --add-data: o spec empacota so os dois arquivos de data/
rem que o app le, deixando de fora as chaves e os bancos do Financeiro AGF.
pyinstaller --noconfirm --clean LojaDeEnvios.spec
echo.
echo Executavel criado em dist\LojaDeEnvios\LojaDeEnvios.exe
pause
