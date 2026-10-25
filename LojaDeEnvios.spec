# -*- mode: python ; coding: utf-8 -*-


# data/ NAO e empacotada por inteiro de proposito: a pasta contem a chave privada
# de licencas (license_private.pem), a chave de segredos (secret.key) e os bancos
# do Financeiro AGF, que nao tem nada que fazer num pacote entregue ao cliente.
# O app.py so le estes arquivos de data/ — confira antes de acrescentar algo:
#   data/cepx.sqlite         base de CEP
#   data/tarifas/*.csv       precos a vista (tabela nacional)
a = Analysis(
    ['app.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('templates', 'templates'),
        ('static', 'static'),
        ('data/cepx.sqlite', 'data'),
        ('data/tarifas', 'data/tarifas'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='LojaDeEnvios',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='LojaDeEnvios',
)
