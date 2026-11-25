"""Testes das correcoes de seguranca do app.py.

Rodar com:  python -m pytest tests/
Cada teste usa um banco SQLite temporario; nada toca no envios.db real."""
import importlib
import os
import sys

import pytest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

SENHA = "senha-de-teste-123"


@pytest.fixture()
def app_mod(tmp_path, monkeypatch):
    for var in ("PRODUCAO", "RENDER", "MASTER_SENHA", "MASTER_LOGIN", "ZERAR_USUARIOS", "ZERAR_MASTER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("DB_PATH", str(tmp_path / "teste.db"))
    monkeypatch.setenv("CHAVE_SEGREDOS_PATH", str(tmp_path / "secret.key"))
    sys.modules.pop("app", None)
    modulo = importlib.import_module("app")
    modulo.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    yield modulo
    sys.modules.pop("app", None)


def criar_usuario(mod, login, perfil, loja_id=1):
    conn = mod.db()
    cur = conn.execute("INSERT INTO usuarios(nome,login,senha_hash,perfil,ativo,loja_id) VALUES(?,?,?,?,1,?)",
                       (login, login, mod.generate_password_hash(SENHA), perfil, loja_id))
    conn.commit(); conn.close()
    return cur.lastrowid


def entrar(cliente, login):
    resposta = cliente.post("/login", data={"login": login, "senha": SENHA})
    assert resposta.status_code == 302, resposta.data[:300]
    return resposta


@pytest.fixture()
def banco(app_mod, monkeypatch):
    monkeypatch.setenv("MASTER_SENHA", SENHA)
    monkeypatch.setenv("MASTER_LOGIN", "master")
    app_mod.init_db()
    ids = {
        "op1": criar_usuario(app_mod, "op1@enviosflash", "Operador de Balcão"),
        "op2": criar_usuario(app_mod, "op2@enviosflash", "Operador de Balcão"),
        "exp": criar_usuario(app_mod, "exp@enviosflash", "Expedidor"),
        "adm": criar_usuario(app_mod, "adm@enviosflash", "Administrador"),
    }
    conn = app_mod.db()
    cur = conn.execute("INSERT INTO cotacoes(criado_em,servico,operador_id) VALUES(?,?,?)",
                       ("2099-01-01T10:00:00", "PAC", ids["op2"]))
    ids["cotacao_op2"] = cur.lastrowid
    conn.commit(); conn.close()
    return ids


# ----------------- Senha Master embutida -----------------

def test_sem_master_senha_nao_cria_master_com_senha_padrao(app_mod):
    app_mod.init_db()
    conn = app_mod.db()
    masters = conn.execute("SELECT * FROM usuarios WHERE perfil='Master'").fetchall()
    conn.close()
    assert masters == []
    assert "scrypt:32768:8:1$6Z1tijV5bU5lkQ5w" not in open(os.path.join(RAIZ, "app.py"), encoding="utf-8").read()


def test_com_master_senha_cria_master(app_mod, monkeypatch):
    monkeypatch.setenv("MASTER_SENHA", SENHA)
    app_mod.init_db()
    conn = app_mod.db()
    master = conn.execute("SELECT * FROM usuarios WHERE perfil='Master'").fetchone()
    conn.close()
    assert master and app_mod.check_password_hash(master["senha_hash"], SENHA)


def test_primeiro_acesso_so_no_proprio_computador(app_mod):
    app_mod.init_db()
    cliente = app_mod.app.test_client()
    dados = {"nome": "Intruso", "login": "intruso", "senha": "12345678", "confirmacao": "12345678"}
    remoto = cliente.post("/primeiro-acesso", data=dados, environ_base={"REMOTE_ADDR": "203.0.113.9"})
    assert remoto.status_code == 403
    assert not app_mod.existe_master()
    local = cliente.post("/primeiro-acesso", data={**dados, "nome": "Dono", "login": "dono"},
                         environ_base={"REMOTE_ADDR": "127.0.0.1"})
    assert local.status_code == 302
    assert app_mod.existe_master()


# ----------------- Redirecionamento aberto no login -----------------

@pytest.mark.parametrize("destino", ["https://site-falso.com/login", "//site-falso.com", "/\\site-falso.com",
                                     " //site-falso.com", "/\t/site-falso.com", "javascript:alert(1)"])
def test_login_ignora_next_externo(app_mod, banco, destino):
    cliente = app_mod.app.test_client()
    resposta = cliente.post("/login?next=" + destino, data={"login": "adm@enviosflash", "senha": SENHA})
    assert resposta.status_code == 302
    assert resposta.headers["Location"] == "/"


def test_login_respeita_next_interno(app_mod, banco):
    cliente = app_mod.app.test_client()
    resposta = cliente.post("/login?next=/historico", data={"login": "adm@enviosflash", "senha": SENHA})
    assert resposta.headers["Location"] == "/historico"


# ----------------- /usuarios restrito a Master e Administrador -----------------

@pytest.mark.parametrize("login", ["op1@enviosflash", "exp@enviosflash"])
def test_operador_e_expedidor_nao_gerenciam_usuarios(app_mod, banco, login):
    cliente = app_mod.app.test_client()
    entrar(cliente, login)
    assert cliente.get("/usuarios").status_code == 403
    resposta = cliente.post("/usuarios", data={"acao": "senha", "usuario_id": banco["op2"], "senha": "tomada123"})
    assert resposta.status_code == 403
    conn = app_mod.db()
    hash_op2 = conn.execute("SELECT senha_hash FROM usuarios WHERE id=?", (banco["op2"],)).fetchone()[0]
    conn.close()
    assert app_mod.check_password_hash(hash_op2, SENHA)


def test_administrador_continua_gerenciando_usuarios(app_mod, banco):
    cliente = app_mod.app.test_client()
    entrar(cliente, "adm@enviosflash")
    assert cliente.get("/usuarios").status_code == 200
    resposta = cliente.post("/usuarios", data={"acao": "senha", "usuario_id": banco["op2"], "senha": "nova-senha-1"})
    assert resposta.status_code == 302
    conn = app_mod.db()
    hash_op2 = conn.execute("SELECT senha_hash FROM usuarios WHERE id=?", (banco["op2"],)).fetchone()[0]
    conn.close()
    assert app_mod.check_password_hash(hash_op2, "nova-senha-1")


# ----------------- IDOR nas rotas de cotacao -----------------

ROTAS_COTACAO = [
    ("post", "/cotacao/{id}/aceitar"),
    ("get", "/cotacao/{id}/recuperar-rotulo"),
    ("get", "/rotulo-ppn-zebra/{id}"),
    ("get", "/rotulo-ppn-pdf/{id}"),
    ("get", "/etiqueta-correios/{id}"),
    ("post", "/etiqueta-correios/{id}"),
]


@pytest.mark.parametrize("metodo,rota", ROTAS_COTACAO)
def test_operador_nao_acessa_cotacao_de_outro_operador(app_mod, banco, metodo, rota):
    cliente = app_mod.app.test_client()
    entrar(cliente, "op1@enviosflash")
    resposta = getattr(cliente, metodo)(rota.format(id=banco["cotacao_op2"]))
    assert resposta.status_code == 403


@pytest.mark.parametrize("metodo,rota", [r for r in ROTAS_COTACAO if r[0] == "get"])
def test_dono_da_cotacao_e_expedidor_continuam_acessando(app_mod, banco, metodo, rota):
    for login in ("op2@enviosflash", "exp@enviosflash"):
        cliente = app_mod.app.test_client()
        entrar(cliente, login)
        resposta = getattr(cliente, metodo)(rota.format(id=banco["cotacao_op2"]))
        assert resposta.status_code in (200, 302), (login, rota, resposta.status_code)


# ----------------- XSS armazenado (F6 e comparacao de transportadoras) -----------------

def test_templates_escapam_dados_no_innerhtml():
    base = open(os.path.join(RAIZ, "templates", "base.html"), encoding="utf-8").read()
    index = open(os.path.join(RAIZ, "templates", "index.html"), encoding="utf-8").read()
    assert "function escaparHtml(" in base
    for campo in ("x.rastreio", "x.servico", "x.destinatario_nome", "x.operador"):
        assert f"<td>${{{campo}" not in base, campo
    assert "escaparHtml(x.destinatario_nome)" in base
    assert "${res.avisos.join(' · ')}" not in index
    assert "${e.message}" not in index
    assert "escaparHtml(o.transportadora)" in index
