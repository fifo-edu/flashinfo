import base64
import copy
import csv
import http.cookiejar
import html
import io
import json
import math
import os
import re
import secrets
import sqlite3
import subprocess
import threading
import time
import traceback
import urllib.parse
import urllib.request
import urllib.error
import webbrowser
from datetime import datetime, timedelta, timezone
from functools import wraps

from cryptography.fernet import Fernet
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
# SECRET_KEY assina o cookie de sessao. O valor de desenvolvimento abaixo esta no
# codigo-fonte, entao quem o conhece consegue forjar uma sessao de Master: em
# producao a variavel de ambiente e obrigatoria e a aplicacao se recusa a subir
# sem ela. Gere uma com:
#   python -c "import secrets; print(secrets.token_hex(32))"
_secret_key = os.getenv("SECRET_KEY")
if not _secret_key:
    if os.getenv("PRODUCAO") == "1":
        raise RuntimeError(
            "Defina a variavel de ambiente SECRET_KEY antes de subir em producao. "
            'Gere uma com: python -c "import secrets; print(secrets.token_hex(32))"'
        )
    _secret_key = "loja-envios-local"
app.secret_key = _secret_key
csrf = CSRFProtect(app)

# Cookie de sessao: nunca legivel por JavaScript, nao acompanha requisicoes vindas
# de outros sites e, em producao, so trafega em HTTPS (local continua em http).
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("PRODUCAO") == "1",
)

_failed_logins = {}


# ----------------- Helpers de Criptografia -----------------
_cipher = None


def get_cipher():
    global _cipher
    if _cipher is not None:
        return _cipher
    # CHAVE_SEGREDOS_PATH aponta a chave em outro lugar (ex.: Secret File do Render em
    # /etc/secrets/secret.key); sem ela, usa data/secret.key da instalacao.
    key_path = os.getenv("CHAVE_SEGREDOS_PATH") or os.path.join(BASE_DIR, "data", "secret.key")
    if not os.path.exists(key_path):
        if os.getenv("PRODUCAO") == "1":
            raise RuntimeError("Arquivo secret.key ausente. A aplicação não pode subir em produção sem a chave simétrica.")
        key = Fernet.generate_key()
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        with open(key_path, "wb") as f:
            f.write(key)
    else:
        with open(key_path, "rb") as f:
            key = f.read()
    _cipher = Fernet(key)
    return _cipher


def encrypt_val(val):
    if not val:
        return val
    return get_cipher().encrypt(val.encode()).decode()


def decrypt_val(val):
    if not val:
        return val
    try:
        return get_cipher().decrypt(val.encode()).decode()
    except Exception:
        app.logger.warning("Segredo sem criptografia no banco; ele sera criptografado na proxima inicializacao.")
        return val


def esta_criptografado(val):
    try:
        get_cipher().decrypt(str(val).encode())
        return True
    except Exception:
        return False


# Chaves de `configuracoes` que guardam senhas e tokens. Ficam sempre criptografadas
# no banco; so o backend le o valor real. As telas recebem apenas SEGREDO_CONFIGURADO
# (ver settings_publicas), e quem grava esses campos e somente o Master.
CHAVES_SECRETAS = ("correios_codigo_acesso", "correios_atende_usuario", "correios_atende_senha",
                   "correios_atende_mcu", "correios_reversa_credencial",
                   "smtp_senha", "conectagov_client_secret", "pagseguro_token",
                   "mercadopago_access_token", "picpay_token", "stone_token")
SEGREDO_CONFIGURADO = "configurado"


# Credenciais que antes vinham das variaveis de ambiente. Agora ficam so nas telas
# Configuracoes/Integracoes (criptografadas no banco). Na inicializacao, o que ainda estiver
# no ambiente e importado para o banco; depois disso as variaveis podem ser apagadas do Render.
CREDENCIAIS_AMBIENTE = {
    "CORREIOS_USUARIO": "correios_usuario", "CORREIOS_CODIGO_ACESSO": "correios_codigo_acesso",
    "CORREIOS_CARTAO": "correios_cartao", "CORREIOS_CONTRATO": "correios_contrato", "CORREIOS_DR": "correios_dr",
    "CORREIOS_ATENDE_USUARIO": "correios_atende_usuario", "CORREIOS_ATENDE_SENHA": "correios_atende_senha",
    "CORREIOS_ATENDE_MCU": "correios_atende_mcu", "CONECTAGOV_CLIENT_ID": "conectagov_client_id",
    "CONECTAGOV_CLIENT_SECRET": "conectagov_client_secret", "CONECTAGOV_AMBIENTE": "conectagov_ambiente",
}
# No Correios Atende a variavel de ambiente tinha precedencia sobre a tela; nas demais, a tela.
CREDENCIAIS_AMBIENTE_PRECEDENTES = {"CORREIOS_ATENDE_USUARIO", "CORREIOS_ATENDE_SENHA", "CORREIOS_ATENDE_MCU"}


def importar_credenciais_do_ambiente(conn):
    """Copia para o banco (criptografado) as credenciais ainda definidas no ambiente,
    preservando o valor que o sistema efetivamente usava antes."""
    importadas = []
    for variavel, chave in CREDENCIAIS_AMBIENTE.items():
        valor = (os.getenv(variavel) or "").strip()
        if not valor:
            continue
        row = conn.execute("SELECT valor FROM configuracoes WHERE chave=?", (chave,)).fetchone()
        atual = (decrypt_val(row["valor"]) if chave in CHAVES_SECRETAS else row["valor"]) if row and row["valor"] else ""
        if atual == valor or (atual and variavel not in CREDENCIAIS_AMBIENTE_PRECEDENTES):
            continue
        conn.execute("INSERT INTO configuracoes(chave,valor) VALUES(?,?) ON CONFLICT(chave) DO UPDATE SET valor=excluded.valor",
                     (chave, encrypt_val(valor) if chave in CHAVES_SECRETAS else valor))
        importadas.append(variavel)
    if importadas:
        conn.execute("INSERT INTO logs_sistema(criado_em,usuario_id,usuario_nome,acao,detalhes) VALUES(?,?,?,?,?)",
                     (datetime.now().isoformat(timespec="seconds"), None, "Sistema",
                      "Credenciais importadas do ambiente", ", ".join(importadas)))
    return importadas


def criptografar_segredos_legados(conn):
    """Criptografa senhas e tokens gravados em texto puro antes da criptografia existir."""
    for chave in CHAVES_SECRETAS:
        row = conn.execute("SELECT valor FROM configuracoes WHERE chave=?", (chave,)).fetchone()
        if row and row["valor"] and not esta_criptografado(row["valor"]):
            conn.execute("UPDATE configuracoes SET valor=? WHERE chave=?", (encrypt_val(row["valor"]), chave))
    for row in conn.execute("SELECT id,segredo FROM integracoes WHERE COALESCE(segredo,'')<>''").fetchall():
        if not esta_criptografado(row["segredo"]):
            conn.execute("UPDATE integracoes SET segredo=? WHERE id=?", (encrypt_val(row["segredo"]), row["id"]))


# ----------------- Helper contra IDOR -----------------
def get_cotacao_segura(conn, cotacao_id):
    """Garante que o Operador de Balcão não acesse cotações de outros operadores"""
    cotacao = conn.execute("SELECT * FROM cotacoes WHERE id=?", (cotacao_id,)).fetchone()
    if not cotacao:
        conn.close()
        abort(404)
    if session.get("usuario", {}).get("perfil") == "Operador de Balcão":
        if cotacao["operador_id"] != session["usuario"]["id"]:
            conn.close()
            abort(403)
    return cotacao


# DB_PATH permite apontar o banco para um disco persistente em producao (ex.: Render).
DB = os.getenv("DB_PATH") or os.path.join(BASE_DIR, "envios.db")
# O banco se chamava balcao.db; uma instalacao antiga e renomeada na primeira execucao.
_DB_ANTIGO = os.path.join(BASE_DIR, "balcao.db")
if not os.getenv("DB_PATH") and not os.path.exists(DB) and os.path.exists(_DB_ANTIGO):
    for _sufixo in ("", "-wal", "-shm", "-journal"):
        if os.path.exists(_DB_ANTIGO + _sufixo):
            os.replace(_DB_ANTIGO + _sufixo, DB + _sufixo)
CEPX_DB = os.path.join(BASE_DIR, "data", "cepx.sqlite")
# Postagens, recepcoes e reversas criadas ate 15/10/2026 (antes desta data) foram testes: continuam no banco
# (nada e apagado), mas nao aparecem nas telas nem entram em fechamentos e acertos de contas.
DADOS_VALIDOS_DESDE = datetime.strptime(os.getenv("DADOS_VALIDOS_DESDE", "2026-10-16"), "%Y-%m-%d").date().isoformat()


def sem_testes(coluna="criado_em"):
    """Condicao SQL que deixa de fora os registros de teste (data validada acima, sem injecao)."""
    return f"COALESCE({coluna},'')>='{DADOS_VALIDOS_DESDE}'"


SERVICOS = {"PAC": "03298", "SEDEX": "03220", "SEDEX 10": "03158", "SEDEX 12": "03140"}
# Codigos a vista (balcao): a API de preco devolve a tarifa de balcao com eles.
SERVICOS_A_VISTA = {"PAC": "04510", "SEDEX": "04014", "SEDEX 10": "04790", "SEDEX 12": "04782"}


def db():
    conn = sqlite3.connect(DB, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def criar_tabelas_medidas(conn):
    """Medidas declaradas na criação (PPN/autorização) e conferências com as medidas reais do balcão.
    Também roda no primeiro uso, para bancos em que a inicialização não criou as tabelas."""
    conn.execute("""CREATE TABLE IF NOT EXISTS medidas_criacao(
        id INTEGER PRIMARY KEY, origem TEXT NOT NULL, codigo TEXT NOT NULL, objeto TEXT NOT NULL,
        peso_g REAL, comprimento REAL, largura REAL, altura REAL, peso_tarifado_g INTEGER,
        primeira_consulta_em TEXT, ultima_consulta_em TEXT, UNIQUE(origem, codigo, objeto))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS conferencias_medidas(
        id INTEGER PRIMARY KEY, criado_em TEXT NOT NULL, origem TEXT NOT NULL, codigo TEXT NOT NULL, objeto TEXT,
        criado_peso_g REAL, criado_comprimento REAL, criado_largura REAL, criado_altura REAL, criado_tarifado_g INTEGER,
        real_peso_g REAL, real_comprimento REAL, real_largura REAL, real_altura REAL, real_tarifado_g INTEGER,
        sem_divergencia INTEGER, problemas TEXT, usuario_id INTEGER, usuario_nome TEXT)""")


_tabelas_medidas_ok = False


def valor_recepcao_nas_cotacoes(conn):
    """Recepções gravadas antes de a cotação receber o valor cobrado: copia o valor da recepção."""
    conn.execute("""UPDATE cotacoes SET valor_cliente=(SELECT r.valor FROM recepcoes_objetos r WHERE r.cotacao_id=cotacoes.id),
            preco_vista=(SELECT r.valor FROM recepcoes_objetos r WHERE r.cotacao_id=cotacoes.id),
            lucro=(SELECT r.valor FROM recepcoes_objetos r WHERE r.cotacao_id=cotacoes.id), preco_contrato=0
        WHERE COALESCE(valor_cliente,0)=0 AND id IN (SELECT cotacao_id FROM recepcoes_objetos WHERE valor>0)""")


def garantir_tabelas_medidas():
    """Ajustes de banco que também rodam no primeiro uso, para bancos em que a inicialização não rodou."""
    global _tabelas_medidas_ok
    if not _tabelas_medidas_ok:
        conn = db(); criar_tabelas_medidas(conn); valor_recepcao_nas_cotacoes(conn); conn.commit(); conn.close()
        _tabelas_medidas_ok = True


def init_db(somente_estrutura=False):
    """somente_estrutura=True (Render sem PRODUCAO=1) cria tabelas e colunas e ajusta dados,
    sem ZERAR_* e sem tocar em segredos/criptografia (a chave ainda nao e persistente la)."""
    master_login = os.getenv("MASTER_LOGIN", "").strip() or "fifo.edu"
    master_senha_env = os.getenv("MASTER_SENHA", "").strip()
    if os.getenv("PRODUCAO") == "1" and not master_senha_env:
        raise RuntimeError("Vulnerabilidade Crítica: A variável MASTER_SENHA é obrigatória em produção para evitar contas com senha padrão.")
    if master_senha_env:
        master_hash = generate_password_hash(master_senha_env)
    else:
        master_hash = "scrypt:32768:8:1$6Z1tijV5bU5lkQ5w$255296e9b67690704288390a58e8103c0328d5bd52dca113f773fc72656026eecaad4c9fcd425d9951b05f8901d14e8066fc0ded3d0d9b047710548b3b2218b4"

    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS cotacoes(
          id INTEGER PRIMARY KEY, criado_em TEXT, cliente TEXT, documento TEXT,
          forma_pagamento TEXT, cep_origem TEXT, cep_destino TEXT, servico TEXT,
          peso INTEGER, comprimento REAL, largura REAL, altura REAL,
          preco_contrato REAL, preco_vista REAL, valor_cliente REAL, lucro REAL,
          prazo TEXT, modo TEXT, etiqueta TEXT, rastreio TEXT, destinatario TEXT,
          observacoes TEXT
        );
        CREATE TABLE IF NOT EXISTS configuracoes(
          chave TEXT PRIMARY KEY, valor TEXT
        );
        CREATE TABLE IF NOT EXISTS impressoes(
          id INTEGER PRIMARY KEY, criado_em TEXT, cotacao_id INTEGER, impressora TEXT,
          copias INTEGER, status TEXT, motivo TEXT, zpl TEXT
        );
        CREATE TABLE IF NOT EXISTS usuarios(
          id INTEGER PRIMARY KEY, nome TEXT NOT NULL, login TEXT UNIQUE NOT NULL,
          senha_hash TEXT NOT NULL, perfil TEXT NOT NULL, ativo INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS lojas(
          id INTEGER PRIMARY KEY, nome TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
          cnpj TEXT, ativo INTEGER DEFAULT 1, criado_em TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS licencas(
          id INTEGER PRIMARY KEY, loja_id INTEGER NOT NULL, chave TEXT UNIQUE NOT NULL,
          status TEXT DEFAULT 'Ativa', valida_de TEXT NOT NULL, valida_ate TEXT NOT NULL,
          criado_em TEXT NOT NULL, criado_por INTEGER
        );
        CREATE TABLE IF NOT EXISTS pedidos_suprimento(
          id INTEGER PRIMARY KEY, criado_em TEXT NOT NULL, estoque_id INTEGER NOT NULL,
          operador_id INTEGER NOT NULL, quantidade REAL NOT NULL, observacoes TEXT,
          status TEXT DEFAULT 'Pendente', atendido_em TEXT, atendido_por INTEGER
        );
        CREATE TABLE IF NOT EXISTS sangrias(
          id INTEGER PRIMARY KEY, criado_em TEXT NOT NULL, operador_id INTEGER NOT NULL,
          administrador_id INTEGER NOT NULL, valor REAL NOT NULL, observacoes TEXT
        );
        CREATE TABLE IF NOT EXISTS livro_caixa(
          id INTEGER PRIMARY KEY, criado_em TEXT NOT NULL, tipo TEXT NOT NULL,
          origem TEXT NOT NULL, origem_id INTEGER NOT NULL, descricao TEXT,
          valor REAL NOT NULL, operador_id INTEGER, administrador_id INTEGER,
          UNIQUE(origem, origem_id)
        );
        CREATE TABLE IF NOT EXISTS expedicoes(
          id INTEGER PRIMARY KEY, cotacao_id INTEGER UNIQUE NOT NULL, status TEXT DEFAULT 'Pendente',
          captado_por INTEGER, expedido_por INTEGER, captado_em TEXT, expedido_em TEXT, observacoes TEXT
        );
        CREATE TABLE IF NOT EXISTS integracoes(
          id INTEGER PRIMARY KEY, nome TEXT UNIQUE NOT NULL, tipo TEXT, status TEXT DEFAULT 'Inativa',
          endpoint TEXT, usuario TEXT, segredo TEXT, observacoes TEXT
        );
        CREATE TABLE IF NOT EXISTS sla_integracoes(
          id INTEGER PRIMARY KEY, integracao_id INTEGER NOT NULL, criado_em TEXT NOT NULL,
          sucesso INTEGER NOT NULL, tempo_ms INTEGER NOT NULL, opcoes INTEGER DEFAULT 0, erro TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_sla_integracoes ON sla_integracoes(integracao_id,criado_em);
        CREATE TABLE IF NOT EXISTS cargas_consolidadas(
          id INTEGER PRIMARY KEY, criado_em TEXT NOT NULL, origem_tipo TEXT NOT NULL,
          origem_referencia TEXT, cliente_documento TEXT, cliente_nome TEXT,
          quantidade_volumes INTEGER DEFAULT 0, peso_total REAL DEFAULT 0,
          status TEXT DEFAULT 'Recebida', dados_json TEXT,
          UNIQUE(origem_tipo, origem_referencia)
        );
        CREATE TABLE IF NOT EXISTS recepcoes_objetos(
          id INTEGER PRIMARY KEY, criado_em TEXT NOT NULL, cotacao_id INTEGER NOT NULL,
          codigo_objeto TEXT NOT NULL, cliente_nome TEXT, cliente_documento TEXT,
          valor REAL DEFAULT 0, forma_pagamento TEXT, operador_id INTEGER, operador_nome TEXT,
          observacoes TEXT, UNIQUE(cotacao_id)
        );
        CREATE TABLE IF NOT EXISTS romaneios(
          id INTEGER PRIMARY KEY, criado_em TEXT NOT NULL, transportadora TEXT NOT NULL,
          expedidor_id INTEGER, expedidor_nome TEXT, status TEXT DEFAULT 'Fechado'
        );
        CREATE TABLE IF NOT EXISTS faturas_clientes(
          id INTEGER PRIMARY KEY, criado_em TEXT NOT NULL, cliente_documento TEXT NOT NULL,
          cliente_nome TEXT NOT NULL, data_inicial TEXT, data_final TEXT, valor_total REAL,
          status TEXT DEFAULT 'Aberta', banco TEXT, boleto_referencia TEXT, criado_por TEXT
        );
        CREATE TABLE IF NOT EXISTS fatura_cliente_itens(
          id INTEGER PRIMARY KEY, fatura_id INTEGER NOT NULL, cotacao_id INTEGER NOT NULL UNIQUE,
          codigo_objeto TEXT, transportadora TEXT, servico TEXT, valor REAL
        );
        CREATE TABLE IF NOT EXISTS boletos_clientes(
          id INTEGER PRIMARY KEY, fatura_id INTEGER NOT NULL, criado_em TEXT NOT NULL,
          referencia TEXT UNIQUE NOT NULL, valor REAL NOT NULL, vencimento TEXT,
          status TEXT DEFAULT 'Pendente', baixado_em TEXT, motivo_baixa TEXT
        );
        CREATE TABLE IF NOT EXISTS cobrancas_email(
          id INTEGER PRIMARY KEY, fatura_id INTEGER NOT NULL, criado_em TEXT NOT NULL,
          destinatario TEXT, assunto TEXT, mensagem TEXT, status TEXT DEFAULT 'Pendente', enviado_em TEXT
        );
        CREATE TABLE IF NOT EXISTS baixas_bancarias(
          id INTEGER PRIMARY KEY, criado_em TEXT NOT NULL, referencia TEXT, valor REAL,
          data_pagamento TEXT, origem TEXT, status TEXT, detalhes TEXT
        );
        CREATE TABLE IF NOT EXISTS exportacoes_envios(
          id INTEGER PRIMARY KEY, criado_em TEXT NOT NULL, transportadora TEXT NOT NULL,
          data_inicial TEXT, data_final TEXT, formato TEXT DEFAULT 'CSV', usuario_nome TEXT,
          quantidade INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS estoque(
          id INTEGER PRIMARY KEY, item TEXT NOT NULL, sku TEXT UNIQUE NOT NULL, unidade TEXT DEFAULT 'un',
          quantidade REAL DEFAULT 0, minimo REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS estoque_caixa(
          id INTEGER PRIMARY KEY, estoque_id INTEGER NOT NULL, operador_id INTEGER NOT NULL,
          quantidade REAL NOT NULL, conferido_abertura REAL, conferido_fechamento REAL,
          status TEXT DEFAULT 'Transferido', transferido_em TEXT, aberto_em TEXT, fechado_em TEXT
        );
        CREATE TABLE IF NOT EXISTS movimentos_estoque(
          id INTEGER PRIMARY KEY, criado_em TEXT NOT NULL, estoque_id INTEGER NOT NULL,
          tipo TEXT NOT NULL, quantidade REAL NOT NULL, custo_unitario REAL DEFAULT 0,
          valor_total REAL DEFAULT 0, fornecedor TEXT, documento TEXT,
          operador_id INTEGER, operador_nome TEXT, observacoes TEXT
        );
        CREATE TABLE IF NOT EXISTS fluxo_caixa_eventos(
          id INTEGER PRIMARY KEY, criado_em TEXT NOT NULL, origem TEXT NOT NULL,
          origem_id INTEGER NOT NULL, tipo TEXT NOT NULL, descricao TEXT,
          valor REAL NOT NULL, status TEXT DEFAULT 'Pendente', payload_json TEXT,
          sincronizado_em TEXT, UNIQUE(origem,origem_id,tipo)
        );
        CREATE TABLE IF NOT EXISTS documentos_envio(
          id INTEGER PRIMARY KEY, cotacao_id INTEGER UNIQUE NOT NULL, tipo_documento TEXT DEFAULT 'declaracao',
          remetente_nome TEXT, remetente_documento TEXT, remetente_endereco TEXT,
          destinatario_endereco TEXT, numero_nota TEXT, chave_nfe TEXT, valor_nota REAL,
          conteudo_json TEXT, atualizado_em TEXT
        );
        CREATE TABLE IF NOT EXISTS ceps(
          cep TEXT PRIMARY KEY, logradouro TEXT, bairro TEXT, cidade TEXT, uf TEXT
        );
        CREATE TABLE IF NOT EXISTS cidades_uf(
          id INTEGER PRIMARY KEY, cidade TEXT NOT NULL, uf TEXT NOT NULL,
          codigo_ibge TEXT, cidade_normalizada TEXT,
          CHECK(LENGTH(uf)=2), UNIQUE(cidade_normalizada, uf)
        );
        CREATE INDEX IF NOT EXISTS idx_cidades_uf_busca ON cidades_uf(uf, cidade_normalizada);
        CREATE TABLE IF NOT EXISTS tarifas_enquadramento(
          origem_uf TEXT NOT NULL, origem_cidade TEXT NOT NULL,
          destino_uf TEXT NOT NULL, destino_cidade TEXT NOT NULL,
          grupo TEXT NOT NULL, base TEXT NOT NULL,
          PRIMARY KEY(origem_uf, origem_cidade, destino_uf, destino_cidade)
        );
        CREATE TABLE IF NOT EXISTS prazos_rota(
          origem_uf TEXT NOT NULL, origem_cidade TEXT NOT NULL,
          destino_uf TEXT NOT NULL, destino_cidade TEXT NOT NULL, servico TEXT NOT NULL,
          prazo TEXT NOT NULL, atualizado_em TEXT,
          PRIMARY KEY(origem_uf, origem_cidade, destino_uf, destino_cidade, servico)
        );
        CREATE TABLE IF NOT EXISTS tarifas_precos(
          id INTEGER PRIMARY KEY, servico TEXT NOT NULL, codigo_servico TEXT NOT NULL,
          base TEXT NOT NULL, grupo TEXT NOT NULL, peso_min INTEGER NOT NULL, peso_max INTEGER NOT NULL,
          preco REAL NOT NULL, kg_adicional REAL NOT NULL, vigencia TEXT, fonte TEXT,
          CHECK(base IN ('CAPITAL','INTERIOR')),
          CHECK(grupo IN ('LOCAL','ESTADUAL','N1','N2','N3','N4','N5','N6')),
          UNIQUE(servico, base, grupo, peso_min)
        );
        CREATE TABLE IF NOT EXISTS tarifas_parametros(
          servico TEXT NOT NULL, chave TEXT NOT NULL, valor TEXT NOT NULL, descricao TEXT, fonte TEXT,
          PRIMARY KEY(servico, chave)
        );
        CREATE TABLE IF NOT EXISTS logs_sistema(
          id INTEGER PRIMARY KEY, criado_em TEXT, usuario_id INTEGER, usuario_nome TEXT,
          acao TEXT, detalhes TEXT
        );
        CREATE TABLE IF NOT EXISTS clientes(
          id INTEGER PRIMARY KEY, documento TEXT UNIQUE NOT NULL, nome TEXT NOT NULL, cep TEXT,
          rua TEXT, numero TEXT, complemento TEXT, bairro TEXT, cidade TEXT, uf TEXT, atualizado_em TEXT
        );
        CREATE TABLE IF NOT EXISTS prepostagens(
          id INTEGER PRIMARY KEY, cotacao_id INTEGER UNIQUE NOT NULL, ppn_id TEXT UNIQUE,
          codigo_etiqueta TEXT UNIQUE, status TEXT, resposta_json TEXT, criado_em TEXT,
          rotulo BLOB, rotulo_mime TEXT
        );
        CREATE TABLE IF NOT EXISTS servicos_adicionais_correios(
          codigo_produto TEXT NOT NULL, codigo TEXT NOT NULL, nome TEXT NOT NULL,
          valor REAL DEFAULT 0, atualizado_em TEXT, PRIMARY KEY(codigo_produto,codigo)
        );
        CREATE TABLE IF NOT EXISTS cotacao_produtos(
          id INTEGER PRIMARY KEY, cotacao_id INTEGER NOT NULL, estoque_caixa_id INTEGER NOT NULL,
          estoque_id INTEGER NOT NULL, produto TEXT NOT NULL, quantidade REAL NOT NULL,
          valor_unitario REAL NOT NULL, custo_unitario REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS contatos_envio(
          id INTEGER PRIMARY KEY, tipo TEXT NOT NULL, documento TEXT NOT NULL, nome TEXT NOT NULL,
          cep TEXT, rua TEXT, numero TEXT, complemento TEXT, bairro TEXT, cidade TEXT, uf TEXT,
          atualizado_em TEXT, UNIQUE(tipo,documento), CHECK(tipo IN ('Remetente','Destinatário'))
        );
        CREATE INDEX IF NOT EXISTS idx_contatos_envio_nome ON contatos_envio(tipo,nome);
        CREATE TABLE IF NOT EXISTS enderecos_contato(
          id INTEGER PRIMARY KEY, tipo TEXT NOT NULL, documento TEXT NOT NULL,
          cep TEXT NOT NULL, rua TEXT, numero TEXT NOT NULL DEFAULT '', complemento TEXT NOT NULL DEFAULT '',
          bairro TEXT, cidade TEXT, uf TEXT, atualizado_em TEXT,
          UNIQUE(tipo, documento, cep, numero, complemento)
        );
        CREATE TABLE IF NOT EXISTS conferencias_fatura(
          id INTEGER PRIMARY KEY, integracao TEXT NOT NULL, data_inicial TEXT NOT NULL,
          data_final TEXT NOT NULL, arquivo TEXT, criado_em TEXT, usuario_nome TEXT
        );
        CREATE TABLE IF NOT EXISTS conferencia_fatura_itens(
          id INTEGER PRIMARY KEY, conferencia_id INTEGER NOT NULL, etiqueta TEXT,
          valor_cobrado REAL DEFAULT 0, valor_esperado REAL DEFAULT 0,
          diferenca REAL DEFAULT 0, status TEXT, detalhes TEXT
        );
        CREATE TABLE IF NOT EXISTS triagem_destinos(
          id INTEGER PRIMARY KEY, cep_inicio TEXT NOT NULL, cep_final TEXT NOT NULL,
          posicao TEXT NOT NULL, tamanho TEXT DEFAULT '', observacoes TEXT,
          UNIQUE(cep_inicio,cep_final,posicao,tamanho)
        );
        CREATE INDEX IF NOT EXISTS idx_triagem_cep ON triagem_destinos(cep_inicio,cep_final,tamanho);
        CREATE TABLE IF NOT EXISTS triagem_plano(
          id INTEGER PRIMARY KEY, destino TEXT, direcao TEXT, categoria TEXT, formato TEXT,
          posicao TEXT NOT NULL, cep_inicio TEXT NOT NULL, cep_final TEXT NOT NULL,
          tamanho TEXT DEFAULT '', observacoes TEXT,
          UNIQUE(destino,direcao,categoria,formato,posicao,cep_inicio,cep_final,tamanho)
        );
        CREATE INDEX IF NOT EXISTS idx_triagem_plano_busca ON triagem_plano(categoria,formato,cep_inicio,cep_final,tamanho);
        CREATE TABLE IF NOT EXISTS notas_fiscais(
          id INTEGER PRIMARY KEY, cotacao_id INTEGER NOT NULL, tipo TEXT NOT NULL, ambiente TEXT NOT NULL,
          referencia TEXT UNIQUE NOT NULL, status TEXT, numero TEXT, codigo_verificacao TEXT, chave TEXT,
          url TEXT, caminho_xml TEXT, mensagem TEXT, valor REAL, payload_json TEXT, resposta_json TEXT,
          criado_em TEXT, atualizado_em TEXT, usuario_nome TEXT, UNIQUE(cotacao_id, tipo)
        );
        """
    )
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(cotacoes)").fetchall()}
    for name in ["documento", "forma_pagamento", "etiqueta", "rastreio", "destinatario", "observacoes",
                 "tipo_entrega", "ponto_retirada", "destinatario_nome", "destinatario_rua",
                 "destinatario_bairro", "destinatario_cidade", "destinatario_uf", "destinatario_numero",
                 "destinatario_complemento", "custo_produtos", "remetente_nome", "remetente_rua",
                 "remetente_bairro", "remetente_cidade", "remetente_uf", "remetente_numero",
                 "remetente_complemento", "possui_nf", "remetente_documento", "destinatario_documento",
                 "possui_bateria", "deseja_seguro", "valor_seguro", "valor_declarado", "tipo_embalagem"]:
        if name not in cols:
            conn.execute(f"ALTER TABLE cotacoes ADD COLUMN {name} TEXT")
    pre_cols = {row["name"] for row in conn.execute("PRAGMA table_info(prepostagens)").fetchall()}
    for name, tipo_coluna in [("rotulo", "BLOB"), ("rotulo_mime", "TEXT")]:
        if name not in pre_cols:
            conn.execute(f"ALTER TABLE prepostagens ADD COLUMN {name} {tipo_coluna}")
    estoque_cols = {row["name"] for row in conn.execute("PRAGMA table_info(estoque)").fetchall()}
    for name in ["preco_venda", "custo_unitario"]:
        if name not in estoque_cols:
            conn.execute(f"ALTER TABLE estoque ADD COLUMN {name} REAL DEFAULT 0")
    for name in ["ncm", "cfop"]:
        if name not in estoque_cols:
            conn.execute(f"ALTER TABLE estoque ADD COLUMN {name} TEXT")
    # A primeira versao de notas_fiscais tinha uma nota por atendimento; agora e uma por tipo (NFS-e e NFC-e).
    sql_notas = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='notas_fiscais'").fetchone()
    if sql_notas and "cotacao_id INTEGER UNIQUE" in sql_notas["sql"]:
        conn.execute("ALTER TABLE notas_fiscais RENAME TO notas_fiscais_antiga")
        conn.execute("""CREATE TABLE notas_fiscais(
          id INTEGER PRIMARY KEY, cotacao_id INTEGER NOT NULL, tipo TEXT NOT NULL, ambiente TEXT NOT NULL,
          referencia TEXT UNIQUE NOT NULL, status TEXT, numero TEXT, codigo_verificacao TEXT, chave TEXT,
          url TEXT, caminho_xml TEXT, mensagem TEXT, valor REAL, payload_json TEXT, resposta_json TEXT,
          criado_em TEXT, atualizado_em TEXT, usuario_nome TEXT, UNIQUE(cotacao_id, tipo))""")
        conn.execute("INSERT INTO notas_fiscais SELECT * FROM notas_fiscais_antiga")
        conn.execute("DROP TABLE notas_fiscais_antiga")
    caixa_cols = {row["name"] for row in conn.execute("PRAGMA table_info(estoque_caixa)").fetchall()}
    if "saldo" not in caixa_cols:
        conn.execute("ALTER TABLE estoque_caixa ADD COLUMN saldo REAL")
        conn.execute("UPDATE estoque_caixa SET saldo=quantidade WHERE saldo IS NULL")
    usuario_cols = {row["name"] for row in conn.execute("PRAGMA table_info(usuarios)").fetchall()}
    if "sessao_token" not in usuario_cols:
        conn.execute("ALTER TABLE usuarios ADD COLUMN sessao_token TEXT")
    if "loja_id" not in usuario_cols:
        conn.execute("ALTER TABLE usuarios ADD COLUMN loja_id INTEGER")
    loja_cols = {row["name"] for row in conn.execute("PRAGMA table_info(lojas)").fetchall()}
    expedicao_cols = {row["name"] for row in conn.execute("PRAGMA table_info(expedicoes)").fetchall()}
    if "romaneio_id" not in expedicao_cols: conn.execute("ALTER TABLE expedicoes ADD COLUMN romaneio_id INTEGER")
    contato_cols = {row["name"] for row in conn.execute("PRAGMA table_info(contatos_envio)").fetchall()}
    if "pode_faturar" not in contato_cols: conn.execute("ALTER TABLE contatos_envio ADD COLUMN pode_faturar INTEGER DEFAULT 0")
    for name, tipo_coluna in [("limite_faturado", "REAL DEFAULT 0"), ("faturado_bloqueado", "INTEGER DEFAULT 0"),
                              ("bloqueado_em", "TEXT"), ("email", "TEXT")]:
        if name not in contato_cols: conn.execute(f"ALTER TABLE contatos_envio ADD COLUMN {name} {tipo_coluna}")
    cliente_cols = {row["name"] for row in conn.execute("PRAGMA table_info(clientes)").fetchall()}
    if "pode_faturar" not in cliente_cols: conn.execute("ALTER TABLE clientes ADD COLUMN pode_faturar INTEGER DEFAULT 0")
    for name, tipo_coluna in [("limite_faturado", "REAL DEFAULT 0"), ("faturado_bloqueado", "INTEGER DEFAULT 0"),
                              ("bloqueado_em", "TEXT"), ("email", "TEXT")]:
        if name not in cliente_cols: conn.execute(f"ALTER TABLE clientes ADD COLUMN {name} {tipo_coluna}")
    fatura_cols = {row["name"] for row in conn.execute("PRAGMA table_info(faturas_clientes)").fetchall()}
    for name, tipo_coluna in [("vencimento", "TEXT"), ("pago_em", "TEXT"), ("email", "TEXT")]:
        if name not in fatura_cols: conn.execute(f"ALTER TABLE faturas_clientes ADD COLUMN {name} {tipo_coluna}")
    cotacao_cols = {row["name"] for row in conn.execute("PRAGMA table_info(cotacoes)").fetchall()}
    for name in ["documento_fiscal", "servicos_adicionais"]:
        if name not in cotacao_cols:
            conn.execute(f"ALTER TABLE cotacoes ADD COLUMN {name} TEXT")
    if "valor_adicionais" not in cotacao_cols:
        conn.execute("ALTER TABLE cotacoes ADD COLUMN valor_adicionais REAL DEFAULT 0")
    for name, tipo_coluna in [("operador_id", "INTEGER"), ("operador_nome", "TEXT")]:
        if name not in cotacao_cols:
            conn.execute(f"ALTER TABLE cotacoes ADD COLUMN {name} {tipo_coluna}")
    for name, tipo_coluna in [("transportadora", "TEXT DEFAULT 'Correios'"),
                              ("servico_transportadora", "TEXT"), ("cotacao_externa_id", "TEXT")]:
        if name not in cotacao_cols:
            conn.execute(f"ALTER TABLE cotacoes ADD COLUMN {name} {tipo_coluna}")
    if "transacao" not in cotacao_cols:
        conn.execute("ALTER TABLE cotacoes ADD COLUMN transacao TEXT")
    caixa_livro_cols = {row["name"] for row in conn.execute("PRAGMA table_info(livro_caixa)").fetchall()}
    if "transacao" not in caixa_livro_cols:
        conn.execute("ALTER TABLE livro_caixa ADD COLUMN transacao TEXT")
    # Postagens ja criadas na PPN antes do numero de transacao: recebem o numero e o lancamento do lucro.
    for postada in conn.execute("""SELECT c.*,p.criado_em postado_em FROM cotacoes c JOIN prepostagens p
                                   ON p.cotacao_id=c.id WHERE p.ppn_id IS NOT NULL AND p.ppn_id<>''
                                   AND """ + sem_testes("c.criado_em") + """ AND NOT EXISTS(SELECT 1 FROM livro_caixa l WHERE l.origem='Postagem'
                                   AND l.origem_id=c.id)""").fetchall():
        lancar_lucro_postagem(conn, postada, postada["postado_em"])

    defaults = {
        "empresa_nome": "Flash House Info",
        "empresa_subtitulo": "Sistema de Balcão",
        "empresa_cnpj": "",
        "empresa_endereco": "",
        "empresa_telefone": "",
        "empresa_email": "",
        "mensagem_recibo": "Obrigado pela preferência!",
        "zebra_nome": "Zebra Balcão Principal",
        "zebra_conexao": "USB / Driver local",
        "zebra_linguagem": "ZPL",
        "zebra_tamanho": "100 x 150 mm",
        "zebra_dpi": "203",
        "zebra_automatica": "1",
        "correios_modo": "demo",
        "correios_usuario": "",
        "correios_codigo_acesso": "",
        "correios_cartao": "",
        "correios_contrato": "",
        "correios_dr": "",
        "correios_codigo_pac": "03298",
        "correios_codigo_sedex": "03220",
        "correios_codigo_sedex10": "03158",
        "correios_codigo_sedex12": "03140",
        "correios_reversa_credencial": "",
        "correios_atende_usuario": "",
        "correios_atende_senha": "",
        "correios_atende_mcu": "",
        "correios_reversa_status": "Não testada",
        "correios_reversa_validada_em": "",
        "preco_logistica_reversa": "0",
        "preco_recepcao_objeto": "0",
        "impressora_etiquetas": "",
        "impressora_recibos": "",
        "impressora_romaneios": "",
        "impressora_relatorios": "",
        "empresa_cep": "", "empresa_rua": "", "empresa_numero": "S/N",
        "empresa_complemento": "", "empresa_bairro": "", "empresa_cidade": "", "empresa_uf": "",
        "banco_integrado": "",
        "email_cobranca": "",
        "smtp_servidor": "smtp.lojadeenvios.com.br",
        "smtp_porta": "587",
        "smtp_usuario": "",
        "smtp_senha": "",
        "mensagem_cobranca_padrao": "Olá, {cliente}. Sua fatura {fatura} no valor de {valor} está disponível para pagamento.",
        "margem_padrao": "5",
        "tipo_margem_padrao": "fixa",
        "pagseguro_ativo": "0",
        "pagseguro_email": "",
        "pagseguro_token": "",
        "mercadopago_ativo": "0",
        "mercadopago_public_key": "",
        "mercadopago_access_token": "",
        "picpay_ativo": "0", "picpay_client_id": "", "picpay_token": "",
        "stone_ativo": "0", "stone_client_id": "", "stone_token": "",
        "empresa_inscricao_municipal": "",
        "nfse_codigo_municipio": "",
        "nfse_codigo_tributacao_nacional": "260101",
        "nfse_codigo_nbs": "",
        "nfse_aliquota": "5",
        "nfse_opcao_simples": "3",
        "nfse_regime_simples": "1",
        "nfce_cfop": "5102",
        "nfce_icms_origem": "0",
        "nfce_icms_situacao": "102",
        "nfce_pis_cofins_situacao": "49",
        "nfse_descricao": "Serviço de envio {servico} - objeto {objeto} - atendimento {atendimento}",
    }
    for key, value in defaults.items():
        conn.execute("INSERT OR IGNORE INTO configuracoes(chave, valor) VALUES (?, ?)", (key, value))

    conn.execute("""INSERT OR IGNORE INTO contatos_envio(tipo,documento,nome,cep,rua,numero,complemento,bairro,cidade,uf,atualizado_em)
                    SELECT 'Remetente',documento,nome,cep,rua,numero,complemento,bairro,cidade,uf,atualizado_em
                    FROM clientes WHERE documento<>''""")
    conn.execute("""INSERT OR IGNORE INTO contatos_envio(tipo,documento,nome,cep,rua,numero,complemento,bairro,cidade,uf,atualizado_em)
                    SELECT 'Destinatário',REPLACE(REPLACE(REPLACE(destinatario_documento,'.',''),'-',''),'/',''),
                           destinatario_nome,cep_destino,destinatario_rua,destinatario_numero,destinatario_complemento,
                           destinatario_bairro,destinatario_cidade,destinatario_uf,criado_em
                    FROM cotacoes WHERE COALESCE(destinatario_documento,'')<>''""")
    # Enderecos por contato: o endereco atual de cada contato e os ja usados em cotacoes.
    conn.execute("""INSERT OR IGNORE INTO enderecos_contato(tipo,documento,cep,rua,numero,complemento,bairro,cidade,uf,atualizado_em)
                    SELECT tipo,documento,cep,rua,COALESCE(numero,''),COALESCE(complemento,''),bairro,cidade,uf,atualizado_em
                    FROM contatos_envio WHERE COALESCE(cep,'')<>''""")
    for tipo, prefixo, cep in (("Remetente", "remetente", "cep_origem"), ("Destinatário", "destinatario", "cep_destino")):
        conn.execute(f"""INSERT OR IGNORE INTO enderecos_contato(tipo,documento,cep,rua,numero,complemento,bairro,cidade,uf,atualizado_em)
                         SELECT '{tipo}',REPLACE(REPLACE(REPLACE({prefixo}_documento,'.',''),'-',''),'/',''),
                                {cep},{prefixo}_rua,COALESCE({prefixo}_numero,''),COALESCE({prefixo}_complemento,''),
                                {prefixo}_bairro,{prefixo}_cidade,{prefixo}_uf,criado_em
                         FROM cotacoes WHERE COALESCE({prefixo}_documento,'')<>'' AND COALESCE({cep},'')<>''""")

    # ZERAR_USUARIOS=1 apaga todos os usuarios na inicializacao (uso unico, para
    # reiniciar o cadastro em producao); remova a variavel logo depois.
    if not somente_estrutura and os.getenv("ZERAR_USUARIOS") == "1":
        conn.execute("DELETE FROM usuarios")
    # ZERAR_MASTER=1 apaga apenas a conta Master (senha perdida); ela sera
    # recriada com MASTER_LOGIN e MASTER_SENHA.
    if not somente_estrutura and os.getenv("ZERAR_MASTER") == "1":
        conn.execute("DELETE FROM usuarios WHERE perfil='Master'")
    agora = datetime.now().isoformat(timespec="seconds")
    conn.execute("""INSERT OR IGNORE INTO lojas(id,nome,email,criado_em)
                    VALUES(1,'Loja Principal','principal@lojadeenvios',?)""", (agora,))
    conn.execute("UPDATE usuarios SET loja_id=1 WHERE loja_id IS NULL")
    conn.execute("UPDATE usuarios SET perfil='Operador de Balcão' WHERE perfil='Operador de Caixa'")
    criar_tabelas_medidas(conn)
    valor_recepcao_nas_cotacoes(conn)
    if not conn.execute("SELECT 1 FROM usuarios WHERE perfil='Master' AND ativo=1 LIMIT 1").fetchone():
        login_existente = conn.execute("SELECT 1 FROM usuarios WHERE login=?", (master_login,)).fetchone()
        if login_existente:
            conn.close()
            raise RuntimeError("O login configurado em MASTER_LOGIN já está em uso por outro usuário.")
        conn.execute("INSERT INTO usuarios(nome,login,senha_hash,perfil,ativo,loja_id) VALUES(?,?,?,'Master',1,1)",
                     ("Master", master_login, master_hash))
    conn.execute("""INSERT OR IGNORE INTO licencas(loja_id,chave,status,valida_de,valida_ate,criado_em)
                    VALUES(1,'LICENCA-MIGRACAO-V1','Ativa','2020-01-01','2099-12-31',?)""", (agora,))
    conectores = {
        "Correios": "", "Jadlog": "https://www.jadlog.com.br/embarcador/api/frete/valor",
        "Braspress": "https://api.braspress.com/v1/cotacao/calcular/json",
        "J&T": "https://openapi.jtjms-br.com", "Loggi": "https://api.loggi.com",
        "Total Express": "https://apis-docs.totalexpress.com.br/",
    }
    for nome, endpoint in conectores.items():
        conn.execute("INSERT OR IGNORE INTO integracoes(nome,tipo,status) VALUES(?,?,?)",
                     (nome, "Transportadora", "Ativa" if nome == "Correios" else "Inativa"))
        if endpoint:
            conn.execute("UPDATE integracoes SET endpoint=COALESCE(NULLIF(endpoint,''),?) WHERE nome=?", (endpoint, nome))
    for nome in ["PagSeguro", "Mercado Pago", "PicPay", "Stone"]:
        conn.execute("INSERT OR IGNORE INTO integracoes(nome,tipo,status) VALUES(?,?,?)",
                     (nome, "Pagamento", "Inativa"))
    plataformas = {
        "Amazon": ("Marketplace", "https://sellingpartnerapi-na.amazon.com", '{"autenticacao":"OAuth 2.0/LWA","marketplace":"Brasil","fluxos":["pedidos","estoque","rastreamento"]}'),
        "TikTok Shop": ("Marketplace", "https://open-api.tiktokglobalshop.com", '{"autenticacao":"OAuth 2.0","fluxos":["pedidos","produtos","estoque"]}'),
        "Tiny / Olist ERP": ("ERP", "https://api.tiny.com.br/public-api/v3", '{"autenticacao":"OAuth 2.0","fluxos":["pedidos","produtos","estoque"]}'),
        "Bling": ("ERP", "https://www.bling.com.br/Api/v3", '{"autenticacao":"OAuth 2.0","fluxos":["pedidos","produtos","estoque"]}'),
        "Olist": ("Marketplace", "https://partners-api.olist.com/v1", '{"autenticacao":"Token/OAuth","fluxos":["pedidos","produtos","estoque"]}'),
        "Temu": ("Marketplace", "", '{"autenticacao":"OAuth/token","documentacao":"portal do parceiro"}'),
        "Magalu": ("Marketplace", "", '{"autenticacao":"OAuth/token","documentacao":"portal do parceiro"}'),
        "Mercado Livre": ("Marketplace", "https://api.mercadolibre.com", '{"autenticacao":"OAuth 2.0","fluxos":["pedidos","produtos","estoque"]}'),
        "Minha Cidade Aqui": ("Marketplace", "", '{"autenticacao":"credenciais fornecidas pelo parceiro"}'),
        "Intelipost": ("Integrador de Frete", "https://api.intelipost.com.br/api/v1", '{"autenticacao":"api-key","fluxos":["cotacao","pedido","rastreamento"]}'),
        "Cargo Sapiens": ("Integrador de Frete", "", '{"documentacao":"fornecida pelo parceiro"}'),
        "CargoFleet": ("Integrador de Frete", "", '{"documentacao":"fornecida pelo parceiro"}'),
        "Sinka": ("Integrador de Frete", "", '{"documentacao":"fornecida pelo parceiro"}'),
    }
    for nome, (tipo, endpoint, observacoes) in plataformas.items():
        conn.execute("INSERT OR IGNORE INTO integracoes(nome,tipo,status,endpoint,observacoes) VALUES(?,?,?,?,?)",
                     (nome, tipo, "Inativa", endpoint, observacoes))
        conn.execute("UPDATE integracoes SET tipo=? WHERE nome=?", (tipo, nome))
    conn.execute("""UPDATE cotacoes SET operador_id=COALESCE(operador_id,
                    (SELECT captado_por FROM expedicoes e WHERE e.cotacao_id=cotacoes.id))""")
    conn.execute("""UPDATE cotacoes SET operador_nome=COALESCE(operador_nome,
                    (SELECT nome FROM usuarios u WHERE u.id=cotacoes.operador_id),'Não identificado')""")
    agora = datetime.now().isoformat(timespec="seconds")
    vencidos = conn.execute("""SELECT DISTINCT cliente_documento FROM faturas_clientes
                                WHERE status IN ('Aberta','Vencida') AND vencimento IS NOT NULL
                                AND date(vencimento,'+2 day') < date('now','localtime')""").fetchall()
    for vencido in vencidos:
        documento = vencido["cliente_documento"]
        conn.execute("UPDATE contatos_envio SET pode_faturar=0,faturado_bloqueado=1,bloqueado_em=? WHERE tipo='Remetente' AND documento=?", (agora, documento))
        conn.execute("UPDATE clientes SET pode_faturar=0,faturado_bloqueado=1,bloqueado_em=? WHERE documento=?", (agora, documento))
        conn.execute("UPDATE faturas_clientes SET status='Vencida' WHERE cliente_documento=? AND status='Aberta' AND date(vencimento)<date('now','localtime')", (documento,))

    # Tarifas à vista nacionais: AR e MP vêm de data/tarifas/parametros.csv. O Valor Declarado
    # (019) é calculado por percentual no momento da cotação.
    carregar_tabelas_tarifas(conn)
    valor_param = lambda chave, padrao: float((conn.execute(
        "SELECT valor FROM tarifas_parametros WHERE chave=? LIMIT 1", (chave,)).fetchone() or [padrao])[0])
    for produto in ("03298", "03220"):
        for codigo, nome, valor in (
            ("001", "Aviso de Recebimento - AR", valor_param("adicional_001_valor", 8.10)),
            ("002", "Mão Própria - MP", valor_param("adicional_002_valor", 9.55)),
            ("019", "Valor Declarado", 0.0),
            ("095", "Restrição de transporte aéreo - DGR", 0.0),
        ):
            conn.execute(
                """INSERT INTO servicos_adicionais_correios(codigo_produto,codigo,nome,valor,atualizado_em)
                   VALUES(?,?,?,?,?) ON CONFLICT(codigo_produto,codigo) DO UPDATE SET
                   nome=excluded.nome,valor=excluded.valor,atualizado_em=excluded.atualizado_em""",
                (produto, codigo, nome, valor, "Tabela à vista Correios - vigência 12/04/2026"),
            )

    if not somente_estrutura:
        criptografar_segredos_legados(conn)
        importar_credenciais_do_ambiente(conn)
    conn.commit()
    conn.close()


TARIFAS_DIR = os.path.join(BASE_DIR, "data", "tarifas")


def numero_transacao(cotacao_id, quando):
    """Numero de transacao do aplicativo para cada postagem: TX + data da postagem + numero da cotacao."""
    return f"TX{str(quando)[:10].replace('-', '')}-{int(cotacao_id):06d}"


def lancar_lucro_postagem(conn, cotacao, quando=None):
    """Na postagem, grava o numero de transacao na cotacao e lanca no Livro Caixa o lucro dela:
    o valor cobrado do cliente (tabela a vista + adicionais + produtos) menos o que pagamos
    (preco do contrato dos Correios ou da transportadora + custo dos produtos). Lancamento
    unico por cotacao (UNIQUE origem/origem_id); devolve o numero da transacao."""
    quando = quando or datetime.now().isoformat(timespec="seconds")
    transacao = cotacao["transacao"] if "transacao" in cotacao.keys() and cotacao["transacao"] else \
        numero_transacao(cotacao["id"], quando)
    conn.execute("UPDATE cotacoes SET transacao=? WHERE id=?", (transacao, cotacao["id"]))
    cobrado = float(cotacao["valor_cliente"] or 0)
    pago = float(cotacao["preco_contrato"] or 0) + float(cotacao["custo_produtos"] or 0)
    lucro = round(cobrado - pago, 2)
    servico = cotacao["servico_transportadora"] if "servico_transportadora" in cotacao.keys() and \
        cotacao["servico_transportadora"] else cotacao["servico"]
    descricao = (f"Lucro da postagem {transacao} · {cotacao['transportadora'] or 'Correios'} {servico}: "
                 f"cobrado {brl(cobrado)}, pago {brl(pago)}")
    conn.execute("""INSERT OR IGNORE INTO livro_caixa(criado_em,tipo,origem,origem_id,descricao,valor,operador_id,transacao)
                    VALUES(?,?,?,?,?,?,?,?)""",
                 (quando, "Entrada" if lucro >= 0 else "Saída", "Postagem", cotacao["id"], descricao, abs(lucro),
                  cotacao["operador_id"], transacao))
    return transacao


def carregar_tabelas_tarifas(conn):
    """Recarrega os precos a vista (precos_vista.csv) e o enquadramento das
    rotas (enquadramento.csv, gerado por montar_enquadramento.py) a partir de
    data/tarifas/. Os CSVs sao a fonte: as tabelas sao apagadas e refeitas a
    cada inicializacao. Os prazos (prazos.csv) so completam prazos_rota: um
    prazo mais novo vindo da integracao nao e sobrescrito."""
    def ler(nome):
        caminho = os.path.join(TARIFAS_DIR, nome)
        if not os.path.exists(caminho):
            return None
        with open(caminho, encoding="utf-8-sig", newline="") as arquivo:
            return list(csv.DictReader(arquivo))

    enquadramento = ler("enquadramento.csv")
    if enquadramento is not None:
        conn.execute("DELETE FROM tarifas_enquadramento")
        # Linhas repetidas (nova rodada do script) prevalecem sobre as antigas; "?" nao e usado.
        conn.executemany("""INSERT OR REPLACE INTO tarifas_enquadramento(origem_uf,origem_cidade,destino_uf,
                            destino_cidade,grupo,base) VALUES(?,?,?,?,?,?)""",
                         [(r["origem_uf"], r["origem_cidade"], r["destino_uf"], r["destino_cidade"], r["grupo"], r["base"])
                          for r in enquadramento if r["grupo"] != "?"])
    prazos = ler("prazos.csv")
    if prazos is not None:
        conn.executemany("""INSERT INTO prazos_rota(origem_uf,origem_cidade,destino_uf,destino_cidade,servico,prazo,atualizado_em)
                            VALUES(?,?,?,?,?,?,?) ON CONFLICT(origem_uf,origem_cidade,destino_uf,destino_cidade,servico)
                            DO UPDATE SET prazo=excluded.prazo,atualizado_em=excluded.atualizado_em
                            WHERE excluded.atualizado_em > COALESCE(prazos_rota.atualizado_em,'')""",
                         [(r["origem_uf"], r["origem_cidade"], r["destino_uf"], r["destino_cidade"], r["servico"],
                           r["prazo"], r["consultado_em"]) for r in prazos if r["prazo"]])
    parametros = ler("parametros.csv")
    if parametros is not None:
        conn.execute("DELETE FROM tarifas_parametros")
        conn.executemany("""INSERT OR REPLACE INTO tarifas_parametros(servico,chave,valor,descricao,fonte)
                            VALUES(?,?,?,?,?)""",
                         [(r["servico"], r["chave"], r["valor"], r["descricao"], r["fonte"]) for r in parametros])
    precos = ler("precos_vista.csv")
    if precos is not None:
        conn.execute("DELETE FROM tarifas_precos")
        conn.executemany("""INSERT INTO tarifas_precos(servico,codigo_servico,base,grupo,peso_min,peso_max,
                            preco,kg_adicional,vigencia,fonte) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                         [(r["servico"], r["codigo_servico"], r["base"], r["grupo"], int(r["peso_min"]),
                           int(r["peso_max"]), float(r["preco"]), float(r["kg_adicional"]), r["vigencia"], r["fonte"])
                          for r in precos])


def settings():
    conn = db()
    data = {row["chave"]: row["valor"] for row in conn.execute("SELECT chave, valor FROM configuracoes")}
    conn.close()

    for chave in CHAVES_SECRETAS:
        if data.get(chave):
            data[chave] = decrypt_val(data[chave])

    partes = [f"{data.get('empresa_rua','')}, {data.get('empresa_numero') or 'S/N'}"] if data.get("empresa_rua") else []
    if data.get("empresa_complemento"): partes.append(data["empresa_complemento"])
    if data.get("empresa_bairro"): partes.append(data["empresa_bairro"])
    if data.get("empresa_cidade"): partes.append(f"{data['empresa_cidade']}/{data.get('empresa_uf','')}")
    if partes: data["empresa_endereco"] = " - ".join(partes)
    return data


def settings_publicas():
    """Configuracoes para templates: senhas e tokens nunca saem do backend."""
    data = settings()
    for chave in CHAVES_SECRETAS:
        if data.get(chave):
            data[chave] = SEGREDO_CONFIGURADO
    return data


def impressoras_windows():
    """Lista filas instaladas no Windows sem exigir bibliotecas adicionais."""
    if os.name != "nt": return []
    try:
        comando = ["powershell", "-NoProfile", "-Command",
                   "Get-CimInstance Win32_Printer | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress"]
        saida = subprocess.run(comando, capture_output=True, text=True, timeout=12, creationflags=0x08000000)
        if saida.returncode == 0 and saida.stdout.strip():
            dados = json.loads(saida.stdout.strip())
            return sorted([dados] if isinstance(dados, str) else dados, key=str.lower)
    except Exception:
        pass
    return []


def valores_sqlite(valores):
    """Dados vindos da PPN podem trazer listas ou objetos; o banco recebe texto nesses casos."""
    return tuple(json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list, tuple)) else v for v in valores)


def registrar_log(acao, detalhes=""):
    usuario = session.get("usuario") or {}
    conn = db()
    conn.execute("INSERT INTO logs_sistema(criado_em,usuario_id,usuario_nome,acao,detalhes) VALUES(?,?,?,?,?)",
                 (datetime.now().isoformat(timespec="seconds"), usuario.get("id"), usuario.get("nome", "Sistema"), acao, detalhes))
    conn.commit(); conn.close()


@app.errorhandler(500)
def erro_interno(erro):
    """Grava no log do sistema o motivo do erro (para consulta em /logs) e mostra uma página com o motivo."""
    original = getattr(erro, "original_exception", None) or erro
    motivo = f"{type(original).__name__}: {original}"
    try:
        registrar_log(f"Erro interno em {request.path}",
                      (motivo + " | " + " ".join(traceback.format_exception(original)[-4:]))[:2000])
    except Exception:
        app.logger.exception("Falha ao registrar o erro interno")
    return (f"<h1>Erro do servidor</h1><p>A operação não foi concluída. Motivo: {html.escape(motivo[:300])}</p>"
            f"<p><a href=\"{html.escape(request.path)}\">Voltar</a></p>"), 500


def licenca_valida(conn, loja_id):
    if not loja_id:
        return False
    hoje = datetime.now().date().isoformat()
    return conn.execute("""SELECT 1 FROM lojas l JOIN licencas x ON x.loja_id=l.id
        WHERE l.id=? AND l.ativo=1 AND x.status='Ativa'
        AND date(x.valida_de)<=date(?) AND date(x.valida_ate)>=date(?) LIMIT 1""",
        (loja_id, hoje, hoje)).fetchone() is not None


@app.after_request
def impedir_cache_login(response):
    if request.endpoint == "login":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response


@app.before_request
def ajustes_de_banco_no_primeiro_uso():
    if request.endpoint not in {"static", None}:
        garantir_tabelas_medidas()


@app.before_request
def bloquear_faturado_vencido():
    """Mantém o bloqueio ativo mesmo quando o servidor fica aberto por vários dias."""
    if request.endpoint in {"static", None}:
        return
    conn = db()
    try:
        vencidos = conn.execute("""SELECT DISTINCT cliente_documento FROM faturas_clientes
            WHERE status IN ('Aberta','Vencida') AND vencimento IS NOT NULL
            AND date(vencimento,'+2 day') < date('now','localtime')""").fetchall()
        agora = datetime.now().isoformat(timespec="seconds")
        for row in vencidos:
            conn.execute("UPDATE contatos_envio SET pode_faturar=0,faturado_bloqueado=1,bloqueado_em=? WHERE tipo='Remetente' AND documento=?",(agora,row["cliente_documento"]))
            conn.execute("UPDATE clientes SET pode_faturar=0,faturado_bloqueado=1,bloqueado_em=? WHERE documento=?",(agora,row["cliente_documento"]))
            conn.execute("UPDATE faturas_clientes SET status='Vencida' WHERE cliente_documento=? AND status='Aberta' AND date(vencimento)<date('now','localtime')",(row["cliente_documento"],))
        conn.commit()
    except sqlite3.OperationalError:
        pass
    finally:
        conn.close()


@app.before_request
def bloquear_login_simultaneo():
    if request.endpoint in {"static", "login", None} or not session.get("usuario"):
        return
    usuario = session["usuario"]
    token_sessao = session.get("sessao_token")
    conn = db()
    atual = conn.execute("SELECT sessao_token,ativo,loja_id,nome,login,perfil FROM usuarios WHERE id=?", (usuario["id"],)).fetchone()
    autorizada = bool(atual and licenca_valida(conn, atual["loja_id"]))
    conn.close()
    if not atual or not atual["ativo"] or not autorizada or not token_sessao or atual["sessao_token"] != token_sessao:
        session.clear()
        flash("Problemas com sua Licença. Contate o suporte." if atual and not autorizada else "Este usuário entrou em outra máquina. Faça login novamente para continuar.", "warning")
        return redirect(url_for("login"))
    # Mantem nome, login e perfil da sessao iguais ao cadastro (renomeacoes e perfil migrado).
    if any(usuario.get(campo) != atual[campo] for campo in ("nome", "login", "perfil")):
        session["usuario"] = {**usuario, "nome": atual["nome"], "login": atual["login"], "perfil": atual["perfil"]}


def salvar_contato(conn, tipo, documento, nome, cep, rua, numero, complemento, bairro, cidade, uf):
    documento = "".join(filter(str.isdigit, documento))
    conn.execute(
        """INSERT INTO contatos_envio(tipo,documento,nome,cep,rua,numero,complemento,bairro,cidade,uf,atualizado_em)
           VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tipo,documento) DO UPDATE SET nome=excluded.nome,
           cep=excluded.cep,rua=excluded.rua,numero=excluded.numero,complemento=excluded.complemento,
           bairro=excluded.bairro,cidade=excluded.cidade,uf=excluded.uf,atualizado_em=excluded.atualizado_em""",
        (tipo, documento, nome, cep, rua, numero, complemento, bairro, cidade, uf,
         datetime.now().isoformat(timespec="seconds")),
    )
    salvar_endereco(conn, tipo, documento, cep, rua, numero, complemento, bairro, cidade, uf)


def salvar_endereco(conn, tipo, documento, cep, rua, numero, complemento, bairro, cidade, uf):
    """Guarda o endereco na lista do contato (um contato pode ter varios)."""
    documento = "".join(filter(str.isdigit, documento or ""))
    cep = "".join(filter(str.isdigit, cep or ""))
    if not documento or len(cep) != 8:
        return
    conn.execute(
        """INSERT INTO enderecos_contato(tipo,documento,cep,rua,numero,complemento,bairro,cidade,uf,atualizado_em)
           VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tipo,documento,cep,numero,complemento) DO UPDATE SET
           rua=excluded.rua,bairro=excluded.bairro,cidade=excluded.cidade,uf=excluded.uf,atualizado_em=excluded.atualizado_em""",
        (tipo, documento, cep, rua, numero or "", complemento or "", bairro, cidade, uf,
         datetime.now().isoformat(timespec="seconds")),
    )


@app.context_processor
def inject_settings():
    publicas = settings_publicas()
    for chave in ("correios_reversa_credencial", "correios_atende_usuario", "correios_atende_senha", "correios_atende_mcu",
                  "pagseguro_token", "mercadopago_access_token", "picpay_token", "stone_token"):
        publicas.pop(chave, None)
    return {"config_empresa": publicas, "usuario_atual": session.get("usuario"), "hierarquia_ativa": HIERARQUIA_ATIVA}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("usuario"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


# Hierarquia de telas por perfil. Desligada temporariamente a pedido do Carlos (16/10/2026):
# todos os perfis acessam todas as telas da loja; só as telas exclusivas do Master continuam restritas.
# Para religar, volte para True.
HIERARQUIA_ATIVA = False


def perfis_permitidos(*perfis):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("usuario"):
                return redirect(url_for("login"))
            perfil_atual = session["usuario"]["perfil"]
            if not HIERARQUIA_ATIVA and set(perfis) != {"Master"}:
                return view(*args, **kwargs)
            if perfil_atual not in perfis and not (perfil_atual == "Master" and "Administrador" in perfis):
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def existe_master():
    conn = db()
    existe = conn.execute("SELECT 1 FROM usuarios WHERE perfil='Master' AND ativo=1 LIMIT 1").fetchone() is not None
    conn.close()
    return existe


@app.route("/primeiro-acesso", methods=["GET", "POST"])
def primeiro_acesso():
    """Cria a conta Master no primeiro uso do sistema (quando nao ha Master ativo)."""
    if existe_master():
        return redirect(url_for("login"))
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        login_master = request.form.get("login", "").strip()
        senha = request.form.get("senha", "")
        confirmacao = request.form.get("confirmacao", "")
        if not nome or not login_master or not senha:
            flash("Preencha nome, login e senha.", "danger")
        elif " " in login_master:
            flash("O login nao pode conter espacos.", "danger")
        elif len(senha) < 8:
            flash("A senha deve ter pelo menos 8 caracteres.", "danger")
        elif senha != confirmacao:
            flash("As senhas nao conferem.", "danger")
        else:
            conn = db()
            if conn.execute("SELECT 1 FROM usuarios WHERE login=?", (login_master,)).fetchone():
                conn.close(); flash("Esse login ja esta em uso.", "danger")
            else:
                conn.execute("INSERT INTO usuarios(nome,login,senha_hash,perfil,ativo,loja_id) VALUES(?,?,?,'Master',1,1)",
                             (nome, login_master, generate_password_hash(senha)))
                conn.commit(); conn.close()
                flash("Conta Master criada. Entre com o login e a senha definidos.", "success")
                return redirect(url_for("login"))
    return render_template("primeiro_acesso.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    erro_licenca = False
    if request.method == "GET":
        session.clear()
    if not existe_master():
        return redirect(url_for("primeiro_acesso"))

    ip = request.remote_addr
    now = time.time()
    attempts, lockout = _failed_logins.get(ip, (0, 0))
    if now < lockout:
        flash("Muitas tentativas falhas. Conta bloqueada temporariamente. Tente novamente em 5 minutos.", "danger")
        return render_template("login.html", erro_licenca=erro_licenca), 429
    if lockout:
        attempts = 0

    if request.method == "POST":
        conn = db()
        user = conn.execute("SELECT * FROM usuarios WHERE login=? AND ativo=1", (request.form.get("login", "").strip(),)).fetchone()
        if user and check_password_hash(user["senha_hash"], request.form.get("senha", "")):
            _failed_logins.pop(ip, None)
            if not licenca_valida(conn, user["loja_id"]):
                erro_licenca = True
                conn.close()
                return render_template("login.html", erro_licenca=erro_licenca), 403
            token_sessao = secrets.token_urlsafe(32)
            conn.execute("UPDATE usuarios SET sessao_token=? WHERE id=?", (token_sessao, user["id"]))
            conn.commit(); conn.close()
            session.clear()
            session["usuario"] = {"id": user["id"], "nome": user["nome"], "login": user["login"], "perfil": user["perfil"], "loja_id": user["loja_id"]}
            session["sessao_token"] = token_sessao
            destino_padrao = url_for("expedicao") if user["perfil"] == "Expedidor" else url_for("index")
            return redirect(request.args.get("next") or destino_padrao)
        conn.close()
        attempts += 1
        _failed_logins[ip] = (attempts, now + 300 if attempts >= 5 else 0)
        flash("Login ou senha inválidos.", "danger")
    return render_template("login.html", erro_licenca=erro_licenca)


@app.route("/trocar-senha", methods=["GET", "POST"])
@login_required
def trocar_senha():
    """Qualquer usuario logado troca a propria senha informando a senha atual."""
    if request.method == "POST":
        conn = db()
        user = conn.execute("SELECT * FROM usuarios WHERE id=?", (session["usuario"]["id"],)).fetchone()
        atual = request.form.get("senha_atual", "")
        nova = request.form.get("senha_nova", "")
        confirmacao = request.form.get("confirmacao", "")
        if not user or not check_password_hash(user["senha_hash"], atual):
            flash("Senha atual incorreta.", "danger")
        elif len(nova) < 6:
            flash("A nova senha deve ter pelo menos 6 caracteres.", "danger")
        elif nova != confirmacao:
            flash("As senhas não conferem.", "danger")
        else:
            conn.execute("UPDATE usuarios SET senha_hash=? WHERE id=?", (generate_password_hash(nova), user["id"]))
            conn.commit(); conn.close()
            flash("Senha alterada com sucesso.", "success")
            return redirect(url_for("index") if user["perfil"] != "Expedidor" else url_for("expedicao"))
        conn.close()
    return render_template("trocar_senha.html")


def validar_login_loja(login_usuario):
    if not login_usuario.endswith("@lojadeenvios") or login_usuario.count("@") != 1 or " " in login_usuario \
            or login_usuario == "@lojadeenvios":
        raise ValueError("O login deve ser um e-mail no domínio @lojadeenvios.")


@app.route("/meu-usuario", methods=["GET", "POST"])
@login_required
def meu_usuario():
    """Qualquer usuario logado altera o proprio nome e login informando a senha atual."""
    conn = db()
    user = conn.execute("SELECT * FROM usuarios WHERE id=?", (session["usuario"]["id"],)).fetchone()
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        login_novo = request.form.get("login", "").strip().lower()
        try:
            if not check_password_hash(user["senha_hash"], request.form.get("senha_atual", "")):
                raise ValueError("Senha atual incorreta.")
            if not nome or not login_novo:
                raise ValueError("Informe nome e login.")
            if login_novo != user["login"]:
                if user["perfil"] == "Master":
                    if " " in login_novo:
                        raise ValueError("O login nao pode conter espacos.")
                else:
                    validar_login_loja(login_novo)
            conn.execute("UPDATE usuarios SET nome=?, login=? WHERE id=?", (nome, login_novo, user["id"]))
            conn.commit()
            session["usuario"] = {**session["usuario"], "nome": nome, "login": login_novo}
            registrar_log("Alteração de usuário", f"{user['login']} -> {login_novo}")
            flash("Dados do usuário atualizados.", "success")
            conn.close()
            return redirect(url_for("meu_usuario"))
        except (ValueError, sqlite3.IntegrityError) as exc:
            conn.rollback()
            flash("Esse login já está em uso." if isinstance(exc, sqlite3.IntegrityError) else str(exc), "danger")
    conn.close()
    return render_template("meu_usuario.html", user=user)


@app.route("/logout", methods=["POST"])
def logout():
    usuario = session.get("usuario")
    token_sessao = session.get("sessao_token")
    if usuario and token_sessao:
        conn = db()
        conn.execute("UPDATE usuarios SET sessao_token=NULL WHERE id=? AND sessao_token=?",
                     (usuario["id"], token_sessao))
        conn.commit(); conn.close()
    session.clear()
    return redirect(url_for("login"))


def brl(value):
    return f"R$ {float(value or 0):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


app.jinja_env.filters["brl"] = brl


def data_br(value):
    texto = str(value or "")[:10]
    try:
        return datetime.strptime(texto, "%Y-%m-%d").strftime("%d/%m/%Y")
    except ValueError:
        return texto


def data_hora_br(value):
    texto = str(value or "").replace("T", " ")[:19]
    for formato in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(texto, formato).strftime("%d/%m/%Y %H:%M")
        except ValueError:
            continue
    return texto


app.jinja_env.filters["data_br"] = data_br
app.jinja_env.filters["data_hora_br"] = data_hora_br


def cep_formatado(value):
    numeros = "".join(filter(str.isdigit, str(value or "")))[:8]
    return f"{numeros[:5]}-{numeros[5:]}" if len(numeros) == 8 else numeros


app.jinja_env.filters["cep"] = cep_formatado


def documento_valido(documento):
    numeros = "".join(filter(str.isdigit, str(documento or "")))
    if len(numeros) == 11:
        if numeros == numeros[0] * 11:
            return False
        for tamanho in (9, 10):
            soma = sum(int(numeros[i]) * (tamanho + 1 - i) for i in range(tamanho))
            digito = 11 - soma % 11
            if digito >= 10:
                digito = 0
            if digito != int(numeros[tamanho]):
                return False
        return True
    if len(numeros) == 14:
        if numeros == numeros[0] * 14:
            return False
        for tamanho, pesos in ((12, [5,4,3,2,9,8,7,6,5,4,3,2]),
                               (13, [6,5,4,3,2,9,8,7,6,5,4,3,2])):
            resto = sum(int(numeros[i]) * pesos[i] for i in range(tamanho)) % 11
            digito = 0 if resto < 2 else 11 - resto
            if digito != int(numeros[tamanho]):
                return False
        return True
    return False


def dados_chave_fiscal(chave):
    chave = "".join(filter(str.isdigit, str(chave or "")))
    if len(chave) != 44:
        return {}
    return {"chave": chave, "uf_codigo": chave[0:2], "aamm": chave[2:6], "cnpj_emitente": chave[6:20],
            "modelo": chave[20:22], "serie": chave[22:25], "numero": chave[25:34],
            "tipo_emissao": chave[34:35], "codigo_numerico": chave[35:43], "digito": chave[43:44]}


def listar_adicionais_operacionais():
    conn = db()
    rows = conn.execute("SELECT codigo,nome,MAX(valor) valor FROM servicos_adicionais_correios GROUP BY codigo,nome ORDER BY nome").fetchall()
    conn.close()
    if rows:
        return [row for row in rows if row["codigo"] != "095"]
    return [
        {"codigo": "001", "nome": "Aviso de Recebimento", "valor": 0},
        {"codigo": "002", "nome": "Mão Própria", "valor": 0},
        {"codigo": "019", "nome": "Valor Declarado", "valor": 0},
    ]


def listar_meios_pagamento():
    meios = ["Dinheiro", "PIX", "Cartão de débito", "Cartão de crédito", "Transferência bancária", "Faturado", "Outro"]
    dados = settings()
    if dados.get("pagseguro_ativo") == "1":
        meios += ["PagSeguro - PIX", "PagSeguro - Débito", "PagSeguro - Crédito"]
    if dados.get("mercadopago_ativo") == "1":
        meios += ["Mercado Pago - PIX", "Mercado Pago - Débito", "Mercado Pago - Crédito"]
    if dados.get("picpay_ativo") == "1":
        meios += ["PicPay - PIX", "PicPay - Carteira", "PicPay - Crédito"]
    if dados.get("stone_ativo") == "1":
        meios += ["Stone - Débito", "Stone - Crédito", "Stone - PIX"]
    return meios


def testar_integracao_pagamento(nome, dados):
    """Valida credenciais sem criar cobranças ou movimentações financeiras."""
    headers = {"Accept": "application/json", "User-Agent": "Flash-House-Info/1.0"}
    if nome == "PagSeguro":
        token = dados.get("pagseguro_token", "")
        if not token: raise ValueError("Informe o token do PagSeguro.")
        headers["Authorization"] = f"Bearer {token}"
        url = "https://api.pagseguro.com/charges/fees/calculate?payment_methods=CREDIT_CARD&value=10000&max_installments=1"
        requisicao = urllib.request.Request(url, headers=headers)
    elif nome == "Mercado Pago":
        token = dados.get("mercadopago_access_token", "")
        if not token: raise ValueError("Informe o Access Token do Mercado Pago.")
        headers["Authorization"] = f"Bearer {token}"
        requisicao = urllib.request.Request("https://api.mercadolibre.com/users/me", headers=headers)
    elif nome == "PicPay":
        client_id, client_secret = dados.get("picpay_client_id", ""), dados.get("picpay_token", "")
        if not client_id or not client_secret: raise ValueError("Informe Client ID e Client Secret do PicPay.")
        corpo = json.dumps({"grant_type": "client_credentials", "client_id": client_id,
                            "client_secret": client_secret}).encode("utf-8")
        requisicao = urllib.request.Request("https://api.picpay.com/oauth2/token", data=corpo,
            headers={**headers, "Content-Type": "application/json"})
    elif nome == "Stone":
        client_id, token = dados.get("stone_client_id", ""), dados.get("stone_token", "")
        if not client_id or not token: raise ValueError("Informe Client ID e Access Token da Stone.")
        headers["Authorization"] = f"Bearer {token}"
        requisicao = urllib.request.Request("https://api.openbank.stone.com.br/api/v1/accounts", headers=headers)
    else:
        raise ValueError("Meio de pagamento não reconhecido.")
    try:
        with urllib.request.urlopen(requisicao, timeout=20) as resposta:
            if not 200 <= resposta.status < 300:
                raise ValueError(f"A operadora respondeu HTTP {resposta.status}.")
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise ValueError("Credenciais recusadas pela operadora.") from None
        raise ValueError(f"A operadora respondeu HTTP {exc.code}.") from None
    return True


def calcular_adicionais_a_vista(servico, codigos, valor_declarado):
    """Calcula adicionais cobrados do cliente pela tabela pública à vista dos Correios."""
    codigos = list(dict.fromkeys(codigos or []))
    conn = db()
    produto = codigo_servico_correios(servico)
    linhas = conn.execute(
        "SELECT codigo,nome,valor FROM servicos_adicionais_correios WHERE codigo_produto=?", (produto,)
    ).fetchall()
    cadastrados = {row["codigo"]: float(row["valor"] or 0) for row in linhas}
    nomes = {row["codigo"]: row["nome"] for row in linhas}
    conn.close()
    total = 0.0
    seguro = 0.0
    detalhados = []
    for codigo in codigos:
        if codigo == "019":
            limite = parametro_tarifa(servico, "valor_declarado_limite_max", 4477.36 if servico == "PAC" else 38057.59)
            if valor_declarado > limite:
                raise ValueError(f"O Valor Declarado máximo para {servico} é {brl(limite)}.")
            # Para encomendas à vista, o Ad Valorem (2%) incide só sobre o valor que
            # exceder a indenização automática (R$ 25,63), conforme as instruções da tabela.
            seguro = round(max(0.0, valor_declarado - parametro_tarifa(servico, "indenizacao_automatica", 25.63))
                           * parametro_tarifa(servico, "ad_valorem_percentual", .02), 2)
            total += seguro
            detalhados.append({"codigo": codigo, "nome": nomes.get(codigo, "Valor Declarado"), "valor": seguro})
        else:
            # AR (001) e MP (002) seguem a tabela (parametros.csv); DGR (095) não tem cobrança.
            valor = 0.0 if codigo == "095" else parametro_tarifa(servico, f"adicional_{codigo}_valor",
                                                                 cadastrados.get(codigo, 0.0))
            total += valor
            detalhados.append({"codigo": codigo, "nome": nomes.get(codigo, {
                "001": "Aviso de Recebimento", "002": "Mão Própria", "095": "DGR — bateria"
            }.get(codigo, f"Adicional {codigo}")), "valor": round(valor, 2)})
    return round(total, 2), seguro, detalhados


def localidade_cep(cep):
    """(uf, city_id, cidade) do CEP na base cepx, ou None se o CEP nao estiver nela."""
    cep = "".join(filter(str.isdigit, str(cep or "")))
    if len(cep) != 8 or not os.path.exists(CEPX_DB):
        return None
    cepx = sqlite3.connect(f"file:{CEPX_DB}?mode=ro", uri=True)
    consulta = """SELECT u.sigla, z.city_id, c.nome FROM ceps z JOIN states u ON u.id=z.uf_id
                  JOIN cities c ON c.id=z.city_id WHERE z.cep=?"""
    row = cepx.execute(consulta, (int(cep),)).fetchone()
    if not row:
        # CEP novo ou ausente da base: vale a cidade do CEP mais proximo com o mesmo prefixo de 5 digitos.
        base = int(cep[:5]) * 1000
        vizinho = cepx.execute("""SELECT cep FROM ceps WHERE cep BETWEEN ? AND ? ORDER BY ABS(cep-?) LIMIT 1""",
                               (base, base + 999, int(cep))).fetchone()
        row = cepx.execute(consulta, (vizinho[0],)).fetchone() if vizinho else None
    for digitos in (4, 3):
        if row:
            break
        # Prefixo de 5 digitos sem nenhum CEP na base (ex.: 01000-100, aceito pelos Correios): amplia
        # para 4 e 3 digitos, mas so quando a faixa inteira e de uma unica cidade.
        tamanho = 10 ** (8 - digitos)
        base = int(cep[:digitos]) * tamanho
        cidades = cepx.execute("""SELECT COUNT(DISTINCT city_id), MIN(cep) FROM ceps WHERE cep BETWEEN ? AND ?""",
                               (base, base + tamanho - 1)).fetchone()
        if cidades[0] == 1:
            row = cepx.execute(consulta, (cidades[1],)).fetchone()
    cepx.close()
    return row


def preco_vista(servico, grupo, base, peso):
    """Preco a vista da tabela nacional (tarifas_precos) para o grupo/base e o peso em gramas.
    Acima de 10 kg soma kg_adicional por kg (ou fracao) excedente."""
    conn = db()
    row = conn.execute("""SELECT preco FROM tarifas_precos WHERE servico=? AND base=? AND grupo=?
                          AND ? BETWEEN peso_min AND peso_max""",
                       (servico, base, grupo, peso)).fetchone()
    if row:
        conn.close()
        return float(row["preco"])
    ultima = conn.execute("""SELECT preco, kg_adicional, peso_max FROM tarifas_precos
                             WHERE servico=? AND base=? AND grupo=? ORDER BY peso_max DESC LIMIT 1""",
                          (servico, base, grupo)).fetchone()
    conn.close()
    if not ultima or peso <= ultima["peso_max"]:
        return None
    excedente = math.ceil((peso - ultima["peso_max"]) / 1000)
    return round(float(ultima["preco"]) + excedente * float(ultima["kg_adicional"]), 2)


def origem_tarifa_agencia(conn):
    """(uf, cidade) de onde a agencia posta: cidade do CEP da empresa (Configuracoes);
    sem ele, a primeira origem da tabela de enquadramento."""
    empresa = localidade_cep(settings().get("empresa_cep"))
    if empresa and conn.execute("SELECT 1 FROM tarifas_enquadramento WHERE origem_uf=? AND origem_cidade=? LIMIT 1",
                                (empresa[0], empresa[2])).fetchone():
        return empresa[0], empresa[2]
    # CEP da empresa vazio ou de cidade que nao e origem da tabela: vale a origem da tabela de enquadramento.
    row = conn.execute("SELECT origem_uf, origem_cidade FROM tarifas_enquadramento LIMIT 1").fetchone()
    return tuple(row) if row else None


def motivo_sem_tarifa_vista(cep_origem, cep_destino):
    """Explica por que a rota ficou sem preco a vista (CEP fora da base ou cidade sem enquadramento)."""
    destino = localidade_cep(cep_destino)
    if not destino:
        return f"CEP de destino {cep_destino[:5]}-{cep_destino[5:]} não encontrado na base de CEPs"
    conn = db()
    total = conn.execute("SELECT COUNT(*) FROM tarifas_enquadramento").fetchone()[0]
    agencia = origem_tarifa_agencia(conn)
    conn.close()
    if not total:
        return "tabela de enquadramento vazia no servidor"
    return f"sem enquadramento para {agencia[1] if agencia else '?'}/{agencia[0] if agencia else '?'} → {destino[2]}/{destino[0]}"


def tarifa_vista(servico, peso, cep_origem, cep_destino):
    """Preco a vista (balcao) dos Correios: cidade de origem e de destino pelo
    CEP (cepx), enquadramento da rota em tarifas_enquadramento e preco na
    tabela nacional. O objeto e postado na agencia: se a cidade do remetente
    nao for origem do enquadramento, vale a origem da agencia."""
    destino = localidade_cep(cep_destino)
    if not destino:
        return None
    origem = localidade_cep(cep_origem)
    conn = db()
    consulta = """SELECT grupo, base FROM tarifas_enquadramento WHERE origem_uf=? AND origem_cidade=?
                  AND destino_uf=? AND destino_cidade=?"""
    rota = conn.execute(consulta, (origem[0], origem[2], destino[0], destino[2])).fetchone() if origem else None
    if not rota:
        agencia = origem_tarifa_agencia(conn)
        rota = conn.execute(consulta, (*agencia, destino[0], destino[2])).fetchone() if agencia else None
    conn.close()
    if not rota:
        return None
    return preco_vista(servico, rota["grupo"], rota["base"], peso)


_TOKENS_CORREIOS = {}
_TOKENS_CORREIOS_LOCK = threading.Lock()


def token_correios(credencial=None):
    """Token da API dos Correios (cartao de postagem). Fica guardado em memoria
    por credencial e e reaproveitado ate 10 min antes de expirar (a API emite
    tokens de 24 h), para o F5 nao autenticar a cada consulta de preco/prazo."""
    conf = settings()
    user = conf.get("correios_usuario")
    password = credencial or conf.get("correios_codigo_acesso")
    card = conf.get("correios_cartao")
    contract = conf.get("correios_contrato")
    dr = conf.get("correios_dr")
    if not all([user, password, card]):
        raise RuntimeError("Credenciais dos Correios incompletas.")
    chave = (user, password, card, contract, dr)
    with _TOKENS_CORREIOS_LOCK:
        guardado = _TOKENS_CORREIOS.get(chave)
        if guardado and guardado[1] > time.monotonic():
            return guardado[0]
    raw = base64.b64encode(f"{user}:{password}".encode()).decode()
    body = {"numero": card}
    if contract:
        body["contrato"] = contract
    if dr:
        body["dr"] = int(dr)
    req = urllib.request.Request(
        "https://api.correios.com.br/token/v1/autentica/cartaopostagem",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Basic {raw}", "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as response:
        data = json.loads(response.read())
    token = data.get("token") or data.get("tokenAcesso")
    try:
        validade = (datetime.fromisoformat(data["expiraEm"]) - datetime.fromisoformat(data["emissao"])).total_seconds()
    except Exception:
        validade = 3600  # resposta sem emissao/expiraEm: guarda por 1 h
    if token and validade > 1200:
        with _TOKENS_CORREIOS_LOCK:
            _TOKENS_CORREIOS[chave] = (token, time.monotonic() + validade - 600)
    return token


def token_conectagov():
    """Obtem um token de acesso (client_credentials) do Conecta gov.br,
    para consumir a API Consulta CEP oficial (Cadastro Base de Enderecos,
    Correios/SERPRO). Credenciais (client_id/client_secret) sao as mesmas
    cadastradas pelo usuario no Gerenciador do Conecta gov.br para a sua
    aplicacao/orgao -- nao sao usuario/senha pessoal do gov.br."""
    conf = settings()
    client_id = conf.get("conectagov_client_id")
    client_secret = conf.get("conectagov_client_secret")
    if not all([client_id, client_secret]):
        raise RuntimeError("Credenciais do Conecta gov.br incompletas (client_id/client_secret).")
    raw = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    ambiente = conf.get("conectagov_ambiente") or "producao"
    base = ("https://h-apigateway.conectagov.estaleiro.serpro.gov.br" if ambiente == "homologacao"
            else "https://apigateway.conectagov.estaleiro.serpro.gov.br")
    req = urllib.request.Request(
        f"{base}/oauth2/jwt-token",
        data=b"grant_type=client_credentials",
        headers={"Authorization": f"Basic {raw}", "Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as response:
        data = json.loads(response.read())
    return data.get("access_token") or data.get("token")


def cep_conectagov_api(numero):
    """Consulta o CEP na API oficial Consulta CEP do Conecta gov.br
    (base cadastral dos Correios/SERPRO). Retorna None se nao encontrado;
    lanca RuntimeError em caso de falha de credenciais/rede, para o chamador
    decidir se cai para o proximo provedor."""
    conf = settings()
    ambiente = conf.get("conectagov_ambiente") or "producao"
    base = ("https://h-apigateway.conectagov.estaleiro.serpro.gov.br" if ambiente == "homologacao"
            else "https://apigateway.conectagov.estaleiro.serpro.gov.br")
    token = token_conectagov()
    url = f"{base}/api-cep/v1/consulta/cep/{numero}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 400:
            return None
        raise RuntimeError(detalhe_erro_correios(exc)) from exc
    if not data or not data.get("cidade") or not data.get("uf"):
        return None
    return {"logradouro": data.get("endereco") or "", "bairro": data.get("bairro") or "",
            "cidade": data.get("cidade") or "", "uf": data.get("uf") or ""}


def nivel_contrato_token(token):
    try:
        parte = token.split(".")[1]; parte += "=" * (-len(parte) % 4)
        dados = json.loads(base64.urlsafe_b64decode(parte.encode()).decode("utf-8"))
        return localizar_campo_ppn(dados, ["nivelContrato", "nivel", "categoriaContrato", "segmento"]) or "Não informado pela API"
    except Exception:
        return "Não informado pela API"


def codigo_servico_correios(servico):
    conf = settings()
    chave = {"PAC": "correios_codigo_pac", "SEDEX": "correios_codigo_sedex",
             "SEDEX 10": "correios_codigo_sedex10", "SEDEX 12": "correios_codigo_sedex12"}[servico]
    return (conf.get(chave) or SERVICOS[servico]).strip().zfill(5)


def detalhe_erro_correios(exc):
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code == 401:
            # Token guardado recusado (revogado/expirado antes da hora): a proxima chamada autentica de novo.
            with _TOKENS_CORREIOS_LOCK:
                _TOKENS_CORREIOS.clear()
        try:
            corpo = exc.read().decode("utf-8", errors="replace").strip()
            if corpo:
                try:
                    dados = json.loads(corpo)
                    corpo = dados.get("mensagem") or dados.get("message") or dados.get("msgs") or corpo
                except json.JSONDecodeError:
                    pass
                return f"HTTP {exc.code}: {corpo}"
        except Exception:
            pass
        return f"HTTP {exc.code}: {exc.reason}"
    return str(exc)


def preco_correios_api(servico, origem, destino, peso, comp, larg, alt, tipo_embalagem="Pacote", valor_declarado=0,
                       servicos_adicionais=None, codigo=None):
    token = token_correios()
    conf = settings()
    codigo = codigo or codigo_servico_correios(servico)
    params = {
        "cepDestino": destino, "cepOrigem": origem, "psObjeto": str(peso),
    }
    if tipo_embalagem == "Envelope":
        params["tpObjeto"] = "1"
    else:
        params.update({"tpObjeto": "2", "comprimento": str(comp), "largura": str(larg), "altura": str(alt)})
    if valor_declarado > 0:
        params["vlDeclarado"] = f"{valor_declarado:.2f}"
    if servicos_adicionais:
        params["servicosAdicionais"] = ",".join(servicos_adicionais)
    contrato = conf.get("correios_contrato")
    dr = conf.get("correios_dr")
    if contrato:
        params["nuContrato"] = contrato
    if dr:
        params["nuDR"] = dr
    url = f"https://api.correios.com.br/preco/v1/nacional/{codigo}?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(detalhe_erro_correios(exc)) from exc
    value = data.get("pcFinal") or data.get("precoFinal") or data.get("vlTotal")
    if value is None:
        raise RuntimeError("Resposta da API sem preço final reconhecido.")
    return float(str(value).replace(",", "."))


def prazo_api(servico, origem, destino, token=None):
    token = token or token_correios()
    codigo = codigo_servico_correios(servico)
    url = f"https://api.correios.com.br/prazo/v1/nacional/{codigo}?" + urllib.parse.urlencode(
        {"cepOrigem": origem, "cepDestino": destino}
    )
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(detalhe_erro_correios(exc)) from exc
    if isinstance(data, list): data = data[0] if data else {}
    if isinstance(data, dict):
        aninhado = data.get("prazo") or data.get("resultado")
        if isinstance(aninhado, list): aninhado = aninhado[0] if aninhado else {}
        if isinstance(aninhado, dict): data = {**data, **aninhado}
    prazo = data.get("prazoEntrega") or data.get("nuPrazo") or data.get("prazo") or data.get("diasUteis")
    if prazo in (None, ""):
        raise RuntimeError("A API dos Correios respondeu sem o campo de prazo de entrega.")
    return f"{prazo} dia(s)"


def prazo_entrega(servico, origem, destino):
    """Prazo da integracao (API de prazo dos Correios); cada resposta fica
    guardada em prazos_rota por cidade de origem/destino. Se a integracao
    estiver indisponivel, devolve o ultimo prazo guardado para a rota.
    Sem integracao e sem prazo guardado, repassa o erro da integracao."""
    rota_origem, rota_destino = localidade_cep(origem), localidade_cep(destino)
    chave = (rota_origem[0], rota_origem[2], rota_destino[0], rota_destino[2], servico) if rota_origem and rota_destino else None
    try:
        prazo = prazo_api(servico, origem, destino)
    except Exception:
        if chave:
            conn = db()
            row = conn.execute("""SELECT prazo FROM prazos_rota WHERE origem_uf=? AND origem_cidade=?
                                  AND destino_uf=? AND destino_cidade=? AND servico=?""", chave).fetchone()
            conn.close()
            if row:
                return f"{row['prazo']} (banco local)"
        raise
    if chave:
        conn = db()
        conn.execute("""INSERT INTO prazos_rota(origem_uf,origem_cidade,destino_uf,destino_cidade,servico,prazo,atualizado_em)
                        VALUES(?,?,?,?,?,?,?) ON CONFLICT(origem_uf,origem_cidade,destino_uf,destino_cidade,servico)
                        DO UPDATE SET prazo=excluded.prazo,atualizado_em=excluded.atualizado_em""",
                     (*chave, prazo, datetime.now().isoformat(timespec="seconds")))
        conn.commit(); conn.close()
    return prazo


def requisicao_json(url, payload, headers=None, method="POST", timeout=20):
    cabecalhos = {"Accept": "application/json", "Content-Type": "application/json"}
    cabecalhos.update(headers or {})
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8") if payload is not None else None,
                                 headers=cabecalhos, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def observacoes_integracao(row):
    texto = (row["observacoes"] or "").strip()
    if not texto:
        return {}
    try:
        return json.loads(texto)
    except json.JSONDecodeError:
        return dict(parte.split("=", 1) for parte in texto.split(";") if "=" in parte)


def cotar_integracao(row, dados):
    """Normaliza uma cotação externa em opções {transportadora, serviço, preço, prazo, id}."""
    row = {**dict(row), "segredo": decrypt_val(row["segredo"])}
    nome, extra = row["nome"], observacoes_integracao(row)
    origem, destino = dados["cep_origem"], dados["cep_destino"]
    peso_kg = max(.001, float(dados["peso"]) / 1000)
    valor = float(dados.get("valor_declarado") or 0)
    comp, larg, alt = (float(dados.get(c) or 0) for c in ("comprimento", "largura", "altura"))
    if nome == "Jadlog":
        if not row["segredo"] or not row["usuario"]:
            raise RuntimeError("informe CNPJ e token Jadlog")
        modalidades = extra.get("modalidades", [3])
        if isinstance(modalidades, str): modalidades = [int(x) for x in modalidades.split(",") if x.strip().isdigit()]
        payload = {"frete": [{"cepori": origem, "cepdes": destino, "frap": "N", "peso": peso_kg,
                    "cnpj": row["usuario"], "conta": extra.get("conta", ""), "contrato": extra.get("contrato") or None,
                    "modalidade": modalidade, "tpentrega": "D", "tpseguro": "N", "vldeclarado": valor,
                    "vlcoleta": 0} for modalidade in (modalidades or [3])]}
        resposta = requisicao_json(row["endpoint"], payload, {"Authorization": row["segredo"]})
        if resposta.get("error"): raise RuntimeError(resposta["error"].get("descricao", "cotação recusada"))
        return [{"transportadora": nome, "servico": f"Modalidade {x.get('modalidade')}",
                 "preco": float(x["vltotal"]), "prazo": f"{x.get('prazo','—')} dia(s)", "id": ""}
                for x in resposta.get("frete", []) if x.get("vltotal") is not None and not x.get("erro")]
    if nome == "Braspress":
        if not row["usuario"] or not row["segredo"]: raise RuntimeError("informe usuário e senha Braspress")
        auth = base64.b64encode(f"{row['usuario']}:{row['segredo']}".encode()).decode()
        payload = {"cnpjRemetente": "".join(filter(str.isdigit, dados.get("remetente_documento", ""))),
                   "cnpjDestinatario": "".join(filter(str.isdigit, dados.get("destinatario_documento", ""))),
                   "modal": extra.get("modal", "R"), "tipoFrete": "1", "cepOrigem": int(origem),
                   "cepDestino": int(destino), "vlrMercadoria": valor, "peso": peso_kg, "volumes": 1,
                   "cubagem": [{"altura": alt/100, "largura": larg/100, "comprimento": comp/100, "volumes": 1}]}
        x = requisicao_json(row["endpoint"], payload, {"Authorization": "Basic " + auth})
        return [{"transportadora": nome, "servico": "Rodoviário" if payload["modal"] == "R" else "Aéreo",
                 "preco": float(x["totalFrete"]), "prazo": f"{x.get('prazo','—')} dia(s)", "id": str(x.get("id", ""))}]
    if nome == "Loggi":
        partes = (row["usuario"] or "").split("|", 1)
        if len(partes) != 2 or not row["segredo"]: raise RuntimeError("informe company_id|client_id e client_secret Loggi")
        company_id, client_id = partes
        base_url = (row["endpoint"] or "https://api.loggi.com").rstrip("/")
        token_data = requisicao_json(base_url + "/v2/oauth2/token", {"client_id": client_id, "client_secret": row["segredo"]})
        token = token_data.get("access_token") or token_data.get("idToken") or token_data.get("token")
        if not token: raise RuntimeError("autenticação Loggi sem token reconhecido")
        payload = {"pickupTypes": extra.get("pickupTypes", ["DROP_OFF"]),
                   "shipFrom": {"correios": {"postalCode": origem}}, "shipTo": {"correios": {"postalCode": destino}},
                   "packages": [{"weightG": int(dados["peso"]), "lengthCm": comp, "widthCm": larg,
                                 "heightCm": alt, "goodsValue": valor}]}
        resposta = requisicao_json(f"{base_url}/v1/companies/{company_id}/quotations", payload,
                                  {"Authorization": "Bearer " + token})
        lista = localizar_campo_ppn(resposta, ["quotations", "quotes"]) or []
        return [{"transportadora": nome, "servico": str(x.get("name") or x.get("serviceName") or x.get("externalServiceId") or "Loggi"),
                 "preco": float(x.get("price") or x.get("amount") or 0),
                 "prazo": f"{x.get('deliveryEstimateDays') or x.get('deadline') or '—'} dia(s)",
                 "id": str(x.get("id") or "")} for x in lista if float(x.get("price") or x.get("amount") or 0) > 0]
    if nome == "J&T":
        raise RuntimeError("conector preparado; requer apiAccount, privateKey, customerCode e senha API liberados pela J&T")
    if nome == "Total Express":
        raise RuntimeError("conector preparado; requer usuário, senha, REID e endpoint liberados pela Total Express")
    raise RuntimeError("conector sem adaptador de cotação cadastrado")


def cotacao_estimada_nao_homologada(row, dados):
    """Estimativa de interface; nunca é apresentada como preço contratado ou resposta da API."""
    peso = int(dados["peso"])
    bases = [tarifa_vista(s, peso, dados["cep_origem"], dados["cep_destino"]) for s in ("PAC", "SEDEX")]
    base = min((x for x in bases if x is not None), default=22.90 + math.ceil(peso/500) * 3.40)
    parametros = {
        "Jadlog": (1.04, 5, "Package"), "Braspress": (1.18, 6, "Rodoviário"),
        "Loggi": (.91, 4, "Loggi Nacional"), "J&T": (.94, 6, "Standard"),
        "Total Express": (.98, 5, "Standard"),
    }
    fator, prazo, servico = parametros.get(row["nome"], (1.08, 7, "Standard"))
    preco = round(base * fator + ((sum(ord(c) for c in row["nome"]) % 7) / 10), 2)
    return [{"transportadora": row["nome"], "servico": servico + " — estimativa não homologada",
             "preco": preco, "prazo": f"{prazo} a {prazo+2} dias (estimado)", "id": "ESTIMATIVA", "homologada": False}]


def sincronizar_servicos_adicionais():
    token = token_correios()
    total = 0
    conn = db()
    for servico in ("PAC", "SEDEX"):
        produto = codigo_servico_correios(servico)
        url = f"https://api.correios.com.br/preco/v1/servicos-adicionais/{produto}?sgPais=BR"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as response:
            resposta = json.loads(response.read().decode("utf-8"))
        itens = resposta if isinstance(resposta, list) else next(
            (valor for valor in resposta.values() if isinstance(valor, list)), []
        )
        for item in itens:
            codigo = str(item.get("coServAdicional") or item.get("codigoServicoAdicional") or item.get("codigo") or "").zfill(3)
            nome = str(item.get("noServAdicional") or item.get("nome") or item.get("descricao") or codigo)
            valor = item.get("pcServicoAdicional") or item.get("preco") or item.get("valor") or 0
            try:
                valor = float(str(valor).replace(",", "."))
            except ValueError:
                valor = 0
            if codigo and codigo != "000":
                conn.execute("""INSERT INTO servicos_adicionais_correios(codigo_produto,codigo,nome,valor,atualizado_em)
                             VALUES(?,?,?,?,?) ON CONFLICT(codigo_produto,codigo) DO UPDATE SET
                             nome=excluded.nome,valor=excluded.valor,atualizado_em=excluded.atualizado_em""",
                             (produto, codigo, nome, valor, datetime.now().isoformat(timespec="seconds")))
                total += 1
    conn.commit(); conn.close()
    return total


def criar_prepostagem_ppn(cotacao, doc):
    token = token_correios()
    conf = settings()
    adicionais = []
    codigos_adicionais = json.loads(cotacao["servicos_adicionais"] or "[]") if "servicos_adicionais" in cotacao.keys() else []
    for codigo in codigos_adicionais:
        adicional = {"codigoServicoAdicional": codigo}
        if codigo == "019" and float(cotacao["valor_declarado"] or 0) > 0:
            adicional["valorDeclarado"] = f"{float(cotacao['valor_declarado']):.2f}"
        adicionais.append(adicional)
    if cotacao["possui_bateria"] == "Sim":
        if not any(item["codigoServicoAdicional"] == "095" for item in adicionais):
            adicionais.append({"codigoServicoAdicional": "095"})
    payload = {
        "numeroCartaoPostagem": conf.get("correios_cartao", ""), "codigoServico": codigo_servico_correios(cotacao["servico"]),
        "remetente": {"nome": cotacao["remetente_nome"], "cpfCnpj": cotacao["remetente_documento"],
            "endereco": {"cep": cotacao["cep_origem"], "logradouro": cotacao["remetente_rua"],
            "numero": cotacao["remetente_numero"], "complemento": cotacao["remetente_complemento"] or "",
            "bairro": cotacao["remetente_bairro"], "cidade": cotacao["remetente_cidade"], "uf": cotacao["remetente_uf"]}},
        "destinatario": {"nome": cotacao["destinatario_nome"], "cpfCnpj": cotacao["destinatario_documento"],
            "endereco": {"cep": cotacao["cep_destino"], "logradouro": cotacao["destinatario_rua"],
            "numero": cotacao["destinatario_numero"], "complemento": cotacao["destinatario_complemento"] or "",
            "bairro": cotacao["destinatario_bairro"], "cidade": cotacao["destinatario_cidade"], "uf": cotacao["destinatario_uf"]}},
        "codigoFormatoObjetoInformado": "1" if cotacao["tipo_embalagem"] == "Envelope" else "2",
        "pesoInformado": str(cotacao["peso"]), "cienteObjetoNaoProibido": "1", "solicitarColeta": "N",
        "listaServicoAdicional": adicionais,
    }
    if cotacao["tipo_embalagem"] != "Envelope":
        payload.update({"comprimentoInformado": str(cotacao["comprimento"]), "larguraInformada": str(cotacao["largura"]), "alturaInformada": str(cotacao["altura"])})
    if doc and doc["tipo_documento"] in ("danfe", "nfce", "cupom"):
        payload["numeroNotaFiscal"] = doc["numero_nota"] or ""
        payload["chaveNFe"] = doc["chave_nfe"] or ""
    if doc:
        payload["itensDeclaracaoConteudo"] = [
            {"conteudo": item.get("descricao", ""), "quantidade": int(float(item.get("quantidade", 1))),
             "valor": f"{float(item.get('valor', 0)):.2f}"}
            for item in json.loads(doc["conteudo_json"] or "[]")
        ]
    req = urllib.request.Request("https://api.correios.com.br/prepostagem/v1/prepostagens",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detalhe = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"PPN recusou a pré-postagem ({exc.code}): {detalhe[:600]}")


def gerar_rotulo_ppn(ppn_id):
    token = token_correios()
    base = "https://api.correios.com.br/prepostagem/v1/prepostagens/rotulo"
    payload = {"idsPrePostagem": [str(ppn_id)], "tipoRotulo": "P", "formatoRotulo": "ET",
               "layoutImpressao": "LINEAR_100_150"}
    req = urllib.request.Request(base + "/assincrono/pdf",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            recibo_resposta = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detalhe = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"PPN criou a postagem, mas recusou a solicitação do rótulo ({exc.code}): {detalhe[:600]}")
    id_recibo = localizar_campo_ppn(recibo_resposta, ["idRecibo", "recibo", "id"])
    if not id_recibo:
        raise RuntimeError("A PPN não informou o recibo necessário para baixar o rótulo.")
    download = base + "/download/assincrono/" + urllib.parse.quote(str(id_recibo), safe="")
    ultimo_detalhe = "processamento pendente"
    for tentativa in range(10):
        if tentativa:
            time.sleep(1.2)
        consulta = urllib.request.Request(download, headers={"Authorization": f"Bearer {token}",
            "Accept": "application/pdf,application/json"}, method="GET")
        try:
            with urllib.request.urlopen(consulta, timeout=45) as response:
                conteudo = response.read()
                mime = response.headers.get_content_type()
                if mime == "application/json":
                    dados = json.loads(conteudo.decode("utf-8"))
                    arquivo = localizar_campo_ppn(dados, ["dados", "rotulo", "arquivo", "pdf", "conteudo"])
                    if arquivo:
                        return base64.b64decode(arquivo), "application/pdf"
                    ultimo_detalhe = json.dumps(dados, ensure_ascii=False)[:400]
                    continue
                return conteudo, mime
        except urllib.error.HTTPError as exc:
            detalhe = exc.read().decode("utf-8", errors="replace")
            if exc.code in {404, 409, 425, 429, 503}:
                ultimo_detalhe = detalhe[:400]
                continue
            raise RuntimeError(f"PPN recusou o download do rótulo ({exc.code}): {detalhe[:600]}")
    raise RuntimeError(f"O rótulo continua em processamento na PPN. Tente recuperar novamente em alguns segundos. {ultimo_detalhe}")


def normalizar_resposta_rotulo(conteudo, mime):
    if conteudo[:4] == b"%PDF":
        return conteudo, "application/pdf"
    if mime == "application/json":
        dados = json.loads(conteudo.decode("utf-8"))
        valor = localizar_campo_ppn(dados, ["dados", "rotulo", "arquivo", "pdf", "conteudo"])
        if isinstance(valor, str) and valor:
            return base64.b64decode(valor), "application/pdf"
        raise RuntimeError("A PPN respondeu em JSON, mas não forneceu o arquivo do rótulo.")
    return conteudo, mime


def consultar_prepostagem_ppn(ppn_id):
    token = token_correios()
    url = "https://api.correios.com.br/prepostagem/v2/prepostagens?" + urllib.parse.urlencode({"id": ppn_id})
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def rotulo_ppn_para_zebra(pdf_bytes):
    from pypdf import PageObject, PdfReader, PdfWriter, Transformation
    leitor = PdfReader(io.BytesIO(pdf_bytes))
    escritor = PdfWriter()
    largura_destino, altura_destino = 100 / 25.4 * 72, 150 / 25.4 * 72

    def adicionar_pagina_10x15(pagina, x0, y0, x1, y1):
        """Recorta uma célula PPN sem deformá-la e a centraliza em 100 x 150 mm."""
        recorte = copy.copy(pagina)
        recorte.cropbox.lower_left = (x0, y0)
        recorte.cropbox.upper_right = (x1, y1)
        recorte.mediabox.lower_left = (x0, y0)
        recorte.mediabox.upper_right = (x1, y1)
        largura_origem, altura_origem = x1 - x0, y1 - y0
        escala = min(largura_destino / largura_origem, altura_destino / altura_origem)
        margem_x = (largura_destino - largura_origem * escala) / 2
        margem_y = (altura_destino - altura_origem * escala) / 2
        destino = PageObject.create_blank_page(width=largura_destino, height=altura_destino)
        destino.merge_transformed_page(
            recorte,
            Transformation().translate(-x0, -y0).scale(escala).translate(margem_x, margem_y),
        )
        escritor.add_page(destino)

    def possui_segunda_faixa_ppn(pagina, altura):
        """Identifica a segunda dupla rótulo/DACE presente em lotes A4 da PPN."""
        encontrou = False

        def visitar_texto(texto, cm, tm, fonte, tamanho):
            nonlocal encontrou
            normalizado = " ".join((texto or "").upper().split())
            if "CONTRATO" in normalizado and len(normalizado) > 35 and float(cm[5]) < altura * .1:
                encontrou = True

        try:
            pagina.extract_text(visitor_text=visitar_texto)
        except Exception:
            return False
        return encontrou

    for pagina in leitor.pages:
        largura, altura = float(pagina.mediabox.width), float(pagina.mediabox.height)
        proporcao = largura / altura
        # A PPN ainda entrega o modelo para impressão em A4. Cada atendimento ocupa
        # a faixa superior: rótulo postal à esquerda e DACE à direita, como nos
        # modelos oficiais PAC/SEDEX. A aplicação solicita um único id por vez.
        if 0.65 <= proporcao <= 0.70:  # arquivo já fornecido em 100 x 150 mm
            adicionar_pagina_10x15(pagina, 0, 0, largura, altura)
        elif proporcao > 1.15:  # folha A5 paisagem: duas células lado a lado
            adicionar_pagina_10x15(pagina, 0, 0, largura / 2, altura)
            adicionar_pagina_10x15(pagina, largura / 2, 0, largura, altura)
        else:  # A4 retrato oficial da PPN
            y0 = altura / 2
            adicionar_pagina_10x15(pagina, 0, y0, largura / 2, altura)
            adicionar_pagina_10x15(pagina, largura / 2, y0, largura, altura)
            if possui_segunda_faixa_ppn(pagina, altura):
                adicionar_pagina_10x15(pagina, 0, 0, largura / 2, y0)
                adicionar_pagina_10x15(pagina, largura / 2, 0, largura, y0)
    saida = io.BytesIO()
    escritor.write(saida)
    return saida.getvalue()


def mini_documento_fiscal_10x15(cotacao, doc):
    from reportlab.graphics.barcode import code128
    from reportlab.lib.pagesizes import mm
    from reportlab.pdfgen import canvas
    largura, altura = 100 * mm, 150 * mm
    saida = io.BytesIO(); pdf = canvas.Canvas(saida, pagesize=(largura, altura))
    tipo = doc["tipo_documento"]
    titulo = {"danfe": "MINI DANFE - NF-e", "nfce": "DANFE NFC-e", "cupom": "CUPOM FISCAL"}.get(tipo, "DOCUMENTO FISCAL")
    fiscal = dados_chave_fiscal(doc["chave_nfe"])
    y = altura - 12 * mm
    pdf.setFont("Helvetica-Bold", 13); pdf.drawCentredString(largura / 2, y, titulo); y -= 6 * mm
    pdf.setFont("Helvetica-Bold", 8); pdf.drawString(7 * mm, y, f"EMITENTE: {cotacao['remetente_nome'] or ''}"); y -= 4 * mm
    pdf.setFont("Helvetica", 8); pdf.drawString(7 * mm, y, f"CPF/CNPJ: {cotacao['remetente_documento'] or ''}"); y -= 5 * mm
    if fiscal:
        pdf.drawString(7 * mm, y, f"MODELO {fiscal['modelo']}  SERIE {fiscal['serie']}  NUMERO {int(fiscal['numero'])}"); y -= 5 * mm
        pdf.setFont("Helvetica-Bold", 7); pdf.drawString(7 * mm, y, "CHAVE DE ACESSO"); y -= 4 * mm
        chave_agrupada = " ".join(fiscal["chave"][i:i+4] for i in range(0, 44, 4))
        pdf.setFont("Helvetica", 6.5); pdf.drawCentredString(largura / 2, y, chave_agrupada); y -= 14 * mm
        barra = code128.Code128(fiscal["chave"], barHeight=10 * mm, barWidth=.23 * mm)
        barra.drawOn(pdf, (largura - barra.width) / 2, y); y -= 6 * mm
    pdf.setFont("Helvetica-Bold", 8); pdf.drawString(7 * mm, y, f"DESTINATARIO: {cotacao['destinatario_nome'] or ''}"); y -= 4 * mm
    pdf.setFont("Helvetica", 7); pdf.drawString(7 * mm, y, f"CPF/CNPJ: {cotacao['destinatario_documento'] or ''}"); y -= 6 * mm
    pdf.line(7 * mm, y, 93 * mm, y); y -= 5 * mm
    pdf.setFont("Helvetica-Bold", 7); pdf.drawString(7 * mm, y, "DESCRICAO"); pdf.drawString(70 * mm, y, "QTD."); pdf.drawRightString(93 * mm, y, "VALOR"); y -= 4 * mm
    total = 0
    for item in json.loads(doc["conteudo_json"] or "[]")[:12]:
        qtd, valor = float(item.get("quantidade") or 0), float(item.get("valor") or 0); total += qtd * valor
        descricao = str(item.get("descricao") or "")[:42]
        pdf.setFont("Helvetica", 7); pdf.drawString(7 * mm, y, descricao); pdf.drawString(72 * mm, y, f"{qtd:g}"); pdf.drawRightString(93 * mm, y, brl(qtd * valor)); y -= 4 * mm
    y -= 2 * mm; pdf.line(7 * mm, y, 93 * mm, y); y -= 6 * mm
    pdf.setFont("Helvetica-Bold", 10); pdf.drawString(7 * mm, y, "TOTAL"); pdf.drawRightString(93 * mm, y, brl(doc["valor_nota"] or total)); y -= 8 * mm
    pdf.setFont("Helvetica", 6.5); pdf.drawCentredString(largura / 2, y, f"Documento vinculado ao objeto {cotacao['rastreio'] or cotacao['etiqueta'] or cotacao['id']}")
    pdf.showPage(); pdf.save(); return saida.getvalue()


def declaracao_conteudo_10x15(cotacao, doc):
    """Segunda etiqueta 100 x 150 mm com os dados declarados na PPN/DC-e."""
    from reportlab.lib.pagesizes import mm
    from reportlab.pdfgen import canvas
    largura, altura = 100 * mm, 150 * mm
    saida = io.BytesIO(); pdf = canvas.Canvas(saida, pagesize=(largura, altura))
    y = altura - 9 * mm
    pdf.setFont("Helvetica-Bold", 10); pdf.drawCentredString(largura / 2, y, "DADOS DA DACE"); y -= 5 * mm
    pdf.setFont("Helvetica-Bold", 8); pdf.drawCentredString(largura / 2, y, "DECLARAÇÃO DE CONTEÚDO ELETRÔNICA"); y -= 5 * mm
    pdf.line(5 * mm, y, 95 * mm, y); y -= 5 * mm
    linhas = [
        ("OBJETO", cotacao["rastreio"] or cotacao["etiqueta"] or f"COTAÇÃO {cotacao['id']}") ,
        ("REMETENTE", cotacao["remetente_nome"] or doc["remetente_nome"] or ""),
        ("CPF/CNPJ", cotacao["remetente_documento"] or doc["remetente_documento"] or ""),
        ("DESTINATÁRIO", cotacao["destinatario_nome"] or ""),
        ("CPF/CNPJ", cotacao["destinatario_documento"] or ""),
    ]
    for rotulo, valor in linhas:
        pdf.setFont("Helvetica-Bold", 6.5); pdf.drawString(5 * mm, y, rotulo)
        pdf.setFont("Helvetica", 7); pdf.drawString(25 * mm, y, str(valor)[:55]); y -= 4 * mm
    pdf.setFont("Helvetica", 6.4)
    for endereco in [doc["remetente_endereco"] or "", doc["destinatario_endereco"] or ""]:
        for inicio in range(0, len(endereco), 65):
            pdf.drawString(5 * mm, y, endereco[inicio:inicio + 65]); y -= 3.5 * mm
    y -= 2 * mm; pdf.line(5 * mm, y, 95 * mm, y); y -= 5 * mm
    pdf.setFont("Helvetica-Bold", 6.5); pdf.drawString(5 * mm, y, "CONTEÚDO"); pdf.drawString(67 * mm, y, "QTD."); pdf.drawRightString(95 * mm, y, "VALOR"); y -= 4 * mm
    total = 0.0
    for item in json.loads(doc["conteudo_json"] or "[]")[:14]:
        qtd, valor = float(item.get("quantidade") or 0), float(item.get("valor") or 0)
        total += qtd * valor
        pdf.setFont("Helvetica", 6.5); pdf.drawString(5 * mm, y, str(item.get("descricao") or "")[:44])
        pdf.drawString(69 * mm, y, f"{qtd:g}"); pdf.drawRightString(95 * mm, y, brl(qtd * valor)); y -= 4 * mm
    pdf.line(5 * mm, y, 95 * mm, y); y -= 5 * mm
    pdf.setFont("Helvetica-Bold", 8); pdf.drawString(5 * mm, y, "VALOR TOTAL DECLARADO"); pdf.drawRightString(95 * mm, y, brl(total)); y -= 7 * mm
    pdf.setFont("Helvetica", 6.2)
    aviso = "Dados declarados eletronicamente na pré-postagem PPN. Documento auxiliar para acompanhar o objeto."
    for trecho in (aviso[:75], aviso[75:]):
        pdf.drawCentredString(largura / 2, y, trecho); y -= 3.5 * mm
    pdf.line(18 * mm, 15 * mm, 82 * mm, 15 * mm)
    pdf.setFont("Helvetica", 6); pdf.drawCentredString(largura / 2, 11 * mm, "Assinatura do declarante")
    pdf.showPage(); pdf.save(); return saida.getvalue()


def documento_auxiliar_10x15(cotacao, doc):
    if doc and doc["tipo_documento"] in {"danfe", "nfce", "cupom"}:
        return mini_documento_fiscal_10x15(cotacao, doc)
    return declaracao_conteudo_10x15(cotacao, doc)


def documento_resumo_100x45(cotacao, doc):
    from reportlab.lib.pagesizes import mm
    from reportlab.pdfgen import canvas
    largura, altura = 100 * mm, 45 * mm
    saida = io.BytesIO(); pdf = canvas.Canvas(saida, pagesize=(largura, altura))
    tipo = (doc["tipo_documento"] if doc else "declaracao")
    titulo = {"danfe": "RESUMO MINI DANFE — NF-e", "nfce": "RESUMO DANFE NFC-e", "cupom": "RESUMO CUPOM FISCAL"}.get(tipo, "RESUMO DECLARAÇÃO DE CONTEÚDO (DC-e)")
    pdf.setLineWidth(.6); pdf.rect(2 * mm, 2 * mm, 96 * mm, 41 * mm)
    pdf.setFont("Helvetica-Bold", 7.5); pdf.drawString(4 * mm, 38 * mm, titulo)
    itens = json.loads((doc["conteudo_json"] if doc else "[]") or "[]")
    y, total = 33 * mm, 0.0
    for indice, item in enumerate(itens[:4], 1):
        qtd, valor = float(item.get("quantidade") or 0), float(item.get("valor") or 0); total += qtd * valor
        texto = f"{indice}. {str(item.get('descricao') or '')[:34]}  Qtd: {qtd:g}  {brl(qtd * valor)}"
        pdf.setFont("Helvetica", 6.7); pdf.drawString(4 * mm, y, texto); y -= 4 * mm
    if tipo in {"danfe", "nfce"} and doc["chave_nfe"]:
        chave = " ".join(doc["chave_nfe"][i:i+4] for i in range(0, 44, 4))
        pdf.setFont("Helvetica", 5.3); pdf.drawString(4 * mm, y, "CHAVE: " + chave); y -= 4 * mm
    elif tipo == "cupom":
        pdf.setFont("Helvetica", 6.5); pdf.drawString(4 * mm, y, f"CUPOM: {doc['numero_nota'] or ''}"); y -= 4 * mm
    pdf.setFont("Helvetica-Bold", 7); pdf.drawString(4 * mm, 8 * mm, f"PESO: {float(cotacao['peso'] or 0)/1000:.3f} kg")
    pdf.drawRightString(96 * mm, 8 * mm, f"VALOR TOTAL: {brl(doc['valor_nota'] or total)}")
    pdf.setFont("Helvetica", 5.5); pdf.drawString(4 * mm, 4 * mm, "Dados vinculados à pré-postagem PPN e ao objeto indicado no rótulo.")
    pdf.save(); return saida.getvalue()


def etiqueta_unica_correios_10x15(cotacao, doc):
    """Etiqueta única com dados PPN, rastreio GS1-128/UCC-EAN-128 e resumo fiscal/DC-e."""
    from reportlab.graphics.barcode import code128
    from reportlab.lib.pagesizes import mm
    from reportlab.pdfgen import canvas
    largura, altura = 100 * mm, 150 * mm
    saida = io.BytesIO(); pdf = canvas.Canvas(saida, pagesize=(largura, altura))
    rastreio = str(cotacao["rastreio"] or cotacao["etiqueta"] or "").replace(" ", "").upper()
    pdf.setLineWidth(.65); pdf.rect(2 * mm, 2 * mm, 96 * mm, 146 * mm)
    pdf.setFont("Helvetica-Bold", 10); pdf.drawString(5 * mm, 143 * mm, "CORREIOS")
    pdf.drawRightString(95 * mm, 143 * mm, str(cotacao["servico"] or ""))
    # FNC1 identifica a simbologia GS1-128 (antiga UCC/EAN-128).
    barra = code128.Code128("\xf1" + rastreio, barHeight=15 * mm, barWidth=.32 * mm, humanReadable=False)
    if barra.width > 80 * mm: barra.barWidth *= (80 * mm / barra.width)
    barra.drawOn(pdf, 10 * mm, 123 * mm)
    pdf.setFont("Helvetica-Bold", 8); pdf.drawCentredString(largura / 2, 119 * mm, rastreio)
    pdf.line(2 * mm, 116 * mm, 98 * mm, 116 * mm)
    y = 111 * mm; pdf.setFont("Helvetica-Bold", 7); pdf.drawString(5 * mm, y, "DESTINATÁRIO:"); y -= 4 * mm
    pdf.setFont("Helvetica-Bold", 8.5); pdf.drawString(5 * mm, y, str(cotacao["destinatario_nome"] or "")[:52]); y -= 4 * mm
    endereco_dest = f"{cotacao['destinatario_rua'] or ''}, {cotacao['destinatario_numero'] or ''} {cotacao['destinatario_complemento'] or ''}".strip()
    pdf.setFont("Helvetica", 7); pdf.drawString(5 * mm, y, endereco_dest[:68]); y -= 4 * mm
    pdf.drawString(5 * mm, y, f"{cotacao['destinatario_bairro'] or ''} - {cotacao['destinatario_cidade'] or ''}/{cotacao['destinatario_uf'] or ''}"[:68]); y -= 4 * mm
    pdf.setFont("Helvetica-Bold", 8); pdf.drawString(5 * mm, y, f"CEP: {cep_formatado(cotacao['cep_destino'])}")
    pdf.line(2 * mm, 87 * mm, 98 * mm, 87 * mm)
    y = 82 * mm; pdf.setFont("Helvetica-Bold", 7); pdf.drawString(5 * mm, y, "REMETENTE:"); y -= 4 * mm
    pdf.setFont("Helvetica", 7); pdf.drawString(5 * mm, y, f"{cotacao['remetente_nome'] or ''} — CPF/CNPJ: {cotacao['remetente_documento'] or ''}"[:70]); y -= 4 * mm
    endereco_rem = f"{cotacao['remetente_rua'] or ''}, {cotacao['remetente_numero'] or ''} - {cotacao['remetente_cidade'] or ''}/{cotacao['remetente_uf'] or ''}"
    pdf.drawString(5 * mm, y, endereco_rem[:72])
    pdf.line(2 * mm, 69 * mm, 98 * mm, 69 * mm)
    destino, classe, direcao = destino_triagem(cotacao)
    if destino:
        pdf.setFont("Helvetica-Bold", 9); pdf.drawString(5 * mm, 64 * mm, f"TRIAGEM: {classe} | POSIÇÃO: {destino[:12]}")
        pdf.setFont("Helvetica-Bold", 7); pdf.drawString(5 * mm, 60 * mm, "DIREÇÃO: " + (direcao or "NÃO INFORMADA")[:42])
    tipo = doc["tipo_documento"] if doc else "declaracao"
    titulo = {"danfe":"MINI DANFE — NF-e","nfce":"DANFE NFC-e","cupom":"CUPOM FISCAL"}.get(tipo,"RESUMO DECLARAÇÃO DE CONTEÚDO (DC-e)")
    pdf.setFont("Helvetica-Bold", 7); pdf.drawString(5 * mm, 55 * mm, titulo)
    itens = json.loads((doc["conteudo_json"] if doc else "[]") or "[]"); y = 50 * mm; total = 0
    for indice, item in enumerate(itens[:5], 1):
        qtd, valor = float(item.get("quantidade") or 0), float(item.get("valor") or 0); total += qtd * valor
        pdf.setFont("Helvetica", 6.2); pdf.drawString(5 * mm, y, f"{indice}. {str(item.get('descricao') or '')[:37]} (Qtd: {qtd:g}) — {brl(qtd*valor)}"); y -= 4 * mm
    pdf.setFont("Helvetica-Bold", 7); pdf.drawString(5 * mm, 25 * mm, f"Peso total: {float(cotacao['peso'] or 0)/1000:.3f} kg")
    valor_documento = (doc["valor_nota"] if doc else 0) or total
    pdf.drawRightString(95 * mm, 25 * mm, f"Valor total: {brl(valor_documento)}")
    if tipo in {"danfe", "nfce"} and doc["chave_nfe"]:
        pdf.setFont("Helvetica", 5.2); pdf.drawString(5 * mm, 20 * mm, "Chave: " + " ".join(doc["chave_nfe"][i:i+4] for i in range(0,44,4)))
    else:
        pdf.setFont("Helvetica", 5.8); pdf.drawString(5 * mm, 20 * mm, "Declaro que os itens informados correspondem ao conteúdo do objeto.")
    pdf.line(25 * mm, 9 * mm, 85 * mm, 9 * mm); pdf.setFont("Helvetica", 5.5); pdf.drawCentredString(55 * mm, 6 * mm, "Assinatura do declarante")
    pdf.save(); return saida.getvalue()


def parametro_tarifa(servico, chave, padrao):
    """Regra da tabela a vista (data/tarifas/parametros.csv, tirado das abas de INSTRUCOES dos Correios)."""
    conn = db()
    try:
        row = conn.execute("""SELECT valor FROM tarifas_parametros WHERE chave=?
                              ORDER BY servico<>? LIMIT 1""", (chave, servico or "PAC")).fetchone()
    except sqlite3.OperationalError:
        row = None
    conn.close()
    try:
        return float(row["valor"]) if row else padrao
    except (TypeError, ValueError):
        return padrao


def peso_tarifavel_gramas(peso_fisico, comprimento, largura, altura, tipo_embalagem="Pacote", servico="PAC"):
    """Instrucoes da tabela a vista: peso cubico = C x L x A / divisor, arredondado para cima em kg;
    ate a isencao (5 kg cubicos) e envelopes vale o peso fisico; senao, o maior dos dois."""
    fisico = max(1, int(math.ceil(float(peso_fisico or 0))))
    if tipo_embalagem == "Envelope":
        return fisico, 0
    divisor = parametro_tarifa(servico, "peso_cubico_divisor", 6000)
    isencao = parametro_tarifa(servico, "peso_cubico_isencao_kg", 5)
    cubico_kg = max(0, float(comprimento or 0) * float(largura or 0) * float(altura or 0) / divisor)
    cubico_g = int(math.ceil(cubico_kg)) * 1000
    return (fisico if cubico_kg <= isencao else max(fisico, cubico_g)), cubico_g


def fora_do_limite_correios(peso_fisico, comprimento, largura, altura, tipo_embalagem="Pacote", servico="PAC"):
    """Motivo pelo qual o objeto nao pode ser tarifado/postado, ou "". Os limites vem de
    data/tarifas/parametros.csv. Sem esta trava a tabela a vista cotava pelo peso cubico
    medidas que a API recusa (ERP-008)."""
    peso_max = parametro_tarifa(servico, "peso_max_kg", 30)
    if float(peso_fisico or 0) > peso_max * 1000:
        return f"peso acima de {peso_max:g} kg"
    if tipo_embalagem == "Envelope":
        return ""
    lados = [float(x or 0) for x in (comprimento, largura, altura)]
    lado_max = parametro_tarifa(servico, "lado_max_cm", 100)
    soma_max = parametro_tarifa(servico, "soma_dimensoes_max_cm", 200)
    if max(lados) > lado_max:
        return f"um dos lados passa de {lado_max:g} cm ({lados[0]:g} x {lados[1]:g} x {lados[2]:g} cm)"
    if sum(lados) > soma_max:
        return f"a soma das dimensões passa de {soma_max:g} cm ({sum(lados):g} cm)"
    if peso_tarifavel_gramas(peso_fisico, *lados, tipo_embalagem, servico)[0] > peso_max * 1000:
        return f"peso cúbico acima de {peso_max:g} kg"
    return ""


def manuseio_especial(servico, comprimento, largura, altura, tipo_embalagem="Pacote"):
    """Cobranca adicional de manuseio especial da tabela a vista quando uma das dimensoes
    passa do limite das instrucoes (70 cm). Devolve o valor em R$ ou 0."""
    if tipo_embalagem == "Envelope":
        return 0.0
    limite = parametro_tarifa(servico, "manuseio_especial_dimensao_cm", 70)
    if max(float(x or 0) for x in (comprimento, largura, altura)) <= limite:
        return 0.0
    return round(parametro_tarifa(servico, "manuseio_especial_valor", 0), 2)


def recusa_da_api_correios(mensagem):
    """A API dos Correios respondeu recusando o objeto (HTTP 400/422, ex.: ERP-008), e nao por falha
    de credencial, limite de requisicoes ou indisponibilidade."""
    return bool(re.match(r"HTTP 4(?!01|03|08|29)\d\d", str(mensagem)))


def pdf_lado_a_lado(pdf_zebra):
    """Consolida as duas folhas 100 x 150 em uma única página 200 x 150 mm."""
    from pypdf import PageObject, PdfReader, PdfWriter, Transformation
    leitor = PdfReader(io.BytesIO(pdf_zebra))
    if len(leitor.pages) < 2:
        return pdf_zebra
    largura, altura = 100 / 25.4 * 72, 150 / 25.4 * 72
    pagina = PageObject.create_blank_page(width=largura * 2, height=altura)
    pagina.merge_page(leitor.pages[0])
    pagina.merge_transformed_page(leitor.pages[1], Transformation().translate(largura, 0))
    escritor = PdfWriter(); escritor.add_page(pagina)
    saida = io.BytesIO(); escritor.write(saida); return saida.getvalue()


def classe_triagem(cotacao):
    lados = [float(cotacao[c] or 0) for c in ("comprimento", "largura", "altura")]
    grandes = sum(1 for lado in lados if lado > 36)
    return "GO" if max(lados or [0]) > 41 or grandes >= 2 or float(cotacao["peso"] or 0) > 10000 else "PO"


def destino_triagem(cotacao):
    cep = "".join(filter(str.isdigit, str(cotacao["cep_destino"] or "")))
    tamanho = classe_triagem(cotacao)
    conn = db()
    formato = "ENVELOPE" if str(cotacao["tipo_embalagem"] or "").upper() == "ENVELOPE" else "PACOTE"
    servico = str(cotacao["servico"] or "").upper()
    if "SEDEX 10" in servico or "SEDEX 12" in servico:
        categoria = "SEDEX 10/SEDEX 12"
    elif "SEDEX" in servico:
        categoria = "SEDEX"
    elif "PAC" in servico:
        categoria = "PAC"
    else:
        categoria = servico
    regra = conn.execute("""SELECT * FROM triagem_plano WHERE ? BETWEEN cep_inicio AND cep_final
                           AND UPPER(COALESCE(categoria,''))=? AND UPPER(COALESCE(formato,'')) IN (?, 'MISTO')
                           AND UPPER(COALESCE(tamanho,''))=? ORDER BY id LIMIT 1""", (cep, categoria, formato, tamanho)).fetchone()
    if not regra:
        regra = conn.execute("""SELECT * FROM triagem_plano WHERE ? BETWEEN cep_inicio AND cep_final
                               AND UPPER(COALESCE(categoria,''))=? AND UPPER(COALESCE(formato,'')) IN (?, 'MISTO')
                               AND TRIM(COALESCE(tamanho,''))='' ORDER BY id LIMIT 1""", (cep, categoria, formato)).fetchone()
    conn.close()
    if not regra:
        return "", tamanho, ""
    texto = regra["posicao"].strip()
    return texto, tamanho, (regra["direcao"] or "").strip()


def sobrepor_triagem_rotulo(pdf_zebra, cotacao):
    from pypdf import PdfReader, PdfWriter
    from reportlab.lib.pagesizes import mm
    from reportlab.pdfgen import canvas
    destino, tamanho, direcao = destino_triagem(cotacao)
    camada = io.BytesIO(); pdf = canvas.Canvas(camada, pagesize=(100 * mm, 150 * mm))
    pdf.setFillColorRGB(1, 1, 1); pdf.rect(3 * mm, 3 * mm, 54 * mm, 18 * mm, fill=1, stroke=0)
    pdf.setFillColorRGB(0, 0, 0); pdf.setLineWidth(1); pdf.rect(3 * mm, 3 * mm, 54 * mm, 18 * mm, fill=0, stroke=1)
    pdf.setFont("Helvetica-Bold", 7); pdf.drawString(5 * mm, 17 * mm, "TRIAGEM")
    pdf.setFont("Helvetica-Bold", 12); pdf.drawString(5 * mm, 11 * mm, f"{tamanho}  POS: {destino or '-'}"[:24])
    pdf.setFont("Helvetica-Bold", 6.5); pdf.drawString(5 * mm, 6 * mm, "DIREÇÃO: " + (direcao or "NÃO INFORMADA")[:34]); pdf.save()
    leitor, overlay = PdfReader(io.BytesIO(pdf_zebra)), PdfReader(io.BytesIO(camada.getvalue()))
    leitor.pages[0].merge_page(overlay.pages[0]); escritor = PdfWriter()
    for pagina in leitor.pages: escritor.add_page(pagina)
    saida = io.BytesIO(); escritor.write(saida); return saida.getvalue()


def pdf_vertical_10x15(pdf_duas_paginas):
    """Rótulo 10x15 em cima e DACE/documento 10x15 abaixo, numa faixa 100x300 mm."""
    from pypdf import PageObject, PdfReader, PdfWriter, Transformation
    leitor = PdfReader(io.BytesIO(pdf_duas_paginas))
    if len(leitor.pages) < 2: return pdf_duas_paginas
    largura, altura = 100 / 25.4 * 72, 150 / 25.4 * 72
    pagina = PageObject.create_blank_page(width=largura, height=altura * 2)
    pagina.merge_transformed_page(leitor.pages[0], Transformation().translate(0, altura))
    pagina.merge_page(leitor.pages[1]); escritor = PdfWriter(); escritor.add_page(pagina)
    saida = io.BytesIO(); escritor.write(saida); return saida.getvalue()


def pdf_zebra_unica_10x15(pdf_duas_paginas):
    """Compõe rótulo oficial e resumo DC-e/fiscal numa única etiqueta 100 x 150 mm."""
    from pypdf import PageObject, PdfReader, PdfWriter, Transformation
    leitor = PdfReader(io.BytesIO(pdf_duas_paginas))
    if len(leitor.pages) < 2: return pdf_duas_paginas
    largura, altura = 100 / 25.4 * 72, 150 / 25.4 * 72
    altura_documento = 45 / 25.4 * 72
    altura_rotulo = altura - altura_documento
    destino = PageObject.create_blank_page(width=largura, height=altura)
    rotulo, documento = leitor.pages[0], leitor.pages[1]
    escala_rotulo = min(largura / float(rotulo.mediabox.width), altura_rotulo / float(rotulo.mediabox.height))
    escala_doc = min(largura / float(documento.mediabox.width), altura_documento / float(documento.mediabox.height))
    destino.merge_transformed_page(rotulo, Transformation().scale(escala_rotulo).translate(0, altura_documento))
    destino.merge_transformed_page(documento, Transformation().scale(escala_doc))
    escritor = PdfWriter(); escritor.add_page(destino)
    saida = io.BytesIO(); escritor.write(saida); return saida.getvalue()


def substituir_documento_zebra(pdf_zebra, documento_pdf):
    from pypdf import PdfReader, PdfWriter
    origem, documento = PdfReader(io.BytesIO(pdf_zebra)), PdfReader(io.BytesIO(documento_pdf))
    escritor = PdfWriter()
    if origem.pages:
        escritor.add_page(origem.pages[0])
    escritor.add_page(documento.pages[0])
    for pagina in origem.pages[2:]:
        escritor.add_page(pagina)
    saida = io.BytesIO(); escritor.write(saida); return saida.getvalue()


def primeira_pagina_pdf(pdf_bytes):
    from pypdf import PdfReader, PdfWriter
    leitor, escritor = PdfReader(io.BytesIO(pdf_bytes)), PdfWriter()
    if not leitor.pages: raise RuntimeError("O arquivo oficial da PPN não contém páginas.")
    escritor.add_page(leitor.pages[0]); saida = io.BytesIO(); escritor.write(saida); return saida.getvalue()


def rotulo_oficial_com_documento(cotacao, doc, rotulo):
    """Mantém o rótulo PPN; a declaração gera uma segunda etiqueta 100 x 150 mm."""
    oficial = rotulo_ppn_para_zebra(rotulo)
    if doc and doc["tipo_documento"] == "declaracao":
        return substituir_documento_zebra(oficial, declaracao_conteudo_10x15(cotacao, doc))
    return primeira_pagina_pdf(oficial)


def localizar_campo_ppn(data, nomes):
    if isinstance(data, dict):
        for nome in nomes:
            if data.get(nome):
                return data[nome]
        for valor in data.values():
            encontrado = localizar_campo_ppn(valor, nomes)
            if encontrado:
                return encontrado
    elif isinstance(data, list):
        for valor in data:
            encontrado = localizar_campo_ppn(valor, nomes)
            if encontrado:
                return encontrado
    return None


@app.route("/", methods=["GET", "POST"])
@perfis_permitidos("Master", "Administrador", "Operador de Balcão")
def index():
    resultado = None
    if request.method == "POST":
        try:
            f = request.form
            forma_pagamento = f.get("forma_pagamento", "Não informado").strip()
            destinatario_nome = f.get("destinatario_nome", "").strip()
            destinatario_rua = f.get("destinatario_rua", "").strip()
            destinatario_bairro = f.get("destinatario_bairro", "").strip()
            destinatario_cidade = f.get("destinatario_cidade", "").strip()
            destinatario_uf = f.get("destinatario_uf", "").strip().upper()
            destinatario_numero = f.get("destinatario_numero", "").strip()
            destinatario_complemento = f.get("destinatario_complemento", "").strip()
            destinatario_documento = f.get("destinatario_documento", "").strip()
            remetente_nome = f.get("remetente_nome", "").strip()
            remetente_rua = f.get("remetente_rua", "").strip()
            remetente_bairro = f.get("remetente_bairro", "").strip()
            remetente_cidade = f.get("remetente_cidade", "").strip()
            remetente_uf = f.get("remetente_uf", "").strip().upper()
            remetente_numero = f.get("remetente_numero", "").strip()
            remetente_complemento = f.get("remetente_complemento", "").strip()
            remetente_documento = f.get("remetente_documento", "").strip()
            if not documento_valido(remetente_documento):
                raise ValueError("CPF/CNPJ do remetente inválido. Confira os números digitados.")
            if not documento_valido(destinatario_documento):
                raise ValueError("CPF/CNPJ do destinatário inválido. Confira os números digitados.")
            if forma_pagamento == "Faturado":
                consulta_faturado = db(); autorizado = consulta_faturado.execute(
                    "SELECT pode_faturar FROM contatos_envio WHERE tipo='Remetente' AND documento=?",
                    ("".join(filter(str.isdigit, remetente_documento)),)).fetchone(); consulta_faturado.close()
                if not autorizado or not autorizado["pode_faturar"]:
                    raise ValueError("Este cliente não está autorizado pelo Administrador para pagamento faturado.")
            documento_fiscal = f.get("documento_fiscal", "Declaração de conteúdo")
            transportadora = f.get("transportadora", "Correios").strip() or "Correios"
            if documento_fiscal not in {"NF-e", "NFC-e", "Cupom fiscal", "Declaração de conteúdo"}:
                raise ValueError("Selecione NF-e, NFC-e, Cupom fiscal ou Declaração de conteúdo.")
            possui_nf = "1" if documento_fiscal in {"NF-e", "NFC-e"} else "0"
            possui_bateria = f.get("possui_bateria", "Não")
            codigos_adicionais = [c for c in f.getlist("servicos_adicionais") if c.isdigit() and len(c) == 3]
            if possui_bateria == "Sim" and "095" not in codigos_adicionais:
                codigos_adicionais.append("095")
            deseja_seguro = "Sim" if "019" in codigos_adicionais else "Não"
            tipo_embalagem = f.get("tipo_embalagem", "Pacote")
            itens_declaracao = []
            for descricao, quantidade, valor in zip(f.getlist("item_descricao"), f.getlist("item_quantidade"), f.getlist("item_valor")):
                descricao = descricao.strip()
                if descricao:
                    if len(descricao) < 5:
                        raise ValueError("A descrição de cada conteúdo deve ter pelo menos 5 caracteres.")
                    qtd, vlr = float(quantidade or 0), float(valor or 0)
                    if qtd <= 0 or vlr <= 0:
                        raise ValueError("Quantidade e valor dos itens da declaração devem ser maiores que zero.")
                    itens_declaracao.append({"descricao": descricao, "quantidade": quantidade, "valor": valor})
            if not itens_declaracao:
                raise ValueError("Preencha os itens da declaração de conteúdo, inclusive para NF-e ou cupom fiscal.")
            chave_nfe = "".join(filter(str.isdigit, f.get("chave_nfe", "")))
            if documento_fiscal in {"NF-e", "NFC-e", "Cupom fiscal"} and len(chave_nfe) != 44:
                raise ValueError("A chave do documento fiscal deve conter exatamente 44 números.")
            if documento_fiscal == "NF-e" and chave_nfe[20:22] != "55":
                raise ValueError("A chave informada não corresponde ao modelo 55 de NF-e.")
            if documento_fiscal == "NFC-e" and chave_nfe[20:22] != "65":
                raise ValueError("A chave informada não corresponde ao modelo 65 de NFC-e.")
            valor_declarado = sum(float(item["quantidade"]) * float(item["valor"]) for item in itens_declaracao)
            lote_produto_id = f.get("estoque_caixa_id", type=int)
            quantidade_produto = f.get("produto_quantidade", type=float) or 0
            produto_venda = None
            custo_produtos = 0
            valor_produtos = 0
            if lote_produto_id:
                conn_produto = db()
                produto_venda = conn_produto.execute(
                    """SELECT ec.id lote_id,ec.saldo,e.id estoque_id,e.item,e.preco_venda,e.custo_unitario
                       FROM estoque_caixa ec JOIN estoque e ON e.id=ec.estoque_id
                       WHERE ec.id=? AND ec.operador_id=? AND ec.status='Aberto'""",
                    (lote_produto_id, session["usuario"]["id"]),
                ).fetchone()
                conn_produto.close()
                if not produto_venda or quantidade_produto <= 0 or quantidade_produto > float(produto_venda["saldo"] or 0):
                    raise ValueError("Produto indisponível ou quantidade maior que o estoque do operador.")
                custo_produtos = round(quantidade_produto * float(produto_venda["custo_unitario"] or 0), 2)
                valor_produtos = round(quantidade_produto * float(produto_venda["preco_venda"] or 0), 2)
            if transportadora == "Correios":
                valor_adicionais, valor_seguro, adicionais_detalhados = calcular_adicionais_a_vista(
                    f["servico"], codigos_adicionais, valor_declarado)
            else:
                valor_adicionais, valor_seguro, codigos_adicionais, adicionais_detalhados = 0.0, 0.0, [], []
            origem = "".join(filter(str.isdigit, f["cep_origem"]))
            destino = "".join(filter(str.isdigit, f["cep_destino"]))
            if len(origem) != 8 or len(destino) != 8:
                raise ValueError("Informe CEPs com 8 números.")
            servico = f["servico"] if transportadora == "Correios" else (f.get("servico_transportadora", "").strip() or transportadora)
            peso = int(f["peso"])
            comp, larg, alt = float(f.get("comprimento") or 0), float(f.get("largura") or 0), float(f.get("altura") or 0)
            modo = "Demonstração"
            correios_modo = settings().get("correios_modo") or os.getenv("CORREIOS_MODO", "demo")
            peso_tarifado, peso_cubico = peso_tarifavel_gramas(peso, comp, larg, alt, tipo_embalagem, servico)
            limite = fora_do_limite_correios(peso, comp, larg, alt, tipo_embalagem, servico) if transportadora == "Correios" else ""
            manuseio = manuseio_especial(servico, comp, larg, alt, tipo_embalagem) if transportadora == "Correios" else 0.0
            if manuseio:
                valor_adicionais = round(valor_adicionais + manuseio, 2)
                adicionais_detalhados.append({"codigo": "ME", "nome": "Manuseio especial (dimensão acima de 70 cm)",
                                              "valor": manuseio})
            if limite:
                raise ValueError(f"Objeto fora do limite dos Correios: {limite}. Confira peso e medidas.")
            vista = tarifa_vista(servico, peso_tarifado, origem, destino) if transportadora == "Correios" else None
            if transportadora != "Correios":
                verificacao = db(); ativa = verificacao.execute(
                    "SELECT 1 FROM integracoes WHERE nome=? AND status='Ativa'", (transportadora,)).fetchone(); verificacao.close()
                if not ativa: raise ValueError("A transportadora escolhida não está habilitada.")
                contrato = float(f.get("preco_integracao") or 0)
                if contrato <= 0: raise ValueError("Refaça a comparação e selecione uma opção válida.")
                vista, prazo, modo = contrato, f.get("prazo_integracao", "Não informado"), f"API {transportadora}"
            elif correios_modo.lower() == "api":
                # Preço de contrato gravado no caixa da atendente: consulta de novo (adicionais e valor
                # declarado mudam o valor); se a API falhar agora, usa o valor coletado no F5.
                coletado = f.get("preco_contrato_coletado", type=float)
                try:
                    contrato = preco_correios_api(servico, origem, destino, peso, comp, larg, alt, tipo_embalagem,
                                                  valor_declarado if deseja_seguro == "Sim" else 0, codigos_adicionais)
                except Exception:
                    if not coletado:
                        raise
                    contrato = coletado
                prazo = f.get("prazo_integracao", "").strip() or prazo_entrega(servico, origem, destino)
                modo = "API Correios"
            else:
                if f.get("preco_contrato_coletado", type=float):
                    contrato = f.get("preco_contrato_coletado", type=float)
                elif vista is not None:
                    contrato = round(vista * 0.68, 2)
                else:
                    faixas = max(1, (peso + 499) // 500)
                    contrato = round((17.90 if servico == "PAC" else 26.90) + faixas * (3.20 if servico == "PAC" else 5.10), 2)
                try:
                    prazo = f.get("prazo_integracao", "").strip() or prazo_entrega(servico, origem, destino)
                except Exception:
                    prazo = "3 a 8 dias (simulado)"
            if vista is None:
                raise ValueError("Não existe tarifa à vista cadastrada para esta rota e faixa de peso.")
            valor_cliente = round(vista + valor_adicionais + valor_produtos, 2)
            if forma_pagamento == "Faturado":
                documento_normalizado = "".join(filter(str.isdigit, remetente_documento))
                credito = db()
                cadastro = credito.execute("""SELECT pode_faturar,limite_faturado,faturado_bloqueado
                    FROM contatos_envio WHERE tipo='Remetente' AND documento=?""", (documento_normalizado,)).fetchone()
                utilizado = credito.execute("""SELECT COALESCE(SUM(c.valor_cliente),0) total FROM cotacoes c
                    LEFT JOIN fatura_cliente_itens fi ON fi.cotacao_id=c.id
                    LEFT JOIN faturas_clientes f ON f.id=fi.fatura_id
                    WHERE REPLACE(REPLACE(REPLACE(c.remetente_documento,'.',''),'-',''),'/','')=?
                    AND c.forma_pagamento='Faturado' AND (fi.id IS NULL OR f.status<>'Paga')
                    AND """ + sem_testes("c.criado_em"),
                    (documento_normalizado,)).fetchone()["total"]
                credito.close()
                if not cadastro or not cadastro["pode_faturar"] or cadastro["faturado_bloqueado"]:
                    raise ValueError("Pagamento faturado bloqueado para este cliente. Procure o Administrador.")
                limite = float(cadastro["limite_faturado"] or 0)
                if limite <= 0 or float(utilizado or 0) + valor_cliente > limite:
                    disponivel = max(0, limite - float(utilizado or 0))
                    raise ValueError(f"Limite do faturado insuficiente. Disponível: R$ {disponivel:,.2f}".replace(",", "X").replace(".", ",").replace("X", "."))
            lucro = round(valor_cliente - contrato - custo_produtos, 2)
            economia = round(vista - contrato, 2) if vista is not None else None
            percentual = round(economia / vista * 100, 2) if vista else None
            conn = db()
            cur = conn.execute(
                """INSERT INTO cotacoes(criado_em,cliente,documento,forma_pagamento,cep_origem,cep_destino,
                servico,peso,comprimento,largura,altura,preco_contrato,preco_vista,valor_cliente,lucro,prazo,modo,
                destinatario_nome,destinatario_rua,destinatario_bairro,destinatario_cidade,destinatario_uf,
                destinatario_numero,destinatario_complemento,custo_produtos,destinatario,remetente_nome,
                remetente_rua,remetente_bairro,remetente_cidade,remetente_uf,remetente_numero,
                remetente_complemento,possui_nf,remetente_documento,destinatario_documento,possui_bateria,
                deseja_seguro,valor_seguro,valor_declarado,tipo_embalagem)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (datetime.now().isoformat(timespec="seconds"), remetente_nome, remetente_documento, forma_pagamento, origem,
                 destino, servico, peso, comp, larg, alt, contrato, vista, valor_cliente, lucro, prazo, modo,
                 destinatario_nome, destinatario_rua, destinatario_bairro, destinatario_cidade, destinatario_uf,
                 destinatario_numero, destinatario_complemento, custo_produtos, destinatario_nome, remetente_nome,
                 remetente_rua, remetente_bairro, remetente_cidade, remetente_uf, remetente_numero,
                 remetente_complemento, possui_nf, remetente_documento, destinatario_documento, possui_bateria,
                 deseja_seguro, valor_seguro, valor_declarado, tipo_embalagem),
            )
            conn.commit()
            cid = cur.lastrowid
            conn.execute("UPDATE cotacoes SET documento_fiscal=?,servicos_adicionais=?,valor_adicionais=? WHERE id=?",
                         (documento_fiscal, json.dumps(codigos_adicionais), valor_adicionais, cid))
            conn.execute("UPDATE cotacoes SET operador_id=?,operador_nome=? WHERE id=?",
                         (session["usuario"]["id"], session["usuario"]["nome"], cid))
            conn.execute("UPDATE cotacoes SET transportadora=?,servico_transportadora=?,cotacao_externa_id=? WHERE id=?",
                         (transportadora, f.get("servico_transportadora", "") or servico,
                          f.get("cotacao_externa_id", ""), cid))
            if produto_venda:
                conn.execute("""INSERT INTO cotacao_produtos(cotacao_id,estoque_caixa_id,estoque_id,produto,
                             quantidade,valor_unitario,custo_unitario) VALUES(?,?,?,?,?,?,?)""",
                             (cid, produto_venda["lote_id"], produto_venda["estoque_id"], produto_venda["item"],
                              quantidade_produto, produto_venda["preco_venda"], produto_venda["custo_unitario"]))
                conn.execute("UPDATE estoque_caixa SET saldo=saldo-? WHERE id=?",
                             (quantidade_produto, produto_venda["lote_id"]))
            conn.execute("INSERT OR IGNORE INTO expedicoes(cotacao_id,captado_por,captado_em) VALUES(?,?,?)",
                         (cid, session["usuario"]["id"], datetime.now().isoformat(timespec="seconds")))
            documento_normalizado = "".join(filter(str.isdigit, remetente_documento))
            conn.execute("""INSERT INTO clientes(documento,nome,cep,rua,numero,complemento,bairro,cidade,uf,atualizado_em)
                         VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(documento) DO UPDATE SET nome=excluded.nome,
                         cep=excluded.cep,rua=excluded.rua,numero=excluded.numero,complemento=excluded.complemento,
                         bairro=excluded.bairro,cidade=excluded.cidade,uf=excluded.uf,atualizado_em=excluded.atualizado_em""",
                         (documento_normalizado, remetente_nome, origem, remetente_rua, remetente_numero,
                          remetente_complemento, remetente_bairro, remetente_cidade, remetente_uf,
                          datetime.now().isoformat(timespec="seconds")))
            salvar_contato(conn, "Remetente", remetente_documento, remetente_nome, origem, remetente_rua,
                           remetente_numero, remetente_complemento, remetente_bairro, remetente_cidade, remetente_uf)
            salvar_contato(conn, "Destinatário", destinatario_documento, destinatario_nome, destino, destinatario_rua,
                           destinatario_numero, destinatario_complemento, destinatario_bairro,
                           destinatario_cidade, destinatario_uf)
            remetente_endereco = f"{remetente_rua}, {remetente_numero}"
            if remetente_complemento:
                remetente_endereco += f" - {remetente_complemento}"
            remetente_endereco += f" - {remetente_bairro} - {remetente_cidade}/{remetente_uf}"
            destinatario_endereco = f"{destinatario_rua}, {destinatario_numero}"
            if destinatario_complemento:
                destinatario_endereco += f" - {destinatario_complemento}"
            destinatario_endereco += f" - {destinatario_bairro} - {destinatario_cidade}/{destinatario_uf}"
            conn.execute("""INSERT OR REPLACE INTO documentos_envio(cotacao_id,tipo_documento,remetente_nome,
                         remetente_documento,remetente_endereco,destinatario_endereco,numero_nota,chave_nfe,
                         valor_nota,conteudo_json,atualizado_em) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                         (cid, "danfe" if documento_fiscal == "NF-e" else ("nfce" if documento_fiscal == "NFC-e" else ("cupom" if documento_fiscal == "Cupom fiscal" else "declaracao")), remetente_nome, remetente_documento,
                          remetente_endereco, destinatario_endereco, f.get("numero_nota", "").strip(),
                          chave_nfe, f.get("valor_nota", type=float) or valor_declarado,
                          json.dumps(itens_declaracao, ensure_ascii=False), datetime.now().isoformat(timespec="seconds")))
            conn.commit()
            conn.close()
            registrar_log("Cotação criada", f"Cotação #{cid}; operador {session['usuario']['nome']}; {transportadora}; valor {valor_cliente:.2f}")
            resultado = {"id": cid, "contrato": contrato, "vista": vista, "valor_cliente": valor_cliente,
                         "lucro": lucro, "economia": economia, "percentual": percentual, "prazo": prazo,
                         "modo": modo, "valor_seguro": valor_seguro, "valor_adicionais": valor_adicionais,
                         "adicionais_detalhados": adicionais_detalhados,
                         "valor_declarado": valor_declarado, "valor_produtos": valor_produtos, "peso_tarifado": peso_tarifado,
                         "peso_cubico": peso_cubico, "transportadora": transportadora,
                         "servico_transportadora": f.get("servico_transportadora", "") or servico}
        except Exception as exc:
            flash(str(exc), "danger")
    conn = db()
    recentes = conn.execute(f"SELECT * FROM cotacoes WHERE {sem_testes()} ORDER BY id DESC LIMIT 5").fetchall()
    produtos_operador = conn.execute(
        """SELECT ec.id lote_id,ec.saldo,e.item,e.sku,e.preco_venda
           FROM estoque_caixa ec JOIN estoque e ON e.id=ec.estoque_id
           WHERE ec.operador_id=? AND ec.status='Aberto' AND COALESCE(ec.saldo,0)>0 ORDER BY e.item""",
        (session["usuario"]["id"],),
    ).fetchall()
    conn.close()
    return render_template("index.html", resultado=resultado, servicos=SERVICOS, recentes=recentes,
                           produtos_operador=produtos_operador, adicionais=listar_adicionais_operacionais(),
                           meios_pagamento=listar_meios_pagamento(),
                           modalidade_carga=request.args.get("modalidade_carga", "fracionada"))


@app.route("/carga-fracionada")
@perfis_permitidos("Master", "Administrador", "Operador de Balcão")
def carga_fracionada():
    return redirect(url_for("index", modalidade_carga="fracionada"))


@app.route("/carga-consolidada")
@perfis_permitidos("Master", "Administrador", "Operador de Balcão")
def carga_consolidada():
    conn = db()
    cargas = conn.execute("SELECT * FROM cargas_consolidadas ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return render_template("carga_consolidada.html", cargas=cargas)


# ----------------- Focus NFe (NFS-e) -----------------
# O token da Focus fica so na variavel de ambiente FOCUS_NFE_TOKEN (Render), nunca no banco.
# O ambiente padrao e homologacao: as notas emitidas la nao tem validade fiscal. Producao so
# e usada com FOCUS_NFE_AMBIENTE=producao.
FOCUS_URLS = {"homologacao": "https://homologacao.focusnfe.com.br", "producao": "https://api.focusnfe.com.br"}
FUSO_BRASILIA = timezone(timedelta(hours=-3))


def focus_ambiente():
    return "producao" if (os.getenv("FOCUS_NFE_AMBIENTE") or "").strip().lower() == "producao" else "homologacao"


def focus_situacao():
    """Resumo para as telas: nunca expoe o token."""
    ambiente = focus_ambiente()
    return {"token_configurado": bool((os.getenv("FOCUS_NFE_TOKEN") or "").strip()), "ambiente": ambiente,
            "ambiente_nome": "Produção" if ambiente == "producao" else "Homologação (sem validade fiscal)"}


def focus_requisicao(metodo, caminho, corpo=None):
    """Chama a API v2 da Focus NFe. Autenticacao HTTP Basic: token como usuario, senha vazia.
    Devolve (status_http, json); erros de rede viram RuntimeError com mensagem para o operador."""
    token = (os.getenv("FOCUS_NFE_TOKEN") or "").strip()
    if not token:
        raise RuntimeError("Token da Focus NFe não configurado. Defina a variável FOCUS_NFE_TOKEN no servidor.")
    url = f"{FOCUS_URLS[focus_ambiente()]}/v2/{caminho}"
    dados = json.dumps(corpo, ensure_ascii=False).encode("utf-8") if corpo is not None else None
    req = urllib.request.Request(url, data=dados, method=metodo, headers={
        "Authorization": "Basic " + base64.b64encode(f"{token}:".encode()).decode(),
        "Content-Type": "application/json", "Accept": "application/json", "User-Agent": "Flash-House-Info/3.4"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resposta:
            status, texto = resposta.status, resposta.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as erro:
        status, texto = erro.code, erro.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError) as erro:
        raise RuntimeError(f"Não foi possível falar com a Focus NFe: {getattr(erro, 'reason', erro)}")
    try:
        retorno = json.loads(texto) if texto.strip() else {}
    except json.JSONDecodeError:
        retorno = {"mensagem": texto[:300]}
    if status == 401:
        raise RuntimeError("A Focus NFe recusou o token (FOCUS_NFE_TOKEN). Confira se é o token do ambiente de "
                           + ("produção." if focus_ambiente() == "producao" else "homologação."))
    return status, retorno if isinstance(retorno, dict) else {"dados": retorno}


def focus_mensagem_erro(retorno):
    """Junta as mensagens de erro que a Focus devolve (mensagem, erros[] ou mensagem_sefaz)."""
    partes = []
    for erro in retorno.get("erros") or []:
        if isinstance(erro, dict):
            texto = erro.get("mensagem") or ""
            if erro.get("correcao"): texto += f" ({erro['correcao']})"
            partes.append(f"{erro.get('codigo') or ''} {texto}".strip())
    for chave in ("mensagem", "mensagem_sefaz"):
        if retorno.get(chave) and retorno[chave] not in partes:
            partes.append(str(retorno[chave]))
    return "; ".join(p for p in partes if p)[:1000]


def codigo_ibge_municipio(cidade, uf):
    """Codigo IBGE (7 digitos) da cidade, guardado em cidades_uf. Na primeira consulta de uma UF,
    baixa a lista de municipios dela da API do IBGE."""
    cidade, uf = (cidade or "").strip(), (uf or "").strip().upper()
    if not cidade or len(uf) != 2:
        return ""
    import unicodedata
    def normalizar(texto):
        return re.sub(r"[^a-z0-9]+", " ", unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode().lower()).strip()
    alvo = normalizar(cidade)
    conn = db()
    row = conn.execute("SELECT codigo_ibge FROM cidades_uf WHERE uf=? AND cidade_normalizada=? AND COALESCE(codigo_ibge,'')<>''",
                       (uf, alvo)).fetchone()
    if not row:
        try:
            req = urllib.request.Request(f"https://servicodados.ibge.gov.br/api/v1/localidades/estados/{uf}/municipios",
                                         headers={"Accept": "application/json", "User-Agent": "Flash-House-Info/3.4"})
            with urllib.request.urlopen(req, timeout=10) as resposta:
                municipios = json.loads(resposta.read().decode("utf-8"))
            for m in municipios:
                conn.execute("""INSERT INTO cidades_uf(cidade,uf,codigo_ibge,cidade_normalizada) VALUES(?,?,?,?)
                                ON CONFLICT(cidade_normalizada,uf) DO UPDATE SET codigo_ibge=excluded.codigo_ibge""",
                             (m["nome"], uf, str(m["id"]), normalizar(m["nome"])))
            conn.commit()
        except Exception as erro:
            app.logger.warning("Código IBGE de %s/%s indisponível: %s", cidade, uf, erro)
        row = conn.execute("SELECT codigo_ibge FROM cidades_uf WHERE uf=? AND cidade_normalizada=?", (uf, alvo)).fetchone()
    conn.close()
    return row["codigo_ibge"] if row and row["codigo_ibge"] else ""


def valor_servico_cotacao(conn, cotacao):
    """Valor do servico (envio + adicionais): o total cobrado menos os produtos vendidos no atendimento."""
    produtos = conn.execute("SELECT COALESCE(SUM(quantidade*valor_unitario),0) total FROM cotacao_produtos WHERE cotacao_id=?",
                            (cotacao["id"],)).fetchone()["total"]
    return round(max(0.0, float(cotacao["valor_cliente"] or 0) - float(produtos or 0)), 2)


def montar_nfse_nacional(conn, cotacao):
    """Monta a DPS no layout nacional da Focus (POST /v2/nfsen). O tomador e o cliente do atendimento."""
    cfg = settings()
    faltando = [rotulo for chave, rotulo in [("empresa_cnpj", "CNPJ da empresa"),
                                             ("nfse_codigo_tributacao_nacional", "código de tributação nacional"),
                                             ("nfse_aliquota", "alíquota do ISS")] if not (cfg.get(chave) or "").strip()]
    codigo_municipio = re.sub(r"\D", "", cfg.get("nfse_codigo_municipio") or "") or \
        codigo_ibge_municipio(cfg.get("empresa_cidade"), cfg.get("empresa_uf"))
    if not codigo_municipio:
        faltando.append("código IBGE do município da empresa")
    if faltando:
        raise ValueError("Preencha em Configurações › Nota fiscal de serviço: " + ", ".join(faltando) + ".")
    documento = re.sub(r"\D", "", cotacao["remetente_documento"] or cotacao["documento"] or "")
    if len(documento) not in (11, 14):
        raise ValueError("O cliente do atendimento não tem CPF/CNPJ válido para a nota.")
    valor = valor_servico_cotacao(conn, cotacao)
    if valor <= 0:
        raise ValueError("Este atendimento não tem valor de serviço para emitir NFS-e.")
    agora = datetime.now(FUSO_BRASILIA)
    servico = cotacao["servico_transportadora"] or cotacao["servico"] or ""
    descricao = (cfg.get("nfse_descricao") or "Serviço de envio {servico}").format_map(
        {"servico": f"{cotacao['transportadora'] or 'Correios'} {servico}".strip(),
         "objeto": cotacao["rastreio"] or cotacao["etiqueta"] or "-",
         "atendimento": cotacao["transacao"] or f"{cotacao['id']:06d}"})
    opcao_simples = (cfg.get("nfse_opcao_simples") or "3").strip()
    dps = {
        "data_emissao": agora.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "data_competencia": agora.strftime("%Y-%m-%d"),
        "codigo_municipio_emissora": codigo_municipio,
        "cnpj_prestador": re.sub(r"\D", "", cfg["empresa_cnpj"]),
        "codigo_opcao_simples_nacional": opcao_simples,
        "regime_especial_tributacao": "0",
        ("cnpj_tomador" if len(documento) == 14 else "cpf_tomador"): documento,
        "razao_social_tomador": (cotacao["remetente_nome"] or cotacao["cliente"] or "")[:150],
        "codigo_municipio_prestacao": codigo_municipio,
        "codigo_tributacao_nacional_iss": re.sub(r"\D", "", cfg["nfse_codigo_tributacao_nacional"]),
        "descricao_servico": descricao[:2000],
        "valor_servico": valor,
        "percentual_aliquota_relativa_municipio": float(str(cfg["nfse_aliquota"]).replace(",", ".")),
        "tributacao_iss": "1",
        "tipo_retencao_iss": "1",
        "indicador_total_tributacao": "0",
    }
    if (cfg.get("empresa_inscricao_municipal") or "").strip():
        dps["inscricao_municipal_prestador"] = cfg["empresa_inscricao_municipal"].strip()
    if opcao_simples == "3":
        dps["regime_tributario_simples_nacional"] = (cfg.get("nfse_regime_simples") or "1").strip()
    if (cfg.get("nfse_codigo_nbs") or "").strip():
        dps["codigo_nbs"] = cfg["nfse_codigo_nbs"].strip()
    cep = re.sub(r"\D", "", cotacao["cep_origem"] or "")
    municipio_tomador = codigo_ibge_municipio(cotacao["remetente_cidade"], cotacao["remetente_uf"])
    if len(cep) == 8 and municipio_tomador and cotacao["remetente_rua"]:
        dps.update({"codigo_municipio_tomador": municipio_tomador, "cep_tomador": cep,
                    "logradouro_tomador": cotacao["remetente_rua"], "numero_tomador": cotacao["remetente_numero"] or "S/N",
                    "bairro_tomador": cotacao["remetente_bairro"] or ""})
        if cotacao["remetente_complemento"]:
            dps["complemento_tomador"] = cotacao["remetente_complemento"]
    cliente = conn.execute("SELECT email FROM clientes WHERE documento=?", (documento,)).fetchone()
    if cliente and cliente["email"]:
        dps["email_tomador"] = cliente["email"]
    return dps, valor


def atualizar_nota_focus(conn, nota, retorno):
    """Grava na nota o que a Focus devolveu (emissao, consulta ou cancelamento)."""
    url = retorno.get("url_danfse") or retorno.get("url") or retorno.get("caminho_danfe") or nota["url"]
    if url and url.startswith("/"):
        url = FOCUS_URLS[nota["ambiente"]] + url
    xml = retorno.get("caminho_xml_nota_fiscal") or nota["caminho_xml"]
    if xml and xml.startswith("/"):
        xml = FOCUS_URLS[nota["ambiente"]] + xml
    conn.execute("""UPDATE notas_fiscais SET status=?,numero=?,codigo_verificacao=?,chave=?,url=?,caminho_xml=?,
                    mensagem=?,resposta_json=?,atualizado_em=? WHERE id=?""",
                 (retorno.get("status") or nota["status"], retorno.get("numero") or nota["numero"],
                  retorno.get("codigo_verificacao") or nota["codigo_verificacao"],
                  retorno.get("chave_nfse") or retorno.get("chave_nfe") or retorno.get("chave") or nota["chave"], url, xml,
                  focus_mensagem_erro(retorno), json.dumps(retorno, ensure_ascii=False),
                  datetime.now().isoformat(timespec="seconds"), nota["id"]))


# Forma de pagamento do comprovante -> codigo tPag da NFC-e.
FORMAS_PAGAMENTO_NFCE = {"Dinheiro": "01", "Cartão de crédito": "03", "Cartão de débito": "04", "Faturado": "05",
                         "PIX": "17", "Transferência bancária": "18"}


def montar_nfce(conn, cotacao):
    """Monta a NFC-e (POST /v2/nfce) dos produtos vendidos no atendimento (embalagens etc.)."""
    cfg = settings()
    cnpj = re.sub(r"\D", "", cfg.get("empresa_cnpj") or "")
    if len(cnpj) != 14:
        raise ValueError("Preencha o CNPJ da empresa em Configurações.")
    produtos = conn.execute("""SELECT p.produto,p.quantidade,p.valor_unitario,e.sku,e.unidade,e.ncm,e.cfop
                               FROM cotacao_produtos p LEFT JOIN estoque e ON e.id=p.estoque_id
                               WHERE p.cotacao_id=? ORDER BY p.id""", (cotacao["id"],)).fetchall()
    if not produtos:
        raise ValueError("Nenhum produto foi vendido neste atendimento; não há NFC-e a emitir.")
    sem_ncm = [p["produto"] for p in produtos if len(re.sub(r"\D", "", p["ncm"] or "")) != 8]
    if sem_ncm:
        raise ValueError("Cadastre o NCM (8 dígitos) em Estoque › Dados fiscais do produto: " + ", ".join(sem_ncm) + ".")
    itens, total = [], 0.0
    for numero, p in enumerate(produtos, start=1):
        quantidade, unitario = float(p["quantidade"] or 0), float(p["valor_unitario"] or 0)
        bruto = round(quantidade * unitario, 2)
        total += bruto
        unidade = (p["unidade"] or "UN").strip().upper()[:6]
        itens.append({
            "numero_item": numero, "codigo_produto": p["sku"] or str(numero), "descricao": p["produto"][:120],
            "codigo_ncm": re.sub(r"\D", "", p["ncm"]), "cfop": (p["cfop"] or cfg.get("nfce_cfop") or "5102").strip(),
            "unidade_comercial": unidade, "quantidade_comercial": quantidade, "valor_unitario_comercial": unitario,
            "unidade_tributavel": unidade, "quantidade_tributavel": quantidade, "valor_unitario_tributavel": unitario,
            "valor_bruto": bruto,
            "icms_origem": (cfg.get("nfce_icms_origem") or "0").strip(),
            "icms_situacao_tributaria": (cfg.get("nfce_icms_situacao") or "102").strip(),
            "pis_situacao_tributaria": (cfg.get("nfce_pis_cofins_situacao") or "49").strip(),
            "cofins_situacao_tributaria": (cfg.get("nfce_pis_cofins_situacao") or "49").strip(),
        })
    total = round(total, 2)
    nfce = {
        "cnpj_emitente": cnpj,
        "data_emissao": datetime.now(FUSO_BRASILIA).strftime("%Y-%m-%dT%H:%M:%S%z"),
        "natureza_operacao": "VENDA AO CONSUMIDOR",
        "presenca_comprador": "1",
        "modalidade_frete": "9",
        "local_destino": "1",
        "items": itens,
        "formas_pagamento": [{"forma_pagamento": FORMAS_PAGAMENTO_NFCE.get(cotacao["forma_pagamento"] or "", "99"),
                              "valor_pagamento": total}],
    }
    documento = re.sub(r"\D", "", cotacao["remetente_documento"] or cotacao["documento"] or "")
    if len(documento) in (11, 14):
        nfce["cpf_destinatario" if len(documento) == 11 else "cnpj_destinatario"] = documento
        if cotacao["remetente_nome"] or cotacao["cliente"]:
            nfce["nome_destinatario"] = (cotacao["remetente_nome"] or cotacao["cliente"])[:60]
    return nfce, total


# Notas emitidas pelo comprovante: NFS-e do envio e NFC-e dos produtos.
MODELOS_NOTA = {
    "nfse": {"tipo": "NFS-e", "caminho": "nfsen", "montar": montar_nfse_nacional},
    "nfce": {"tipo": "NFC-e", "caminho": "nfce", "montar": montar_nfce},
}


def modelo_nota(modelo):
    if modelo not in MODELOS_NOTA:
        abort(404)
    return MODELOS_NOTA[modelo]


@app.route("/recibo/<int:cotacao_id>/<modelo>/emitir", methods=["POST"])
@perfis_permitidos("Administrador", "Operador de Balcão")
def emitir_nota(cotacao_id, modelo):
    m = modelo_nota(modelo)
    conn = db()
    cotacao = get_cotacao_segura(conn, cotacao_id)
    nota = conn.execute("SELECT * FROM notas_fiscais WHERE cotacao_id=? AND tipo=?", (cotacao_id, m["tipo"])).fetchone()
    if not cotacao["transacao"]:
        conn.close(); flash("Aceite o atendimento antes de emitir a nota fiscal.", "warning")
        return redirect(url_for("recibo", cotacao_id=cotacao_id))
    if nota and nota["status"] in ("processando_autorizacao", "autorizado"):
        conn.close(); flash(f"Este atendimento já tem {m['tipo']} emitida ou em processamento.", "warning")
        return redirect(url_for("recibo", cotacao_id=cotacao_id))
    try:
        dados, valor = m["montar"](conn, cotacao)
        # Referencia nova a cada tentativa: a Focus nao aceita repetir uma referencia ja usada.
        referencia = f"loja-{modelo}-{cotacao_id}-{secrets.token_hex(4)}"
        ambiente = focus_ambiente()
        status_http, retorno = focus_requisicao("POST", f"{m['caminho']}?ref={referencia}", dados)
    except (ValueError, RuntimeError) as erro:
        conn.close(); flash(str(erro), "danger")
        return redirect(url_for("recibo", cotacao_id=cotacao_id))
    agora = datetime.now().isoformat(timespec="seconds")
    status = retorno.get("status") or ("processando_autorizacao" if status_http in (200, 201, 202) else "erro_envio")
    conn.execute("""INSERT INTO notas_fiscais(cotacao_id,tipo,ambiente,referencia,status,valor,payload_json,criado_em,atualizado_em,usuario_nome)
                    VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(cotacao_id,tipo) DO UPDATE SET ambiente=excluded.ambiente,
                    referencia=excluded.referencia,status=excluded.status,valor=excluded.valor,payload_json=excluded.payload_json,
                    numero=NULL,codigo_verificacao=NULL,chave=NULL,url=NULL,caminho_xml=NULL,mensagem=NULL,
                    atualizado_em=excluded.atualizado_em,usuario_nome=excluded.usuario_nome""",
                 (cotacao_id, m["tipo"], ambiente, referencia, status, valor, json.dumps(dados, ensure_ascii=False),
                  agora, agora, session["usuario"]["nome"]))
    nota = conn.execute("SELECT * FROM notas_fiscais WHERE cotacao_id=? AND tipo=?", (cotacao_id, m["tipo"])).fetchone()
    atualizar_nota_focus(conn, nota, {**retorno, "status": status})
    conn.commit(); conn.close()
    registrar_log(f"{m['tipo']} enviada à Focus", f"Cotação #{cotacao_id}; ref {referencia}; {ambiente}; HTTP {status_http}; {status}")
    if status_http >= 400 or status in ("erro_autorizacao", "denegado"):
        flash(f"A {m['tipo']} foi recusada: " + (focus_mensagem_erro(retorno) or f"HTTP {status_http}"), "danger")
    elif status == "autorizado":
        flash(f"{m['tipo']} autorizada.", "success")
    else:
        flash(f"{m['tipo']} enviada. O processamento leva alguns segundos; use \"Atualizar situação\" para ver o resultado.", "success")
    return redirect(url_for("recibo", cotacao_id=cotacao_id))


@app.route("/recibo/<int:cotacao_id>/<modelo>/consultar", methods=["POST"])
@perfis_permitidos("Administrador", "Operador de Balcão")
def consultar_nota(cotacao_id, modelo):
    m = modelo_nota(modelo)
    conn = db()
    get_cotacao_segura(conn, cotacao_id)
    nota = conn.execute("SELECT * FROM notas_fiscais WHERE cotacao_id=? AND tipo=?", (cotacao_id, m["tipo"])).fetchone()
    if not nota:
        conn.close(); abort(404)
    if nota["ambiente"] != focus_ambiente():
        conn.close(); flash("Esta nota foi emitida em outro ambiente da Focus NFe e não pode ser consultada daqui.", "warning")
        return redirect(url_for("recibo", cotacao_id=cotacao_id))
    try:
        status_http, retorno = focus_requisicao("GET", f"{m['caminho']}/{nota['referencia']}")
    except RuntimeError as erro:
        conn.close(); flash(str(erro), "danger")
        return redirect(url_for("recibo", cotacao_id=cotacao_id))
    if status_http == 404:
        retorno = {**retorno, "status": "erro_envio"}
    atualizar_nota_focus(conn, nota, retorno)
    conn.commit(); conn.close()
    return redirect(url_for("recibo", cotacao_id=cotacao_id))


@app.route("/recibo/<int:cotacao_id>/<modelo>/cancelar", methods=["POST"])
@perfis_permitidos("Administrador")
def cancelar_nota(cotacao_id, modelo):
    m = modelo_nota(modelo)
    justificativa = request.form.get("justificativa", "").strip()
    if not 15 <= len(justificativa) <= 255:
        flash("A justificativa do cancelamento precisa ter entre 15 e 255 caracteres.", "warning")
        return redirect(url_for("recibo", cotacao_id=cotacao_id))
    conn = db()
    get_cotacao_segura(conn, cotacao_id)
    nota = conn.execute("SELECT * FROM notas_fiscais WHERE cotacao_id=? AND tipo=?", (cotacao_id, m["tipo"])).fetchone()
    if not nota or nota["status"] != "autorizado" or nota["ambiente"] != focus_ambiente():
        conn.close(); flash(f"Só é possível cancelar uma {m['tipo']} autorizada neste ambiente.", "warning")
        return redirect(url_for("recibo", cotacao_id=cotacao_id))
    try:
        status_http, retorno = focus_requisicao("DELETE", f"{m['caminho']}/{nota['referencia']}", {"justificativa": justificativa})
    except RuntimeError as erro:
        conn.close(); flash(str(erro), "danger")
        return redirect(url_for("recibo", cotacao_id=cotacao_id))
    atualizar_nota_focus(conn, nota, retorno)
    conn.commit(); conn.close()
    registrar_log(f"{m['tipo']} cancelada na Focus", f"Cotação #{cotacao_id}; ref {nota['referencia']}; HTTP {status_http}; {retorno.get('status')}")
    if retorno.get("status") == "cancelado":
        flash(f"{m['tipo']} cancelada.", "success")
    else:
        flash("Cancelamento não confirmado: " + (focus_mensagem_erro(retorno) or f"HTTP {status_http}"), "danger")
    return redirect(url_for("recibo", cotacao_id=cotacao_id))


@app.route("/recibo/<int:cotacao_id>", methods=["GET", "POST"])
@perfis_permitidos("Administrador", "Operador de Balcão")
def recibo(cotacao_id):
    conn = db()
    cotacao = get_cotacao_segura(conn, cotacao_id)
    if request.method == "POST":
        conn.execute(
            """UPDATE cotacoes SET etiqueta=?, rastreio=?, destinatario=?, observacoes=?, forma_pagamento=? WHERE id=?""",
            (request.form.get("etiqueta", "").strip(), request.form.get("rastreio", "").strip(),
             request.form.get("destinatario", "").strip(), request.form.get("observacoes", "").strip(),
             request.form.get("forma_pagamento", "").strip(), cotacao_id),
        )
        conn.commit()
        conn.close()
        flash("Dados do recibo atualizados.", "success")
        return redirect(url_for("recibo", cotacao_id=cotacao_id))
    produtos = conn.execute("SELECT * FROM cotacao_produtos WHERE cotacao_id=? ORDER BY id", (cotacao_id,)).fetchall()
    total_produtos = sum(float(p["quantidade"] or 0) * float(p["valor_unitario"] or 0) for p in produtos)
    lista = json.loads(cotacao["servicos_adicionais"] or "[]") if cotacao["servicos_adicionais"] else []
    # Objetos vindos da Recepção guardam os adicionais da PPN (dicionários) em vez de códigos.
    codigos = [str(x) for x in lista if not isinstance(x, dict)]
    adicionais = [{"nome": n, "valor": 0} for n in nomes_adicionais_ppn([x for x in lista if isinstance(x, dict)])]
    if codigos:
        marcas=",".join("?" for _ in codigos)
        adicionais+=conn.execute(f"SELECT codigo,nome,valor FROM servicos_adicionais_correios WHERE codigo IN ({marcas}) GROUP BY codigo ORDER BY nome",codigos).fetchall()
    tem_ppn = bool(conn.execute("SELECT 1 FROM prepostagens WHERE cotacao_id=? AND COALESCE(ppn_id,'')<>''",
                                (cotacao_id,)).fetchone())
    notas = {n["tipo"]: n for n in conn.execute("SELECT * FROM notas_fiscais WHERE cotacao_id=?", (cotacao_id,)).fetchall()}
    conn.close()
    return render_template("recibo.html", cotacao=cotacao, produtos=produtos, total_produtos=total_produtos,
                           total_pacotes=max(0,float(cotacao["valor_cliente"] or 0)-total_produtos), adicionais=adicionais,
                           tem_ppn=tem_ppn, notas=notas, focus=focus_situacao())


@app.route("/cotacao/<int:cotacao_id>/aceitar", methods=["POST"])
@perfis_permitidos("Administrador", "Operador de Balcão")
def aceitar_cotacao(cotacao_id):
    conn = db()
    cotacao = conn.execute("SELECT * FROM cotacoes WHERE id=?", (cotacao_id,)).fetchone()
    doc = conn.execute("SELECT * FROM documentos_envio WHERE cotacao_id=?", (cotacao_id,)).fetchone()
    existente = conn.execute("SELECT * FROM prepostagens WHERE cotacao_id=?", (cotacao_id,)).fetchone()
    if not cotacao:
        conn.close(); abort(404)
    if (cotacao["transportadora"] or "Correios") != "Correios":
        transacao = lancar_lucro_postagem(conn, cotacao)
        conn.commit(); conn.close()
        registrar_log("Envio externo selecionado", f"Cotação #{cotacao_id}; transação {transacao}; {cotacao['transportadora']}; {cotacao['servico_transportadora']}")
        flash(f"Opção {cotacao['transportadora']} selecionada. A criação do envio será liberada após a homologação das credenciais dessa transportadora; nenhuma PPN dos Correios foi criada.", "warning")
        return redirect(url_for("recibo", cotacao_id=cotacao_id))
    if existente and existente["ppn_id"]:
        possui_rotulo = bool(existente["rotulo"])
        conn.close()
        if possui_rotulo:
            flash("Esta cotação já possui etiqueta PPN e não foi duplicada.", "warning")
            return redirect(url_for("rotulo_ppn_zebra", cotacao_id=cotacao_id))
        flash("A postagem já existe. O sistema tentará recuperar somente o rótulo.", "warning")
        return redirect(url_for("recuperar_rotulo_ppn", cotacao_id=cotacao_id))
    try:
        resposta = criar_prepostagem_ppn(cotacao, doc)
        ppn_id = localizar_campo_ppn(resposta, ["id", "idPrePostagem", "codigoPrePostagem"])
        etiqueta = localizar_campo_ppn(resposta, ["codigoObjeto", "codigoRastreio", "numeroEtiqueta", "codigoEtiqueta"])
        if not ppn_id:
            raise RuntimeError("A PPN respondeu sem um identificador de pré-postagem reconhecido.")
        conn.execute("""INSERT INTO prepostagens(cotacao_id,ppn_id,codigo_etiqueta,status,resposta_json,criado_em)
                     VALUES(?,?,?,?,?,?) ON CONFLICT(cotacao_id) DO UPDATE SET ppn_id=excluded.ppn_id,
                     codigo_etiqueta=excluded.codigo_etiqueta,status=excluded.status,resposta_json=excluded.resposta_json""",
                     (cotacao_id, ppn_id, etiqueta, "Pré-postado", json.dumps(resposta, ensure_ascii=False), datetime.now().isoformat(timespec="seconds")))
        conn.execute("UPDATE cotacoes SET etiqueta=?,rastreio=? WHERE id=?", (etiqueta or ppn_id, etiqueta or "", cotacao_id))
        transacao = lancar_lucro_postagem(conn, cotacao)
        conn.commit()
        try:
            rotulo, rotulo_mime = gerar_rotulo_ppn(ppn_id)
            rotulo, rotulo_mime = normalizar_resposta_rotulo(rotulo, rotulo_mime)
            conn.execute("UPDATE prepostagens SET rotulo=?,rotulo_mime=? WHERE cotacao_id=?",
                         (rotulo, rotulo_mime, cotacao_id))
            try:
                consulta = consultar_prepostagem_ppn(ppn_id)
                etiqueta_consultada = localizar_campo_ppn(consulta, ["codigoObjeto", "codigoRastreio", "numeroEtiqueta", "codigoEtiqueta"])
                if etiqueta_consultada:
                    etiqueta = etiqueta_consultada
                    conn.execute("UPDATE prepostagens SET codigo_etiqueta=? WHERE cotacao_id=?", (etiqueta, cotacao_id))
                    conn.execute("UPDATE cotacoes SET etiqueta=?,rastreio=? WHERE id=?", (etiqueta, etiqueta, cotacao_id))
            except Exception:
                pass
            conn.commit()
        except Exception as erro_rotulo:
            conn.close()
            registrar_log("PPN criada; rótulo pendente", f"Cotação #{cotacao_id}; {erro_rotulo}")
            flash(str(erro_rotulo), "warning")
            return redirect(url_for("etiqueta_correios", cotacao_id=cotacao_id))
        conn.close()
        registrar_log("Cotação aceita / PPN", f"Cotação #{cotacao_id}; transação {transacao}; PPN {ppn_id}; etiqueta {etiqueta or 'pendente'}")
        flash(f"Cotação aceita e pré-postagem criada na PPN. Transação {transacao}.", "success")
        return redirect(url_for("rotulo_ppn_zebra", cotacao_id=cotacao_id))
    except Exception as exc:
        conn.close(); flash(str(exc), "danger"); return redirect(url_for("index"))


@app.route("/cotacao/<int:cotacao_id>/recuperar-rotulo", methods=["GET", "POST"])
@perfis_permitidos("Administrador", "Operador de Balcão", "Expedidor")
def recuperar_rotulo_ppn(cotacao_id):
    conn = db()
    row = conn.execute("SELECT * FROM prepostagens WHERE cotacao_id=?", (cotacao_id,)).fetchone()
    if not row or not row["ppn_id"]:
        conn.close()
        flash("Esta cotação ainda não possui uma pré-postagem PPN para recuperar.", "warning")
        return redirect(url_for("etiqueta_correios", cotacao_id=cotacao_id))
    if row["rotulo"]:
        conn.close()
        return redirect(url_for("rotulo_ppn_zebra", cotacao_id=cotacao_id))
    ppn_id = row["ppn_id"]
    try:
        rotulo, mime = normalizar_resposta_rotulo(*gerar_rotulo_ppn(ppn_id))
        etiqueta = row["codigo_etiqueta"]
        try:
            consulta = consultar_prepostagem_ppn(ppn_id)
            etiqueta = localizar_campo_ppn(
                consulta, ["codigoObjeto", "codigoRastreio", "numeroEtiqueta", "codigoEtiqueta"]
            ) or etiqueta
        except Exception:
            pass
        conn.execute(
            "UPDATE prepostagens SET rotulo=?,rotulo_mime=?,codigo_etiqueta=?,status=? WHERE cotacao_id=?",
            (rotulo, mime, etiqueta, "Rótulo recuperado", cotacao_id),
        )
        if etiqueta:
            conn.execute("UPDATE cotacoes SET etiqueta=?,rastreio=? WHERE id=?", (etiqueta, etiqueta, cotacao_id))
        conn.commit()
        conn.close()
        registrar_log("Rótulo PPN recuperado", f"Cotação #{cotacao_id}; PPN {ppn_id}")
        flash("Rótulo oficial recuperado sem criar uma nova postagem.", "success")
        return redirect(url_for("rotulo_ppn_zebra", cotacao_id=cotacao_id))
    except Exception as exc:
        conn.close()
        registrar_log("Falha ao recuperar rótulo PPN", f"Cotação #{cotacao_id}; PPN {ppn_id}; {exc}")
        flash(str(exc), "danger")
        return redirect(url_for("etiqueta_correios", cotacao_id=cotacao_id))


@app.route("/rotulo-ppn/<int:cotacao_id>")
@perfis_permitidos("Administrador", "Operador de Balcão", "Expedidor")
def rotulo_ppn(cotacao_id):
    conn = db()
    row = conn.execute("""
        SELECT p.*, c.operador_id
        FROM prepostagens p
        JOIN cotacoes c ON c.id = p.cotacao_id
        WHERE p.cotacao_id=?
    """, (cotacao_id,)).fetchone()
    conn.close()
    if row and session["usuario"]["perfil"] == "Operador de Balcão" and row["operador_id"] != session["usuario"]["id"]:
        abort(403)
    if not row or not row["rotulo"]:
        flash("O rótulo oficial ainda não está disponível na PPN.", "warning")
        return redirect(url_for("etiqueta_correios", cotacao_id=cotacao_id))
    return send_file(io.BytesIO(row["rotulo"]), mimetype=row["rotulo_mime"] or "application/pdf",
                     download_name=f"etiqueta_correios_{cotacao_id}.pdf", as_attachment=False)


@app.route("/rotulo-ppn-zebra/<int:cotacao_id>")
@perfis_permitidos("Administrador", "Operador de Balcão", "Expedidor")
def rotulo_ppn_zebra(cotacao_id):
    conn = db()
    row = conn.execute("SELECT * FROM prepostagens WHERE cotacao_id=?", (cotacao_id,)).fetchone()
    cotacao = conn.execute("SELECT * FROM cotacoes WHERE id=?", (cotacao_id,)).fetchone()
    doc = conn.execute("SELECT * FROM documentos_envio WHERE cotacao_id=?", (cotacao_id,)).fetchone()
    conn.close()
    if not row or not row["rotulo"]:
        flash("O rótulo oficial ainda não está disponível na PPN.", "warning")
        return redirect(url_for("etiqueta_correios", cotacao_id=cotacao_id))
    if (row["rotulo_mime"] or "application/pdf") != "application/pdf":
        flash("A PPN não devolveu o rótulo em PDF para separação 10×15.", "danger")
        return redirect(url_for("rotulo_ppn", cotacao_id=cotacao_id))
    try:
        arquivo = sobrepor_triagem_rotulo(rotulo_oficial_com_documento(cotacao, doc, row["rotulo"]), cotacao)
    except Exception as exc:
        flash(f"Não foi possível preparar as duas etiquetas 10×15: {exc}", "danger")
        return redirect(url_for("rotulo_ppn", cotacao_id=cotacao_id))
    paginas = 2 if doc and doc["tipo_documento"] == "declaracao" else 1
    registrar_log("Rótulo oficial PPN preparado", f"Cotação #{cotacao_id}; {paginas} etiqueta(s) 100×150 mm")
    return send_file(io.BytesIO(arquivo), mimetype="application/pdf",
                     download_name=f"ppn_zebra_10x15_{cotacao_id}.pdf", as_attachment=False)


@app.route("/rotulo-ppn-pdf/<int:cotacao_id>")
@perfis_permitidos("Administrador", "Master", "Operador de Balcão", "Expedidor")
def rotulo_ppn_pdf(cotacao_id):
    conn = db()
    row = conn.execute("SELECT * FROM prepostagens WHERE cotacao_id=?", (cotacao_id,)).fetchone()
    cotacao = conn.execute("SELECT * FROM cotacoes WHERE id=?", (cotacao_id,)).fetchone()
    doc = conn.execute("SELECT * FROM documentos_envio WHERE cotacao_id=?", (cotacao_id,)).fetchone(); conn.close()
    if not row or not row["rotulo"]:
        flash("O rótulo oficial ainda não está disponível na PPN.", "warning")
        return redirect(url_for("etiqueta_correios", cotacao_id=cotacao_id))
    try:
        arquivo = sobrepor_triagem_rotulo(rotulo_oficial_com_documento(cotacao, doc, row["rotulo"]), cotacao)
    except Exception as exc:
        flash(f"Não foi possível preparar o PDF oficial: {exc}", "danger")
        return redirect(url_for("rotulo_ppn_zebra", cotacao_id=cotacao_id))
    registrar_log("Rótulo reimpresso em PDF", f"Cotação #{cotacao_id}; padrão oficial PPN")
    return send_file(io.BytesIO(arquivo), mimetype="application/pdf",
                     download_name=f"ppn_oficial_{cotacao_id}.pdf", as_attachment=False)


@app.route("/historico")
@perfis_permitidos("Administrador", "Operador de Balcão")
def historico():
    conn = db()
    if session["usuario"]["perfil"] in {"Administrador", "Master"}:
        rows = conn.execute(f"SELECT * FROM cotacoes WHERE {sem_testes()} ORDER BY id DESC LIMIT 500").fetchall()
    else:
        rows = conn.execute(f"SELECT * FROM cotacoes WHERE operador_id=? AND {sem_testes()} ORDER BY id DESC LIMIT 500",
                            (session["usuario"]["id"],)).fetchall()
    conn.close()
    return render_template("historico.html", rows=rows)


@app.route("/configuracoes", methods=["GET", "POST"])
@perfis_permitidos("Administrador", "Master")
def configuracoes():
    if request.method == "POST":
        if session["usuario"]["perfil"] != "Master":
            abort(403)
        allowed = ["empresa_nome", "empresa_subtitulo", "empresa_cnpj", "empresa_telefone", "empresa_email",
                   "empresa_cep", "empresa_rua", "empresa_numero", "empresa_complemento", "empresa_bairro", "empresa_cidade", "empresa_uf",
                   "zebra_nome", "zebra_conexao", "zebra_linguagem", "zebra_tamanho", "zebra_dpi", "zebra_automatica",
                   "margem_padrao", "tipo_margem_padrao", "preco_logistica_reversa", "preco_recepcao_objeto",
                   "impressora_etiquetas", "impressora_recibos", "impressora_romaneios", "impressora_relatorios", "banco_integrado",
                   "email_cobranca", "smtp_servidor", "smtp_porta", "smtp_usuario", "smtp_senha", "mensagem_cobranca_padrao",
                   "empresa_inscricao_municipal", "nfse_codigo_municipio", "nfse_codigo_tributacao_nacional", "nfse_codigo_nbs",
                   "nfse_aliquota", "nfse_opcao_simples", "nfse_regime_simples", "nfse_descricao",
                   "nfce_cfop", "nfce_icms_origem", "nfce_icms_situacao", "nfce_pis_cofins_situacao"]
        conn = db()
        for key in allowed:
            valor = request.form.get(key, "").strip()
            if key == "smtp_senha":
                if not valor:
                    continue
                valor = encrypt_val(valor)
            conn.execute("INSERT INTO configuracoes(chave,valor) VALUES(?,?) ON CONFLICT(chave) DO UPDATE SET valor=excluded.valor", (key, valor))
        conn.commit()
        conn.close()
        flash("Configurações salvas.", "success")
        return redirect(url_for("configuracoes"))
    return render_template("configuracoes.html", dados=settings_publicas(), impressoras=impressoras_windows(),
                           somente_leitura=session["usuario"]["perfil"] != "Master", focus=focus_situacao())

def gerar_zpl_teste(cotacao=None):
    destinatario = (cotacao["destinatario"] if cotacao and cotacao["destinatario"] else "CLIENTE DE TESTE")
    cep = cep_formatado(cotacao["cep_destino"] if cotacao else "13224450")
    servico = cotacao["servico"] if cotacao else "SEDEX"
    rastreio = (cotacao["rastreio"] if cotacao and cotacao["rastreio"] else "AB123456789BR")
    return f"""^XA
^PW799
^LL1199
^FO40,40^A0N,35,35^FDFLASH HOUSE INFO^FS
^FO40,95^A0N,55,55^FD{servico}^FS
^FO40,180^A0N,28,28^FDDESTINATARIO: {destinatario[:35]}^FS
^FO40,225^A0N,28,28^FDCEP: {cep}^FS
^FO80,320^BY3^BCN,130,Y,N,N^FD{rastreio}^FS
^XZ"""


@app.route("/enviar-zebra/<int:cotacao_id>", methods=["POST"])
@perfis_permitidos("Administrador", "Expedidor")
def enviar_zebra(cotacao_id):
    conf = settings()
    conn = db()
    cotacao = conn.execute("SELECT * FROM cotacoes WHERE id=?", (cotacao_id,)).fetchone()
    if not cotacao:
        conn.close()
        abort(404)
    zpl = gerar_zpl_teste(cotacao)
    conn.execute(
        "INSERT INTO impressoes(criado_em,cotacao_id,impressora,copias,status,motivo,zpl) VALUES(?,?,?,?,?,?,?)",
        (datetime.now().isoformat(timespec="seconds"), cotacao_id,
         conf.get("zebra_nome", "Zebra Balcão Principal"), 1, "Impresso", "Envio direto pelo balcão", zpl),
    )
    conn.commit()
    conn.close()
    flash("Etiqueta enviada para a Zebra com sucesso.", "success")
    return redirect(url_for("impressao_zebra", cotacao_id=cotacao_id))


@app.route("/impressao-zebra", methods=["GET", "POST"])
@perfis_permitidos("Administrador", "Expedidor")
def impressao_zebra():
    conf = settings()
    cotacao_id = request.values.get("cotacao_id", type=int)
    conn = db()
    cotacao = conn.execute("SELECT * FROM cotacoes WHERE id=?", (cotacao_id,)).fetchone() if cotacao_id else None
    if request.method == "POST":
        acao = request.form.get("acao", "imprimir")
        copias = max(1, min(99, request.form.get("copias", type=int) or 1))
        status = "Impresso" if acao in {"imprimir", "reimprimir"} else "Falha"
        motivo = request.form.get("motivo", "").strip()
        zpl = gerar_zpl_teste(cotacao)
        conn.execute(
            "INSERT INTO impressoes(criado_em,cotacao_id,impressora,copias,status,motivo,zpl) VALUES(?,?,?,?,?,?,?)",
            (datetime.now().isoformat(timespec="seconds"), cotacao_id, conf.get("zebra_nome", "Zebra"), copias, status, motivo, zpl),
        )
        conn.commit()
        flash("Etiqueta enviada ao Print Service e impressa com sucesso." if status == "Impresso" else "Falha simulada: verifique a Zebra e tente novamente.", "success" if status == "Impresso" else "danger")
        return redirect(url_for("impressao_zebra", cotacao_id=cotacao_id) if cotacao_id else url_for("impressao_zebra"))
    historico = conn.execute("SELECT * FROM impressoes ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    return render_template("impressao_zebra.html", dados=conf, cotacao=cotacao, historico=historico, zpl=gerar_zpl_teste(cotacao))


@app.route("/expedicao")
@perfis_permitidos("Administrador", "Expedidor")
def expedicao():
    conn = db()
    rows = conn.execute("""SELECT e.*, c.cliente,c.destinatario,c.cep_destino,c.servico,c.peso,c.rastreio,
                          COALESCE(NULLIF(c.transportadora,''),'Correios') transportadora,
                          u.nome captado_nome FROM expedicoes e JOIN cotacoes c ON c.id=e.cotacao_id
                          LEFT JOIN usuarios u ON u.id=e.captado_por WHERE """ + sem_testes("c.criado_em") + """
                          ORDER BY e.id DESC""").fetchall()
    romaneios = conn.execute(f"""SELECT r.*,COUNT(e.id) objetos FROM romaneios r JOIN expedicoes e ON e.romaneio_id=r.id
        JOIN cotacoes c ON c.id=e.cotacao_id WHERE {sem_testes("c.criado_em")} GROUP BY r.id ORDER BY r.id DESC LIMIT 30""").fetchall()
    conn.close()
    return render_template("expedicao.html", rows=rows, romaneios=romaneios)


@app.route("/expedicao/leitor", methods=["POST"])
@perfis_permitidos("Administrador", "Expedidor")
def expedicao_leitor():
    codigo = request.form.get("codigo", "").strip().upper()
    conn = db()
    row = conn.execute("""SELECT e.id FROM expedicoes e JOIN cotacoes c ON c.id=e.cotacao_id
                        WHERE (UPPER(COALESCE(c.rastreio,''))=? OR UPPER(COALESCE(c.etiqueta,''))=?
                        OR CAST(c.id AS TEXT)=?) AND """ + sem_testes("c.criado_em"), (codigo, codigo, codigo.lstrip("#"))).fetchone()
    if not row:
        conn.close(); flash("Código não encontrado na fila de expedição.", "danger"); return redirect(url_for("expedicao"))
    conn.execute("UPDATE expedicoes SET status='Conferido',expedido_por=?,expedido_em=? WHERE id=?",
                 (session["usuario"]["id"], datetime.now().isoformat(timespec="seconds"), row["id"]))
    conn.commit(); conn.close()
    registrar_log("Expedição por leitor", f"Código {codigo}")
    flash(f"Objeto {codigo} conferido e separado para o romaneio da transportadora.", "success")
    return redirect(url_for("expedicao"))


@app.route("/expedicao/fechar-romaneios", methods=["POST"])
@perfis_permitidos("Administrador", "Master", "Expedidor")
def fechar_romaneios():
    conn=db(); grupos=conn.execute("""SELECT COALESCE(NULLIF(c.transportadora,''),'Correios') transportadora,COUNT(*) total
      FROM expedicoes e JOIN cotacoes c ON c.id=e.cotacao_id WHERE e.status='Conferido' AND e.romaneio_id IS NULL
      AND """ + sem_testes("c.criado_em") + """ GROUP BY COALESCE(NULLIF(c.transportadora,''),'Correios')""").fetchall(); criados=[]
    for g in grupos:
        cur=conn.execute("INSERT INTO romaneios(criado_em,transportadora,expedidor_id,expedidor_nome) VALUES(?,?,?,?)",
          (datetime.now().isoformat(timespec="seconds"),g["transportadora"],session["usuario"]["id"],session["usuario"]["nome"]))
        rid=cur.lastrowid;conn.execute("""UPDATE expedicoes SET romaneio_id=?,status='Expedido' WHERE id IN(
          SELECT e.id FROM expedicoes e JOIN cotacoes c ON c.id=e.cotacao_id WHERE e.status='Conferido' AND e.romaneio_id IS NULL
          AND COALESCE(NULLIF(c.transportadora,''),'Correios')=? AND """ + sem_testes("c.criado_em") + ")",(rid,g["transportadora"]));criados.append((rid,g["transportadora"],g["total"]))
    conn.commit();conn.close()
    if not criados: flash("Não há objetos conferidos para fechar.","warning")
    else: registrar_log("Romaneios fechados","; ".join(f"#{i} {t} ({n})" for i,t,n in criados));flash(f"{len(criados)} romaneio(s) criado(s), um por transportadora.","success")
    return redirect(url_for("expedicao"))


@app.route("/triagem", methods=["GET", "POST"])
@perfis_permitidos("Master")
def triagem():
    conn = db()
    if request.method == "POST":
        if session["usuario"]["perfil"] not in {"Administrador", "Master"}:
            conn.close(); abort(403)
        inicio = "".join(filter(str.isdigit, request.form.get("cep_inicio", ""))).zfill(8)
        fim = "".join(filter(str.isdigit, request.form.get("cep_final", ""))).zfill(8)
        tamanho = request.form.get("tamanho", "").strip().upper()
        if len(inicio) != 8 or len(fim) != 8 or inicio > fim or tamanho not in {"", "GO", "PO"}:
            conn.close(); flash("Confira a faixa de CEP e o tamanho GO/PO.", "danger"); return redirect(request.url)
        conn.execute("""INSERT OR REPLACE INTO triagem_plano(destino,direcao,categoria,formato,posicao,cep_inicio,cep_final,tamanho,observacoes)
                     VALUES(?,?,?,?,?,?,?,?,?)""", (request.form.get("destino", "").strip(), request.form.get("direcao", "").strip(),
                     request.form.get("categoria", "").strip().upper(), request.form.get("formato", "").strip().upper(),
                     request.form["posicao"].strip().upper(), inicio, fim, tamanho, request.form.get("observacoes", "").strip()))
        conn.commit(); flash("Regra de triagem cadastrada.", "success")
    rows = conn.execute("SELECT * FROM triagem_plano ORDER BY CAST(posicao AS INTEGER),categoria,formato,cep_inicio").fetchall(); conn.close()
    return render_template("triagem.html", rows=rows)


@app.route("/relatorio-expedicao")
@perfis_permitidos("Administrador", "Master", "Expedidor")
def relatorio_expedicao():
    data = request.args.get("data") or datetime.now().strftime("%Y-%m-%d")
    romaneio_id = request.args.get("romaneio",type=int)
    conn = db()
    rows = conn.execute("""SELECT e.*,c.rastreio,c.etiqueta,c.destinatario_nome,c.cep_destino,c.servico,c.peso,
                    c.comprimento,c.largura,c.altura,c.tipo_embalagem,COALESCE(NULLIF(c.transportadora,''),'Correios') transportadora,
                    u.nome expedidor_nome
                    FROM expedicoes e JOIN cotacoes c ON c.id=e.cotacao_id
                    LEFT JOIN usuarios u ON u.id=e.expedido_por
                    WHERE e.status='Expedido' AND ((? IS NOT NULL AND e.romaneio_id=?) OR (? IS NULL AND substr(e.expedido_em,1,10)=?))
                    AND """ + sem_testes("c.criado_em") + """ ORDER BY e.expedido_em""", (romaneio_id,romaneio_id,romaneio_id,data)).fetchall()
    resultado = []
    for row in rows:
        destino, tamanho, direcao = destino_triagem(row)
        resultado.append({**dict(row), "triagem": destino, "classe": tamanho, "direcao": direcao})
    romaneio=conn.execute("SELECT * FROM romaneios WHERE id=?",(romaneio_id,)).fetchone() if romaneio_id else None
    conn.close()
    return render_template("romaneio_expedicao.html", rows=resultado, data=data, romaneio=romaneio,
                           impressora=settings().get("impressora_romaneios",""))


@app.route("/api/cep/<cep>")
@login_required
def consultar_cep(cep):
    numero = "".join(filter(str.isdigit, cep))[:8]
    if len(numero) != 8:
        return jsonify({"encontrado": False, "mensagem": "CEP inválido."}), 400

    conn = db()
    row = conn.execute("SELECT * FROM ceps WHERE cep=?", (numero,)).fetchone()
    conn.close()
    if row:
        return jsonify({"encontrado": True, "logradouro": row["logradouro"], "bairro": row["bairro"],
                        "cidade": row["cidade"], "uf": row["uf"], "fonte": "cache local"})

    try:
        endereco = cep_conectagov_api(numero)
    except Exception:
        endereco = None
    if endereco:
        conn = db()
        conn.execute(
            """INSERT INTO ceps(cep,logradouro,bairro,cidade,uf) VALUES(?,?,?,?,?)
               ON CONFLICT(cep) DO UPDATE SET logradouro=excluded.logradouro,bairro=excluded.bairro,
               cidade=excluded.cidade,uf=excluded.uf""",
            (numero, endereco["logradouro"], endereco["bairro"], endereco["cidade"], endereco["uf"]),
        )
        conn.commit(); conn.close()
        return jsonify({"encontrado": True, **endereco, "fonte": "Conecta gov.br"})

    if os.path.exists(CEPX_DB):
        cepx = sqlite3.connect(f"file:{CEPX_DB}?mode=ro", uri=True)
        cepx.row_factory = sqlite3.Row
        row = cepx.execute(
            """SELECT st.nome logradouro, n.nome bairro, c.nome cidade, u.sigla uf
               FROM ceps z JOIN states u ON u.id=z.uf_id JOIN cities c ON c.id=z.city_id
               JOIN neighborhoods n ON n.id=z.neigh_id JOIN streets st ON st.id=z.street_id
               WHERE z.cep=?""", (int(numero),)
        ).fetchone()
        cepx.close()
        if row:
            return jsonify({"encontrado": True, "logradouro": row["logradouro"], "bairro": row["bairro"],
                            "cidade": row["cidade"], "uf": row["uf"], "fonte": "CEPX local"})

    provedores = [
        ("BrasilAPI", f"https://brasilapi.com.br/api/cep/v2/{numero}",
         {"logradouro": "street", "bairro": "neighborhood", "cidade": "city", "uf": "state"}),
        ("OpenCEP", f"https://opencep.com/v1/{numero}.json",
         {"logradouro": "logradouro", "bairro": "bairro", "cidade": "localidade", "uf": "uf"}),
    ]
    for fonte, url, campos in provedores:
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "Flash-House-Info/3.4"})
            with urllib.request.urlopen(req, timeout=6) as response:
                dados = json.loads(response.read().decode("utf-8"))
            endereco = {destino: str(dados.get(origem) or "").strip() for destino, origem in campos.items()}
            if endereco["cidade"] and endereco["uf"]:
                conn = db()
                conn.execute(
                    """INSERT INTO ceps(cep,logradouro,bairro,cidade,uf) VALUES(?,?,?,?,?)
                       ON CONFLICT(cep) DO UPDATE SET logradouro=excluded.logradouro,bairro=excluded.bairro,
                       cidade=excluded.cidade,uf=excluded.uf""",
                    (numero, endereco["logradouro"], endereco["bairro"], endereco["cidade"], endereco["uf"]),
                )
                conn.commit(); conn.close()
                return jsonify({"encontrado": True, **endereco, "fonte": fonte})
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError):
            continue
    return jsonify({"encontrado": False, "mensagem": "CEP não localizado nas bases disponíveis."}), 404


@app.route("/logs")
@perfis_permitidos("Administrador", "Master")
def logs_sistema():
    conn = db(); rows = conn.execute("SELECT * FROM logs_sistema ORDER BY id DESC LIMIT 1000").fetchall(); conn.close()
    return render_template("logs.html", rows=rows)


GRUPOS_TARIFA = ["LOCAL", "ESTADUAL", "N1", "N2", "N3", "N4", "N5", "N6"]


@app.route("/tarifas")
@perfis_permitidos("Administrador", "Master", "Operador de Balcão")
def tarifas():
    """Consulta (somente leitura) da tarifa a vista: tabela nacional de precos,
    enquadramento das cidades de destino com prazos e consulta por CEP."""
    servico = request.args.get("servico", "PAC") if request.args.get("servico") in ("PAC", "SEDEX") else "PAC"
    base = "CAPITAL" if request.args.get("base") == "CAPITAL" else "INTERIOR"
    uf, busca = request.args.get("uf", "").strip().upper(), request.args.get("busca", "").strip()
    cep = "".join(filter(str.isdigit, request.args.get("cep", "")))
    conn = db()
    precos = conn.execute("SELECT * FROM tarifas_precos WHERE servico=? AND base=? ORDER BY peso_min",
                          (servico, base)).fetchall()
    faixas = {}
    for p in precos:
        faixas.setdefault((p["peso_min"], p["peso_max"]), {})[p["grupo"]] = p
    kg_adicional = {p["grupo"]: p["kg_adicional"] for p in precos}
    vigencia = precos[0]["vigencia"] if precos else ""
    origens = conn.execute("SELECT DISTINCT origem_uf, origem_cidade FROM tarifas_enquadramento").fetchall()
    resumo = {r["grupo"]: r["n"] for r in conn.execute(
        "SELECT grupo, COUNT(*) n FROM tarifas_enquadramento GROUP BY grupo")}
    filtros, parametros = [], []
    if uf:
        filtros.append("e.destino_uf=?"); parametros.append(uf)
    if busca:
        filtros.append("e.destino_cidade LIKE ? COLLATE NOCASE"); parametros.append(f"%{busca}%")
    cidades = conn.execute(
        """SELECT e.*, pp.prazo prazo_pac, ps.prazo prazo_sedex FROM tarifas_enquadramento e
           LEFT JOIN prazos_rota pp ON pp.origem_uf=e.origem_uf AND pp.origem_cidade=e.origem_cidade
                AND pp.destino_uf=e.destino_uf AND pp.destino_cidade=e.destino_cidade AND pp.servico='PAC'
           LEFT JOIN prazos_rota ps ON ps.origem_uf=e.origem_uf AND ps.origem_cidade=e.origem_cidade
                AND ps.destino_uf=e.destino_uf AND ps.destino_cidade=e.destino_cidade AND ps.servico='SEDEX'"""
        + (" WHERE " + " AND ".join(filtros) if filtros else "")
        + " ORDER BY e.destino_uf, e.destino_cidade LIMIT 300", parametros).fetchall() if (uf or busca) else []
    ufs = [r[0] for r in conn.execute("SELECT DISTINCT destino_uf FROM tarifas_enquadramento ORDER BY 1")]
    regras = conn.execute("SELECT * FROM tarifas_parametros WHERE servico=? ORDER BY rowid", (servico,)).fetchall()
    conn.close()
    consulta = None
    if cep:
        conn = db()
        origem = origem_tarifa_agencia(conn)
        conn.close()
        destino = localidade_cep(cep)
        rota = None
        if origem and destino:
            conn = db()
            rota = conn.execute("""SELECT grupo, base FROM tarifas_enquadramento WHERE origem_uf=? AND origem_cidade=?
                                   AND destino_uf=? AND destino_cidade=?""", (*origem, destino[0], destino[2])).fetchone()
            conn.close()
        consulta = {"cep": cep, "destino": destino and f"{destino[2]}/{destino[0]}",
                    "origem": origem and f"{origem[1]}/{origem[0]}", "grupo": rota and rota["grupo"],
                    "base": rota and rota["base"],
                    "precos": {s: preco_vista(s, rota["grupo"], rota["base"], 300) for s in ("PAC", "SEDEX")} if rota else {}}
    return render_template("tarifas.html", servico=servico, base=base, grupos=GRUPOS_TARIFA, faixas=faixas,
                           kg_adicional=kg_adicional, vigencia=vigencia, origens=origens, resumo=resumo,
                           cidades=cidades, ufs=ufs, uf=uf, busca=busca, consulta=consulta,
                           regras=regras)


@app.route("/api/contatos")
@perfis_permitidos("Administrador", "Operador de Balcão")
def api_contatos():
    termo = request.args.get("q", "").strip()
    tipo = request.args.get("tipo", "Remetente")
    if tipo not in {"Remetente", "Destinatário"} or len(termo) < 2:
        return jsonify([])
    numeros = "".join(filter(str.isdigit, termo))
    if numeros and not re.search(r"[^\d.\-/\s]", termo):
        # Digitando CPF/CNPJ: sugere pelos primeiros números do documento.
        filtro, parametros = "c.documento LIKE ?", (f"{numeros}%",)
    else:
        filtro, parametros = ("(c.nome LIKE ? COLLATE NOCASE OR c.documento LIKE ?)",
                              (f"%{termo}%", f"%{numeros}%" if numeros else "--"))
    # Uma linha por endereco cadastrado do contato: com mais de um, o operador escolhe o certo.
    conn = db()
    rows = conn.execute(
        f"""SELECT c.tipo, c.documento, c.nome,
                   COALESCE(e.cep,c.cep) cep, COALESCE(e.rua,c.rua) rua, COALESCE(e.numero,c.numero) numero,
                   COALESCE(e.complemento,c.complemento) complemento, COALESCE(e.bairro,c.bairro) bairro,
                   COALESCE(e.cidade,c.cidade) cidade, COALESCE(e.uf,c.uf) uf,
                   (SELECT COUNT(*) FROM enderecos_contato x WHERE x.tipo=c.tipo AND x.documento=c.documento) total_enderecos
            FROM contatos_envio c LEFT JOIN enderecos_contato e ON e.tipo=c.tipo AND e.documento=c.documento
            WHERE c.tipo=? AND {filtro}
            ORDER BY c.atualizado_em DESC, e.atualizado_em DESC LIMIT 20""",
        (tipo, *parametros)).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])


@app.route("/api/validar-documento/<documento>")
@perfis_permitidos("Administrador", "Operador de Balcão")
def api_validar_documento(documento):
    numeros = "".join(filter(str.isdigit, documento))
    return jsonify({"valido": documento_valido(numeros), "tipo": "CPF" if len(numeros) == 11 else "CNPJ" if len(numeros) == 14 else "Documento"})


@app.route("/clientes", methods=["GET", "POST"])
@perfis_permitidos("Administrador", "Master")
def clientes():
    busca = request.args.get("q", "").strip()
    selecionado = "".join(filter(str.isdigit, request.args.get("documento", "")))
    conn = db()
    if request.method == "POST":
        if session["usuario"]["perfil"] not in {"Administrador", "Master"}: conn.close(); abort(403)
        f=request.form; documento="".join(filter(str.isdigit,f.get("documento","")))
        if not documento_valido(documento): conn.close(); flash("CPF/CNPJ inválido.","danger"); return redirect(request.url)
        cep="".join(filter(str.isdigit,f.get("cep",""))); numero=f.get("numero","").strip() or "S/N"
        limite=max(0,f.get("limite_faturado",type=float) or 0); pode=1 if f.get("pode_faturar") else 0
        dados=("Remetente",documento,f.get("nome","").strip(),cep,f.get("rua","").strip(),numero,
               f.get("complemento","").strip(),f.get("bairro","").strip(),f.get("cidade","").strip(),
               f.get("uf","").strip().upper(),datetime.now().isoformat(timespec="seconds"),pode,limite,f.get("email","").strip(),0)
        conn.execute("""INSERT INTO contatos_envio(tipo,documento,nome,cep,rua,numero,complemento,bairro,cidade,uf,atualizado_em,pode_faturar,limite_faturado,email,faturado_bloqueado)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tipo,documento) DO UPDATE SET nome=excluded.nome,cep=excluded.cep,
          rua=excluded.rua,numero=excluded.numero,complemento=excluded.complemento,bairro=excluded.bairro,
          cidade=excluded.cidade,uf=excluded.uf,pode_faturar=excluded.pode_faturar,limite_faturado=excluded.limite_faturado,
          email=excluded.email,faturado_bloqueado=0,bloqueado_em=NULL,atualizado_em=excluded.atualizado_em""",dados)
        conn.execute("""INSERT INTO clientes(documento,nome,cep,rua,numero,complemento,bairro,cidade,uf,atualizado_em,pode_faturar,limite_faturado,email,faturado_bloqueado)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(documento) DO UPDATE SET nome=excluded.nome,cep=excluded.cep,
          rua=excluded.rua,numero=excluded.numero,complemento=excluded.complemento,bairro=excluded.bairro,
          cidade=excluded.cidade,uf=excluded.uf,pode_faturar=excluded.pode_faturar,limite_faturado=excluded.limite_faturado,
          email=excluded.email,faturado_bloqueado=0,bloqueado_em=NULL,atualizado_em=excluded.atualizado_em""",
          (documento,dados[2],cep,dados[4],numero,dados[6],dados[7],dados[8],dados[9],dados[10],pode,limite,dados[13],0))
        salvar_endereco(conn,"Remetente",documento,cep,dados[4],numero,dados[6],dados[7],dados[8],dados[9])
        conn.commit();conn.close();registrar_log("Cliente cadastrado",f"{dados[2]}; faturado={'Sim' if dados[11] else 'Não'}")
        flash("Cliente cadastrado com sucesso.","success");return redirect(url_for("clientes"))
    operador_filtro = "" if session["usuario"]["perfil"] in {"Administrador", "Master"} else " AND q.operador_id=?"
    parametros = [f"%{busca}%", f"%{''.join(filter(str.isdigit, busca))}%" if busca else "%"]
    if operador_filtro: parametros.append(session["usuario"]["id"])
    rows = conn.execute(
        """SELECT c.*,COUNT(q.id) total_envios,MAX(q.criado_em) ultimo_envio
           FROM contatos_envio c LEFT JOIN cotacoes q ON
           REPLACE(REPLACE(REPLACE(q.remetente_documento,'.',''),'-',''),'/','')=c.documento
           AND """ + sem_testes("q.criado_em") + """
           WHERE c.tipo='Remetente' AND (c.nome LIKE ? COLLATE NOCASE OR c.documento LIKE ?)""" + operador_filtro + """
           GROUP BY c.id ORDER BY c.nome LIMIT 500""",
        parametros,
    ).fetchall()
    envios = []
    if selecionado:
        filtro_envio = "" if not operador_filtro else " AND operador_id=?"
        parametros_envio = [selecionado] + ([session["usuario"]["id"]] if filtro_envio else [])
        envios = conn.execute(
            """SELECT * FROM cotacoes WHERE REPLACE(REPLACE(REPLACE(remetente_documento,'.',''),'-',''),'/','')=?
               AND """ + sem_testes() + filtro_envio + " ORDER BY id DESC", parametros_envio
        ).fetchall()
    conn.close()
    return render_template("clientes.html", rows=rows, envios=envios, selecionado=selecionado, busca=busca)


@app.route("/enviados")
@perfis_permitidos("Administrador", "Operador de Balcão")
def enviados():
    busca = request.args.get("q", "").strip()
    conn = db()
    filtro = "" if session["usuario"]["perfil"] in {"Administrador", "Master"} else " AND operador_id=?"
    params = [f"%{busca}%", f"%{busca}%", f"%{busca}%"] + ([session["usuario"]["id"]] if filtro else [])
    rows = conn.execute(
        """SELECT *,(SELECT p.ppn_id FROM prepostagens p WHERE p.cotacao_id=cotacoes.id) ppn_id
           FROM cotacoes WHERE (remetente_nome LIKE ? COLLATE NOCASE
           OR destinatario_nome LIKE ? COLLATE NOCASE OR rastreio LIKE ? COLLATE NOCASE)
           AND """ + sem_testes() + filtro +
        " ORDER BY id DESC LIMIT 1000", params
    ).fetchall()
    conn.close()
    return render_template("enviados.html", rows=rows, busca=busca)


@app.route("/cobranca", methods=["GET", "POST"])
@perfis_permitidos("Administrador", "Master")
def cobranca():
    conn = db(); hoje = datetime.now().date()
    if request.method == "POST":
        acao = request.form.get("acao", "")
        if acao == "emitir_faturas":
            inicio = request.form.get("data_inicial") or hoje.replace(day=1).isoformat()
            fim = request.form.get("data_final") or hoje.isoformat()
            vencimento = request.form.get("vencimento") or (hoje + timedelta(days=5)).isoformat()
            grupos = conn.execute("""SELECT REPLACE(REPLACE(REPLACE(c.remetente_documento,'.',''),'-',''),'/','') documento,
                COALESCE(c.remetente_nome,c.cliente) nome,ce.email,SUM(c.valor_cliente) total
                FROM cotacoes c LEFT JOIN fatura_cliente_itens fi ON fi.cotacao_id=c.id
                LEFT JOIN contatos_envio ce ON ce.tipo='Remetente' AND ce.documento=REPLACE(REPLACE(REPLACE(c.remetente_documento,'.',''),'-',''),'/','')
                WHERE c.forma_pagamento='Faturado' AND fi.id IS NULL AND substr(c.criado_em,1,10) BETWEEN ? AND ?
                AND """ + sem_testes("c.criado_em") + """
                GROUP BY REPLACE(REPLACE(REPLACE(c.remetente_documento,'.',''),'-',''),'/',''),COALESCE(c.remetente_nome,c.cliente),ce.email""", (inicio, fim)).fetchall()
            criadas = 0
            for grupo in grupos:
                cur = conn.execute("""INSERT INTO faturas_clientes(criado_em,cliente_documento,cliente_nome,data_inicial,data_final,
                    valor_total,status,banco,criado_por,vencimento,email) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (datetime.now().isoformat(timespec="seconds"), grupo["documento"], grupo["nome"], inicio, fim,
                     grupo["total"], "Aberta", settings().get("banco_integrado", ""), session["usuario"]["nome"], vencimento, grupo["email"]))
                fid = cur.lastrowid
                conn.execute("""INSERT INTO fatura_cliente_itens(fatura_id,cotacao_id,codigo_objeto,transportadora,servico,valor)
                    SELECT ?,c.id,COALESCE(c.rastreio,c.etiqueta),COALESCE(c.transportadora,'Correios'),c.servico,c.valor_cliente
                    FROM cotacoes c LEFT JOIN fatura_cliente_itens fi ON fi.cotacao_id=c.id
                    WHERE c.forma_pagamento='Faturado' AND fi.id IS NULL
                    AND REPLACE(REPLACE(REPLACE(c.remetente_documento,'.',''),'-',''),'/','')=?
                    AND substr(c.criado_em,1,10) BETWEEN ? AND ? AND """ + sem_testes("c.criado_em"), (fid, grupo["documento"], inicio, fim)); criadas += 1
            conn.commit(); flash(f"{criadas} fatura(s) quinzenal(is) emitida(s).", "success")
        elif acao == "emitir_boletos":
            faturas = conn.execute("""SELECT f.* FROM faturas_clientes f LEFT JOIN boletos_clientes b ON b.fatura_id=f.id AND b.status NOT IN ('Baixado','Cancelado')
                WHERE f.status IN ('Aberta','Vencida') AND b.id IS NULL""").fetchall(); quantidade = 0
            for fatura in faturas:
                ref = f"FAT-{fatura['id']:06d}-{int(time.time())}-{quantidade}"
                conn.execute("INSERT INTO boletos_clientes(fatura_id,criado_em,referencia,valor,vencimento,status) VALUES(?,?,?,?,?,?)",
                             (fatura["id"],datetime.now().isoformat(timespec="seconds"),ref,fatura["valor_total"],fatura["vencimento"],"Pendente integração bancária"))
                conn.execute("UPDATE faturas_clientes SET boleto_referencia=? WHERE id=?",(ref,fatura["id"])); quantidade += 1
            conn.commit(); flash(f"{quantidade} boleto(s) preparado(s) para o banco integrado.", "success")
        elif acao == "gerar_cobranca":
            fatura = conn.execute("SELECT * FROM faturas_clientes WHERE id=?",(request.form.get("fatura_id"),)).fetchone()
            if fatura:
                modelo=settings().get("mensagem_cobranca_padrao",""); valor=brl(fatura["valor_total"])
                mensagem=modelo.replace("{cliente}",fatura["cliente_nome"]).replace("{fatura}",str(fatura["id"])).replace("{valor}",valor)
                conn.execute("INSERT INTO cobrancas_email(fatura_id,criado_em,destinatario,assunto,mensagem,status) VALUES(?,?,?,?,?,?)",
                    (fatura["id"],datetime.now().isoformat(timespec="seconds"),fatura["email"],f"Cobrança da fatura {fatura['id']}",mensagem,"Pendente de envio"));conn.commit()
                flash("Cobrança gerada e colocada na fila de e-mail.","success")
        elif acao == "reemitir_boleto":
            fid=request.form.get("fatura_id"); conn.execute("UPDATE boletos_clientes SET status='Baixado',baixado_em=?,motivo_baixa='Reemitido após vencimento/não pagamento' WHERE fatura_id=? AND status<>'Pago'",(datetime.now().isoformat(timespec="seconds"),fid))
            fatura=conn.execute("SELECT * FROM faturas_clientes WHERE id=?",(fid,)).fetchone()
            if fatura:
                ref=f"FAT-{int(fid):06d}-{int(time.time())}"; venc=(hoje+timedelta(days=5)).isoformat()
                conn.execute("INSERT INTO boletos_clientes(fatura_id,criado_em,referencia,valor,vencimento,status) VALUES(?,?,?,?,?,?)",(fid,datetime.now().isoformat(timespec="seconds"),ref,fatura["valor_total"],venc,"Pendente integração bancária"));conn.execute("UPDATE faturas_clientes SET boleto_referencia=?,vencimento=?,status='Aberta' WHERE id=?",(ref,venc,fid));conn.commit();flash("Novo boleto preparado.","success")
        registrar_log("Cobrança", acao); conn.close(); return redirect(url_for("cobranca"))
    faturas=conn.execute("""SELECT f.*,b.status boleto_status,b.vencimento boleto_vencimento FROM faturas_clientes f
        LEFT JOIN boletos_clientes b ON b.id=(SELECT MAX(id) FROM boletos_clientes WHERE fatura_id=f.id)
        WHERE f.status<>'Paga' ORDER BY f.id DESC""").fetchall(); conn.close()
    return render_template("cobranca.html",faturas=faturas,hoje=hoje.isoformat())


def aplicar_curva_abc(rows):
    total = sum(float(r["vendas"] or 0) for r in rows) or 1
    acumulado = 0; saida = []
    for r in rows:
        valor = float(r["vendas"] or 0); acumulado += valor
        percentual = valor / total * 100; acumulado_pct = acumulado / total * 100
        classe = "A" if acumulado_pct <= 80 or len(saida) == 0 else ("B" if acumulado_pct <= 95 else "C")
        saida.append({**dict(r), "percentual": percentual, "acumulado": acumulado_pct, "classe": classe})
    return saida


@app.route("/relatorios")
@perfis_permitidos("Administrador", "Master")
def relatorios():
    hoje = datetime.now().strftime("%Y-%m-%d")
    tipo = request.args.get("tipo", "diario")
    data = request.args.get("data") or hoje
    data_inicial = request.args.get("data_inicial") or hoje
    data_final = request.args.get("data_final") or hoje
    inicio, fim = ((data, data) if tipo == "diario" else (data_inicial, data_final))
    conn = db()
    base = """CAST(COALESCE(valor_cliente,0) AS REAL)-CAST(COALESCE(preco_contrato,0) AS REAL)-
              CAST(COALESCE(custo_produtos,0) AS REAL)"""
    filtro_operador = f" AND {sem_testes()}" + (
        "" if session["usuario"]["perfil"] in {"Administrador", "Master"} else " AND operador_id=?")
    parametros_periodo = [inicio, fim] + ([session["usuario"]["id"]] if "operador_id" in filtro_operador else [])
    entrada = "CAST(COALESCE(preco_vista,0) AS REAL)+CAST(COALESCE(valor_adicionais,0) AS REAL)"
    totais = conn.execute(f"""SELECT COUNT(*) quantidade,COALESCE(SUM(valor_cliente),0) vendas,
              COALESCE(SUM({entrada}),0) entradas,
              COALESCE(SUM(valor_cliente-({entrada})),0) produtos_venda,
              COALESCE(SUM(CAST(preco_contrato AS REAL)),0) fretes,
              COALESCE(SUM(CAST(custo_produtos AS REAL)),0) produtos,COALESCE(SUM({base}),0) liquido
              FROM cotacoes WHERE substr(criado_em,1,10) BETWEEN ? AND ?{filtro_operador}""", parametros_periodo).fetchone()
    if tipo == "diario":
        rows = conn.execute(f"""SELECT *,COALESCE(operador_nome,'Não identificado') operador,{base} liquido_relatorio,
                  {entrada} entrada_vista,valor_cliente-({entrada}) produtos_venda
                  FROM cotacoes WHERE substr(criado_em,1,10)=?{filtro_operador} ORDER BY id DESC""",
                  [data] + ([session["usuario"]["id"]] if "operador_id" in filtro_operador else [])).fetchall()
    else:
        campo = "COALESCE(remetente_nome,cliente,'Não identificado')" if tipo in {"cliente", "abc_clientes"} else "COALESCE(operador_nome,'Não identificado')"
        rows = conn.execute(f"""SELECT {campo} grupo,COUNT(*) quantidade,COALESCE(SUM(valor_cliente),0) vendas,
                  COALESCE(SUM({entrada}),0) entradas,COALESCE(SUM(valor_cliente-({entrada})),0) produtos_venda,
                  COALESCE(SUM(preco_contrato),0) fretes,COALESCE(SUM(custo_produtos),0) produtos,
                  COALESCE(SUM({base}),0) liquido FROM cotacoes
                  WHERE substr(criado_em,1,10) BETWEEN ? AND ?{filtro_operador} GROUP BY {campo} ORDER BY vendas DESC""",
                  parametros_periodo).fetchall()
        if tipo.startswith("abc_"):
            rows = aplicar_curva_abc(rows)
    conn.close()
    return render_template("relatorios.html", rows=rows, totais=totais, data=data, tipo=tipo,
                           data_inicial=data_inicial, data_final=data_final)


@app.route("/api/etiquetas")
@perfis_permitidos("Administrador", "Master", "Operador de Balcão", "Expedidor")
def api_etiquetas():
    data = request.args.get("data") or datetime.now().strftime("%Y-%m-%d")
    perfil, usuario_id = session["usuario"]["perfil"], session["usuario"]["id"]
    filtro, params = "", [data]
    if perfil not in {"Administrador", "Master"}:
        filtro = " AND c.operador_id=?"; params.append(usuario_id)
    conn = db()
    rows = conn.execute("""SELECT c.id,c.criado_em,c.servico,c.destinatario_nome,c.rastreio,
                    COALESCE(c.operador_nome,'Não identificado') operador
                    FROM cotacoes c JOIN prepostagens p ON p.cotacao_id=c.id
                    WHERE substr(c.criado_em,1,10)=? AND p.rotulo IS NOT NULL AND """ + sem_testes("c.criado_em") + filtro + " ORDER BY c.id DESC", params).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/conferencia-faturas", methods=["GET", "POST"])
@perfis_permitidos("Administrador", "Master")
def conferencia_faturas():
    conn = db()
    if request.method == "POST":
        arquivo = request.files.get("arquivo")
        if not arquivo or not arquivo.filename.lower().endswith(".csv"):
            conn.close(); flash("Envie a fatura em CSV, com as colunas etiqueta e valor_cobrado.", "danger"); return redirect(request.url)
        conteudo = arquivo.read().decode("utf-8-sig", errors="replace")
        amostra = conteudo[:2048]; delimitador = ";" if amostra.count(";") >= amostra.count(",") else ","
        linhas = list(csv.DictReader(io.StringIO(conteudo), delimiter=delimitador))
        integracao = request.form.get("integracao", "Correios").strip()
        inicio, fim = request.form["data_inicial"], request.form["data_final"]
        cur = conn.execute("INSERT INTO conferencias_fatura(integracao,data_inicial,data_final,arquivo,criado_em,usuario_nome) VALUES(?,?,?,?,?,?)",
                           (integracao, inicio, fim, arquivo.filename, datetime.now().isoformat(timespec="seconds"), session["usuario"]["nome"]))
        conferencia_id = cur.lastrowid
        for linha in linhas:
            etiqueta = "".join(str(linha.get("etiqueta") or linha.get("objeto") or linha.get("rastreio") or "").split()).upper()
            valor_txt = str(linha.get("valor_cobrado") or linha.get("valor") or "0").replace("R$", "").strip().replace(".", "").replace(",", ".")
            try: cobrado = float(valor_txt)
            except ValueError: cobrado = 0
            cotacao = conn.execute("SELECT id,preco_contrato FROM cotacoes WHERE rastreio=? OR etiqueta=?", (etiqueta, etiqueta)).fetchone()
            esperado = float(cotacao["preco_contrato"] or 0) if cotacao else 0
            diferenca = round(cobrado - esperado, 2)
            status = "Não localizado" if not cotacao else ("Divergente" if abs(diferenca) > .01 else "Conferido")
            conn.execute("INSERT INTO conferencia_fatura_itens(conferencia_id,etiqueta,valor_cobrado,valor_esperado,diferenca,status,detalhes) VALUES(?,?,?,?,?,?,?)",
                         (conferencia_id, etiqueta, cobrado, esperado, diferenca, status, "Objeto não encontrado no período" if not cotacao else ""))
        conn.commit(); flash(f"Fatura conferida: {len(linhas)} lançamento(s).", "success")
        return redirect(url_for("conferencia_faturas", id=conferencia_id))
    selecionada = request.args.get("id", type=int)
    itens = conn.execute("SELECT * FROM conferencia_fatura_itens WHERE conferencia_id=? ORDER BY status DESC,id", (selecionada,)).fetchall() if selecionada else []
    historico = conn.execute("SELECT * FROM conferencias_fatura ORDER BY id DESC LIMIT 30").fetchall(); conn.close()
    return render_template("conferencia_faturas.html", itens=itens, historico=historico, selecionada=selecionada)


@app.route("/expedicao/<int:expedicao_id>/expedir", methods=["POST"])
@perfis_permitidos("Administrador", "Expedidor")
def expedir_etiqueta(expedicao_id):
    conn = db()
    row = conn.execute("SELECT * FROM expedicoes WHERE id=?", (expedicao_id,)).fetchone()
    if not row:
        conn.close(); abort(404)
    conn.execute("UPDATE expedicoes SET status='Expedido',expedido_por=?,expedido_em=?,observacoes=? WHERE id=?",
                 (session["usuario"]["id"], datetime.now().isoformat(timespec="seconds"), request.form.get("observacoes", "").strip(), expedicao_id))
    conn.commit(); conn.close()
    flash("Objeto expedido e etiqueta processada.", "success")
    return redirect(url_for("expedicao"))


@app.route("/etiqueta-correios/<int:cotacao_id>", methods=["GET", "POST"])
@perfis_permitidos("Administrador", "Operador de Balcão", "Expedidor")
def etiqueta_correios(cotacao_id):
    conn = db()
    cotacao = conn.execute("SELECT * FROM cotacoes WHERE id=?", (cotacao_id,)).fetchone()
    if not cotacao:
        conn.close(); abort(404)
    prepostagem_existente = conn.execute(
        "SELECT ppn_id,codigo_etiqueta,rotulo FROM prepostagens WHERE cotacao_id=?", (cotacao_id,)
    ).fetchone()
    if request.method == "POST" and prepostagem_existente and prepostagem_existente["ppn_id"]:
        conn.close()
        flash("Envio bloqueado: depois que a PPN é criada, os dados não podem ser alterados.", "warning")
        return redirect(url_for("etiqueta_correios", cotacao_id=cotacao_id))
    if request.method == "POST":
        tipo_documento = request.form.get("tipo_documento", "declaracao")
        if tipo_documento not in {"declaracao", "cupom", "danfe", "nfce"}:
            conn.close(); flash("Tipo de documento fiscal inválido.", "danger"); return redirect(request.url)
        chave_digitada = "".join(filter(str.isdigit, request.form.get("chave_nfe", "")))
        if tipo_documento in {"danfe", "nfce", "cupom"}:
            esperado = "55" if tipo_documento == "danfe" else ("65" if tipo_documento == "nfce" else "qualquer modelo fiscal válido")
            if len(chave_digitada) != 44 or (tipo_documento != "cupom" and chave_digitada[20:22] != esperado):
                conn.close(); flash(f"A chave deve ter 44 números e corresponder ao modelo {esperado}.", "danger"); return redirect(request.url)
        itens = []
        descricoes = request.form.getlist("item_descricao")
        quantidades = request.form.getlist("item_quantidade")
        valores = request.form.getlist("item_valor")
        for descricao, quantidade, valor in zip(descricoes, quantidades, valores):
            if descricao.strip():
                itens.append({"descricao": descricao.strip(), "quantidade": quantidade or "1", "valor": valor or "0"})
        dados = (tipo_documento, request.form.get("remetente_nome", "").strip(),
                 request.form.get("remetente_documento", "").strip(), request.form.get("remetente_endereco", "").strip(),
                 request.form.get("destinatario_endereco", "").strip(), request.form.get("numero_nota", "").strip(),
                 chave_digitada, request.form.get("valor_nota", type=float) or 0,
                 json.dumps(itens, ensure_ascii=False), datetime.now().isoformat(timespec="seconds"), cotacao_id)
        conn.execute("""INSERT INTO documentos_envio(tipo_documento,remetente_nome,remetente_documento,remetente_endereco,
                     destinatario_endereco,numero_nota,chave_nfe,valor_nota,conteudo_json,atualizado_em,cotacao_id)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(cotacao_id) DO UPDATE SET tipo_documento=excluded.tipo_documento,
                     remetente_nome=excluded.remetente_nome,remetente_documento=excluded.remetente_documento,
                     remetente_endereco=excluded.remetente_endereco,destinatario_endereco=excluded.destinatario_endereco,
                     numero_nota=excluded.numero_nota,chave_nfe=excluded.chave_nfe,valor_nota=excluded.valor_nota,
                     conteudo_json=excluded.conteudo_json,atualizado_em=excluded.atualizado_em""", dados)
        conn.commit()
        flash("Dados da etiqueta salvos.", "success")
    doc = conn.execute("SELECT * FROM documentos_envio WHERE cotacao_id=?", (cotacao_id,)).fetchone()
    prepostagem = conn.execute(
        "SELECT ppn_id,codigo_etiqueta,rotulo FROM prepostagens WHERE cotacao_id=?", (cotacao_id,)
    ).fetchone()
    conn.close()
    itens = json.loads(doc["conteudo_json"] or "[]") if doc else []
    auto_imprimir = request.args.get("imprimir") == "1"
    if auto_imprimir and prepostagem and prepostagem["rotulo"]:
        registrar_log("Etiqueta oficial enviada à impressora", f"Cotação #{cotacao_id}; impressora {settings().get('zebra_nome','Padrão')}")
        return redirect(url_for("rotulo_ppn_zebra", cotacao_id=cotacao_id))
    return render_template("etiqueta_correios.html", cotacao=cotacao, doc=doc, itens=itens,
                           fiscal=dados_chave_fiscal(doc["chave_nfe"] if doc else ""),
                           tem_prepostagem=bool(prepostagem and prepostagem["ppn_id"]),
                           tem_rotulo_ppn=bool(prepostagem and prepostagem["rotulo"]), auto_imprimir=auto_imprimir,
                           bloqueado=bool(prepostagem and prepostagem["ppn_id"]))


@app.route("/integracoes", methods=["GET", "POST"])
@perfis_permitidos("Master")
def integracoes():
    if request.method == "POST":
        # Toda alteração em Integrações exige confirmar a senha do Master.
        conn = db()
        master = conn.execute("SELECT senha_hash FROM usuarios WHERE id=? AND perfil='Master'",
                              (session["usuario"]["id"],)).fetchone()
        conn.close()
        if not master or not check_password_hash(master["senha_hash"], request.form.get("senha_master", "")):
            registrar_log("Senha do Master recusada em Integrações", f"Ação {request.form.get('acao', '')}")
            flash("Senha do Master incorreta. Nada foi alterado.", "danger")
            return redirect(url_for("integracoes"))
    conn = db()
    if request.method == "POST":
        if request.form.get("acao") == "testar_salvar_pagamento":
            meio = request.form.get("meio_pagamento", "").strip()
            campos = {
                "PagSeguro": ("pagseguro_ativo", ["pagseguro_email"], ["pagseguro_token"]),
                "Mercado Pago": ("mercadopago_ativo", ["mercadopago_public_key"], ["mercadopago_access_token"]),
                "PicPay": ("picpay_ativo", ["picpay_client_id"], ["picpay_token"]),
                "Stone": ("stone_ativo", ["stone_client_id"], ["stone_token"]),
            }
            if meio not in campos:
                conn.close(); abort(400)
            chave_ativo, simples, segredos = campos[meio]
            ativo = "1" if request.form.get("ativo") else "0"
            conn.execute("INSERT INTO configuracoes(chave,valor) VALUES(?,?) ON CONFLICT(chave) DO UPDATE SET valor=excluded.valor",
                         (chave_ativo, ativo))
            for chave in simples:
                conn.execute("INSERT INTO configuracoes(chave,valor) VALUES(?,?) ON CONFLICT(chave) DO UPDATE SET valor=excluded.valor",
                             (chave, request.form.get(chave, "").strip()))
            for chave in segredos:
                valor = request.form.get(chave, "").strip()
                if valor:
                    conn.execute("INSERT INTO configuracoes(chave,valor) VALUES(?,?) ON CONFLICT(chave) DO UPDATE SET valor=excluded.valor",
                                 (chave, encrypt_val(valor)))
            conn.execute("UPDATE integracoes SET status=? WHERE nome=?", ("Ativa" if ativo == "1" else "Inativa", meio))
            conn.commit(); conn.close()
            prefixo = chave_ativo.removesuffix("_ativo")
            agora = datetime.now().isoformat(timespec="seconds")
            try:
                testar_integracao_pagamento(meio, settings())
                status_teste, categoria, mensagem = "Válida", "success", f"{meio}: credenciais válidas. Integração salva."
            except Exception as exc:
                status_teste, categoria, mensagem = "Falhou", "danger", f"{meio}: configuração salva, mas o teste falhou — {exc}"
            status_conn = db()
            for chave, valor in ((f"{prefixo}_teste_status", status_teste), (f"{prefixo}_teste_em", agora)):
                status_conn.execute("INSERT INTO configuracoes(chave,valor) VALUES(?,?) ON CONFLICT(chave) DO UPDATE SET valor=excluded.valor",
                                    (chave, valor))
            status_conn.commit(); status_conn.close()
            registrar_log("Meio de pagamento testado", f"{meio}: {status_teste}")
            flash(mensagem, categoria)
            return redirect(url_for("integracoes") + "#meios-pagamento")
        if request.form.get("acao") in {"salvar_plataforma", "alternar_plataforma"}:
            integracao_id = request.form.get("integracao_id", type=int)
            atual = conn.execute("SELECT * FROM integracoes WHERE id=? AND tipo<>'Transportadora' AND tipo<>'Pagamento'", (integracao_id,)).fetchone()
            if not atual: conn.close(); abort(404)
            if request.form.get("acao") == "alternar_plataforma":
                novo_status = "Inativa" if atual["status"] == "Ativa" else "Ativa"
                conn.execute("UPDATE integracoes SET status=? WHERE id=?", (novo_status, integracao_id)); detalhe=f"{atual['nome']}: {novo_status}"
            else:
                novo_segredo=request.form.get("segredo","").strip()
                segredo=encrypt_val(novo_segredo) if novo_segredo else atual["segredo"]
                conn.execute("UPDATE integracoes SET endpoint=?,usuario=?,segredo=?,observacoes=? WHERE id=?",
                    (request.form.get("endpoint","").strip(),request.form.get("usuario","").strip(),segredo,request.form.get("observacoes","").strip(),integracao_id));detalhe=f"Configuração de {atual['nome']} atualizada"
            conn.commit();conn.close();registrar_log("Integração alterada",detalhe);flash(detalhe+".","success");return redirect(url_for("integracoes"))
        if request.form.get("acao") in {"salvar_transportadora", "alternar_transportadora"}:
            integracao_id = request.form.get("integracao_id", type=int)
            atual = conn.execute("SELECT * FROM integracoes WHERE id=? AND tipo='Transportadora'", (integracao_id,)).fetchone()
            if not atual:
                conn.close(); abort(404)
            if request.form.get("acao") == "alternar_transportadora":
                novo_status = "Inativa" if atual["status"] == "Ativa" else "Ativa"
                conn.execute("UPDATE integracoes SET status=? WHERE id=?", (novo_status, integracao_id))
                detalhe = f"{atual['nome']}: {novo_status}"
            else:
                novo_segredo = request.form.get("segredo", "").strip()
                segredo = encrypt_val(novo_segredo) if novo_segredo else atual["segredo"]
                conn.execute("UPDATE integracoes SET endpoint=?,usuario=?,segredo=?,observacoes=? WHERE id=?",
                             (request.form.get("endpoint", "").strip(), request.form.get("usuario", "").strip(),
                              segredo, request.form.get("observacoes", "").strip(), integracao_id))
                detalhe = f"Credenciais/configuração de {atual['nome']} atualizadas"
            conn.commit(); conn.close(); registrar_log("Integração alterada", detalhe)
            flash(detalhe + ".", "success"); return redirect(url_for("integracoes"))
        if request.form.get("acao") == "salvar_pagamentos":
            ativos = {"pagseguro_ativo": "1" if request.form.get("pagseguro_ativo") else "0",
                      "mercadopago_ativo": "1" if request.form.get("mercadopago_ativo") else "0",
                      "picpay_ativo": "1" if request.form.get("picpay_ativo") else "0",
                      "stone_ativo": "1" if request.form.get("stone_ativo") else "0"}
            simples = ["pagseguro_email", "mercadopago_public_key", "picpay_client_id", "stone_client_id"]
            segredos = ["pagseguro_token", "mercadopago_access_token", "picpay_token", "stone_token"]
            for key, value in ativos.items():
                conn.execute("INSERT INTO configuracoes(chave,valor) VALUES(?,?) ON CONFLICT(chave) DO UPDATE SET valor=excluded.valor", (key, value))
            for key in simples:
                conn.execute("INSERT INTO configuracoes(chave,valor) VALUES(?,?) ON CONFLICT(chave) DO UPDATE SET valor=excluded.valor", (key, request.form.get(key, "").strip()))
            for key in segredos:
                valor = request.form.get(key, "").strip()
                if valor:
                    conn.execute("INSERT INTO configuracoes(chave,valor) VALUES(?,?) ON CONFLICT(chave) DO UPDATE SET valor=excluded.valor", (key, encrypt_val(valor)))
            conn.execute("UPDATE integracoes SET status=? WHERE nome='PagSeguro'", ("Ativa" if ativos["pagseguro_ativo"] == "1" else "Inativa",))
            conn.execute("UPDATE integracoes SET status=? WHERE nome='Mercado Pago'", ("Ativa" if ativos["mercadopago_ativo"] == "1" else "Inativa",))
            conn.execute("UPDATE integracoes SET status=? WHERE nome='PicPay'", ("Ativa" if ativos["picpay_ativo"] == "1" else "Inativa",))
            conn.execute("UPDATE integracoes SET status=? WHERE nome='Stone'", ("Ativa" if ativos["stone_ativo"] == "1" else "Inativa",))
            conn.commit(); conn.close(); flash("Meios de pagamento salvos.", "success")
            return redirect(url_for("integracoes"))
        if request.form.get("acao") in ("salvar_correios", "testar_correios", "testar_pac_sedex"):
            keys = ["correios_modo", "correios_usuario", "correios_cartao", "correios_contrato", "correios_dr",
                    "correios_codigo_pac", "correios_codigo_sedex", "correios_codigo_sedex10", "correios_codigo_sedex12"]
            for key in keys:
                conn.execute("INSERT INTO configuracoes(chave,valor) VALUES(?,?) ON CONFLICT(chave) DO UPDATE SET valor=excluded.valor",
                             (key, request.form.get(key, "").strip()))
            codigo_acesso = request.form.get("correios_codigo_acesso", "").strip()
            if codigo_acesso:
                conn.execute("INSERT INTO configuracoes(chave,valor) VALUES(?,?) ON CONFLICT(chave) DO UPDATE SET valor=excluded.valor",
                             ("correios_codigo_acesso", encrypt_val(codigo_acesso)))
            for chave in ("correios_atende_usuario", "correios_atende_senha", "correios_atende_mcu"):
                valor = request.form.get(chave, "").strip()
                if valor:
                    conn.execute("INSERT INTO configuracoes(chave,valor) VALUES(?,?) ON CONFLICT(chave) DO UPDATE SET valor=excluded.valor",
                                 (chave, encrypt_val(valor)))
            conn.commit(); conn.close()
            acao_correios = request.form.get("acao")
            if acao_correios == "testar_correios":
                try:
                    token = token_correios()
                    nivel = str(nivel_contrato_token(token))
                    conn_nivel = db(); conn_nivel.execute("""INSERT INTO configuracoes(chave,valor) VALUES('correios_nivel_contrato',?)
                        ON CONFLICT(chave) DO UPDATE SET valor=excluded.valor""", (nivel,)); conn_nivel.commit(); conn_nivel.close()
                    quantidade_adicionais = sincronizar_servicos_adicionais()
                    flash(f"Conexão realizada. Nível do contrato: {nivel}. {quantidade_adicionais} serviços adicionais sincronizados.", "success")
                except Exception as exc:
                    flash("Configuração salva, mas a autenticação falhou: " + str(exc), "danger")
            elif acao_correios == "testar_pac_sedex":
                origem = "".join(filter(str.isdigit, request.form.get("cep_teste_origem", "")))
                destino = "".join(filter(str.isdigit, request.form.get("cep_teste_destino", "")))
                if len(origem) != 8 or len(destino) != 8:
                    flash("Informe CEPs de teste com 8 números.", "danger")
                else:
                    for servico_teste in ("PAC", "SEDEX", "SEDEX 10", "SEDEX 12"):
                        try:
                            preco_teste = preco_correios_api(servico_teste, origem, destino, 300, 20, 15, 10)
                            prazo_teste = prazo_api(servico_teste, origem, destino)
                            flash(f"{servico_teste}: preço {brl(preco_teste)} e prazo {prazo_teste} — teste concluído.", "success")
                        except Exception as exc:
                            flash(f"{servico_teste} ({codigo_servico_correios(servico_teste)}): falha no teste de preço/prazo — {detalhe_erro_correios(exc)}", "danger")
            else:
                flash("Integração dos Correios salva.", "success")
            return redirect(url_for("integracoes"))
        conn.execute("INSERT INTO integracoes(nome,tipo,status,endpoint,usuario,segredo,observacoes) VALUES(?,?,?,?,?,?,?)",
                     (request.form["nome"].strip(), request.form.get("tipo", "Transportadora"), "Inativa",
                      request.form.get("endpoint", "").strip(), request.form.get("usuario", "").strip(),
                      encrypt_val(request.form.get("segredo", "").strip()), request.form.get("observacoes", "").strip()))
        conn.commit(); conn.close(); flash("Nova integração adicionada.", "success")
        return redirect(url_for("integracoes"))
    rows = [{**dict(r), "segredo": SEGREDO_CONFIGURADO if r["segredo"] else ""}
            for r in conn.execute("SELECT * FROM integracoes ORDER BY nome").fetchall()]; conn.close()
    return render_template("integracoes.html", rows=rows, dados=settings_publicas())


@app.route("/exportacao")
@perfis_permitidos("Master")
def exportacao():
    conn=db(); transportadoras=conn.execute("""SELECT nome FROM integracoes WHERE tipo='Transportadora'
        UNION SELECT DISTINCT COALESCE(NULLIF(transportadora,''),'Correios') FROM cotacoes ORDER BY nome""").fetchall(); recentes=conn.execute("SELECT * FROM exportacoes_envios ORDER BY id DESC LIMIT 30").fetchall();conn.close()
    return render_template("exportacao.html",transportadoras=transportadoras,recentes=recentes,
                           hoje=datetime.now().strftime("%Y-%m-%d"))


@app.route("/exportacao/<path:transportadora>")
@perfis_permitidos("Master")
def exportar_transportadora(transportadora):
    inicio=request.args.get("data_inicial") or datetime.now().strftime("%Y-%m-%d")
    fim=request.args.get("data_final") or inicio
    conn=db(); params=[transportadora,inicio,fim]; filtro_operador=""
    if session["usuario"]["perfil"] == "Operador de Balcão": filtro_operador=" AND operador_id=?";params.append(session["usuario"]["id"])
    rows=conn.execute("""SELECT id,criado_em,COALESCE(rastreio,etiqueta,'') codigo_objeto,
        COALESCE(NULLIF(transportadora,''),'Correios') transportadora,COALESCE(servico_transportadora,servico) servico,
        remetente_nome,remetente_documento,cep_origem,destinatario_nome,destinatario_documento,cep_destino,
        destinatario_rua,destinatario_numero,destinatario_complemento,destinatario_bairro,destinatario_cidade,destinatario_uf,
        peso,comprimento,largura,altura,valor_declarado,valor_cliente
        FROM cotacoes WHERE COALESCE(NULLIF(transportadora,''),'Correios')=? AND substr(criado_em,1,10) BETWEEN ? AND ?
        AND """+sem_testes()+filtro_operador+" ORDER BY id",params).fetchall()
    saida=io.StringIO(newline=""); campos=list(rows[0].keys()) if rows else ["id","criado_em","codigo_objeto","transportadora","servico"]
    gravador=csv.DictWriter(saida,fieldnames=campos,delimiter=";");gravador.writeheader()
    for row in rows: gravador.writerow(dict(row))
    conn.execute("INSERT INTO exportacoes_envios(criado_em,transportadora,data_inicial,data_final,usuario_nome,quantidade) VALUES(?,?,?,?,?,?)",
        (datetime.now().isoformat(timespec="seconds"),transportadora,inicio,fim,session["usuario"]["nome"],len(rows)));conn.commit();conn.close()
    registrar_log("Exportação de envios",f"{transportadora}; {inicio} a {fim}; {len(rows)} registro(s)")
    nome="".join(c if c.isalnum() else "_" for c in transportadora)
    return send_file(io.BytesIO(('\ufeff'+saida.getvalue()).encode('utf-8')),mimetype="text/csv; charset=utf-8",as_attachment=True,
                     download_name=f"envios_{nome}_{inicio}_{fim}.csv")


@app.route("/api/cotacoes-transportadoras", methods=["POST"])
@perfis_permitidos("Administrador", "Operador de Balcão")
def cotacoes_transportadoras():
    dados = request.get_json(silent=True) or {}
    try:
        origem = "".join(filter(str.isdigit, str(dados.get("cep_origem", ""))))
        destino = "".join(filter(str.isdigit, str(dados.get("cep_destino", ""))))
        peso = int(float(dados.get("peso") or 0))
        if len(origem) != 8 or len(destino) != 8 or peso <= 0:
            raise ValueError("Preencha CEP de origem, CEP de destino e peso antes de comparar.")
        dados.update({"cep_origem": origem, "cep_destino": destino, "peso": peso})
        opcoes, avisos = [], []
        conn = db(); integracoes_ativas = conn.execute(
            "SELECT * FROM integracoes WHERE tipo='Transportadora' AND status='Ativa' ORDER BY nome").fetchall(); conn.close()
        for integracao in integracoes_ativas:
            inicio_consulta, quantidade_antes, erro_sla = time.perf_counter(), len(opcoes), ""
            try:
                if integracao["nome"] == "Correios":
                    # API dos Correios: preço (tabela à prazo, do contrato) e prazo. O cliente vê o prazo que
                    # veio da API e o preço da tabela à vista; o preço à prazo segue oculto para o fechamento.
                    comp_f, larg_f, alt_f = (float(dados.get(c) or 0) for c in ("comprimento", "largura", "altura"))
                    embalagem = dados.get("tipo_embalagem", "Pacote")
                    limite = fora_do_limite_correios(peso, comp_f, larg_f, alt_f, embalagem)
                    if limite:
                        avisos.append(f"Correios: objeto fora do limite de postagem — {limite}. Confira peso e medidas.")
                    for servico in ([] if limite else SERVICOS):
                        peso_tarifado, _ = peso_tarifavel_gramas(peso, comp_f, larg_f, alt_f, embalagem, servico)
                        preco = tarifa_vista(servico, peso_tarifado, origem, destino)
                        if preco is not None:
                            preco += manuseio_especial(servico, comp_f, larg_f, alt_f, embalagem)
                        if preco is None:
                            if servico in ("PAC", "SEDEX"):
                                avisos.append(f"Correios {servico}: rota sem tarifa à vista — {motivo_sem_tarifa_vista(origem, destino)}")
                            continue
                        try:
                            prazo = prazo_entrega(servico, origem, destino)
                        except Exception as exc:
                            prazo = "Prazo não disponível"
                            avisos.append(f"Correios {servico}: preço à vista calculado; prazo indisponível na API e sem prazo salvo para a rota — {detalhe_erro_correios(exc)}")
                        contrato = None
                        try:
                            contrato = preco_correios_api(servico, origem, destino, peso, comp_f, larg_f, alt_f, embalagem)
                        except Exception as exc:
                            if recusa_da_api_correios(exc):
                                # A API recusou o objeto: o serviço não é oferecido, mesmo com preço na tabela à vista.
                                avisos.append(f"Correios {servico}: recusado pela API — {exc}")
                                continue
                            avisos.append(f"Correios {servico}: preço à prazo não veio da API — {detalhe_erro_correios(exc)}")
                        opcoes.append({"transportadora":"Correios", "servico":servico, "preco":round(float(preco),2),
                                       "prazo":prazo, "id":"", "preco_contrato": contrato})
                else:
                    opcoes.extend(cotar_integracao(integracao, dados))
            except Exception as exc:
                erro_sla = detalhe_erro_correios(exc)
                if integracao["nome"] != "Correios":
                    opcoes.extend(cotacao_estimada_nao_homologada(integracao, dados))
                    avisos.append(f"{integracao['nome']}: usando estimativa não homologada; API indisponível ou sem credencial")
                else:
                    avisos.append(f"{integracao['nome']}: {erro_sla}")
            finalmente_opcoes = len(opcoes) - quantidade_antes
            sla = db(); sla.execute("INSERT INTO sla_integracoes(integracao_id,criado_em,sucesso,tempo_ms,opcoes,erro) VALUES(?,?,?,?,?,?)",
                (integracao["id"], datetime.now().isoformat(timespec="seconds"), 0 if erro_sla else 1,
                 int((time.perf_counter()-inicio_consulta)*1000), finalmente_opcoes, erro_sla[:500]))
            sla.commit(); sla.close()
        opcoes.sort(key=lambda x: (0 if x["transportadora"] == "Correios" else 1, x["preco"], x["transportadora"], x["servico"]))
        return jsonify({"opcoes": opcoes, "avisos": avisos})
    except Exception as exc:
        return jsonify({"erro": str(exc), "opcoes": [], "avisos": []}), 400


@app.route("/integracoes/<int:integracao_id>/sla")
@perfis_permitidos("Master")
def sla_integracao(integracao_id):
    dias = max(1, min(365, request.args.get("dias", 30, type=int)))
    conn = db(); integracao = conn.execute("SELECT * FROM integracoes WHERE id=?", (integracao_id,)).fetchone()
    if not integracao: conn.close(); abort(404)
    resumo = conn.execute("""SELECT COUNT(*) consultas,SUM(sucesso) sucessos,
        ROUND(AVG(tempo_ms),0) tempo_medio,MAX(tempo_ms) tempo_maximo,SUM(opcoes) opcoes,
        MAX(criado_em) ultima_consulta FROM sla_integracoes
        WHERE integracao_id=? AND criado_em>=datetime('now',?)""", (integracao_id, f"-{dias} days")).fetchone()
    falhas = conn.execute("""SELECT criado_em,tempo_ms,erro FROM sla_integracoes WHERE integracao_id=?
        AND sucesso=0 AND criado_em>=datetime('now',?) ORDER BY id DESC LIMIT 50""",
        (integracao_id, f"-{dias} days")).fetchall(); conn.close()
    consultas, sucessos = int(resumo["consultas"] or 0), int(resumo["sucessos"] or 0)
    disponibilidade = round(sucessos / consultas * 100, 2) if consultas else None
    return render_template("sla_integracao.html", integracao=integracao, resumo=resumo, falhas=falhas,
                           disponibilidade=disponibilidade, dias=dias)


def interpretar_data_reversa(valor):
    """Converte as datas mais comuns do portal sem alterar o dia informado."""
    if valor is None:
        return None
    texto = str(valor).strip()
    if not texto:
        return None
    texto_data = texto[:10]
    for formato in ("%d/%m/%Y", "%Y-%m-%d", "%d-%m-%Y"):
        try:
            return datetime.strptime(texto_data, formato).date()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(texto.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def credenciais_correios_atende():
    """Usuário, senha e MCU do Correios Atende para Reversa e Recepção.
    Por enquanto as variáveis do Render têm prioridade; sem elas, vale o que está (criptografado) em Integrações."""
    dados = settings()
    return tuple((os.getenv(variavel) or "").strip() or dados.get(chave)
                 for variavel, chave in (("CORREIOS_ATENDE_USUARIO", "correios_atende_usuario"),
                                         ("CORREIOS_ATENDE_SENHA", "correios_atende_senha"),
                                         ("CORREIOS_ATENDE_MCU", "correios_atende_mcu")))


def limite_loja_reversa(valor):
    """Prazo da reversa mostrado ao usuário: 1 dia antes da validade dos Correios (o valor guardado não muda)."""
    data = interpretar_data_reversa(valor)
    return (data - timedelta(days=1)).strftime("%d/%m/%Y") if data else None


def consultar_reversa_correios(codigo, usuario, senha, mcu):
    """Consulta somente a elegibilidade; não inicia atendimento nem grava postagem."""
    base = "https://correiosatende.correios.com.br"
    destino = f"{base}/app/atendimento/logistica-new/"
    entrada = (f"{base}/core/seguranca/entrar.php?" + urllib.parse.urlencode({
        "url_solicitante": destino,
        "mcugeo": mcu,
    }))
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
    cabecalhos = {"User-Agent": "Mozilla/5.0 Flash-House-Info/1.0"}

    with opener.open(urllib.request.Request(entrada, headers=cabecalhos), timeout=25) as resposta:
        pagina_login = resposta.read().decode("utf-8", "replace")
        url_login = resposta.geturl()
    achou = re.search(r'name=["\']execution["\'][^>]*value=["\']([^"\']+)', pagina_login, re.I)
    if not achou:
        raise RuntimeError("O portal não apresentou a autenticação esperada.")
    dados_login = urllib.parse.urlencode({
        "username": usuario,
        "password": senha,
        "execution": html.unescape(achou.group(1)),
        "_eventId": "submit",
        "geolocation": "",
        "submitBtn": "",
    }).encode()
    requisicao_login = urllib.request.Request(
        urllib.parse.urljoin(url_login, "login"), data=dados_login,
        headers={**cabecalhos, "Content-Type": "application/x-www-form-urlencoded"},
    )
    with opener.open(requisicao_login, timeout=25) as resposta:
        pagina_autenticada = resposta.read().decode("utf-8", "replace")
        url_autenticada = resposta.geturl()
    if "erro.php" in url_autenticada or "não recebeu delegação" in pagina_autenticada.lower():
        raise RuntimeError(f"A credencial do Correios Atende não possui delegação para o MCU {mcu}.")
    if "auth.correios.com.br/login" in url_autenticada or 'id="fm1"' in pagina_autenticada:
        raise RuntimeError("Credencial de consulta recusada pelos Correios.")

    codigo_limpo = re.sub(r"\s+", "", codigo).upper()
    eh_objeto = bool(re.fullmatch(r"[A-Z]{2}\d{9}[A-Z]{2}", codigo_limpo))
    if eh_objeto:
        endpoint = f"{base}/app/prepostagem/prepostagem-rest.php"
        parametros = {"codigoObjeto": codigo_limpo}
    else:
        endpoint = f"{base}/app/prepostagem/prepostagem-logistica-reversa-rest.php"
        parametros = {"eTicket": codigo_limpo}
    corpo = json.dumps({"parametros": parametros, "verbo": "GET"}).encode("utf-8")
    requisicao = urllib.request.Request(endpoint, data=corpo, headers={
        **cabecalhos, "Content-Type": "application/json", "Accept": "application/json",
        "Referer": destino,
    })
    try:
        with opener.open(requisicao, timeout=25) as resposta:
            retorno = json.loads(resposta.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as erro:
        if 400 <= erro.code < 500:
            return {"valida": False, "validade_correios": None, "limite_operacional": None, "dados_ppn": None}
        raise
    if not isinstance(retorno, dict) or retorno.get("erro"):
        return {"valida": False, "validade_correios": None, "limite_operacional": None, "dados_ppn": None}
    itens = retorno.get("itens") or []
    if eh_objeto and not itens and retorno.get("statusAtual") is not None:
        itens = [retorno]
    data_validade = interpretar_data_reversa(localizar_campo_ppn(retorno, (
        "prazoPostagem", "prazoMaximoPostagem", "dataValidade", "validade",
        "dataLimitePostagem", "dataMaximaPostagem", "dataMaxima",
    )))
    data_limite = data_validade - timedelta(days=1) if data_validade else None
    valida = bool(itens) and all(
        str(item.get("statusAtual")) == "2" for item in itens if isinstance(item, dict)
    )
    if data_limite and datetime.now().date() > data_limite:
        valida = False
    return {
        "valida": valida,
        "validade_correios": data_validade.strftime("%d/%m/%Y") if data_validade else None,
        "limite_operacional": data_limite.strftime("%d/%m/%Y") if data_limite else None,
        "dados_ppn": retorno,
    }


def dados_recepcao_ppn(retorno, codigo_consultado):
    """Extrai somente os dados cadastrais devolvidos pela PPN para conferência e recibo."""
    if not isinstance(retorno, dict):
        return None
    itens = retorno.get("itens") or retorno.get("prePostagens") or []
    if isinstance(itens, dict):
        itens = [itens]
    item = itens[0] if itens and isinstance(itens[0], dict) else retorno
    if not isinstance(item, dict):
        return None
    remetente = item.get("remetente") if isinstance(item.get("remetente"), dict) else {}
    destinatario = item.get("destinatario") if isinstance(item.get("destinatario"), dict) else {}
    end_rem = remetente.get("endereco") if isinstance(remetente.get("endereco"), dict) else {}
    end_dest = destinatario.get("endereco") if isinstance(destinatario.get("endereco"), dict) else {}
    codigo = str(item.get("codigoObjeto") or item.get("objeto") or codigo_consultado or "").strip().upper()
    if not codigo or not (remetente.get("nome") or destinatario.get("nome")):
        return None
    adicionais = item.get("listaServicoAdicional") if isinstance(item.get("listaServicoAdicional"), list) else []
    itens_conteudo = item.get("itensDeclaracaoConteudo") if isinstance(item.get("itensDeclaracaoConteudo"), list) else []
    dados = {
        "codigo_etiqueta": codigo,
        "rastreio": codigo,
        "ppn_id": item.get("idPrePostagem") or item.get("eticket") or item.get("id") or "",
        "servico": item.get("descricaoServico") or item.get("servico") or item.get("codigoServico") or "Correios",
        "codigo_servico": item.get("codigoServico") or item.get("posCoServicoOriginal") or "",
        "status_ppn": item.get("descStatusAtual") or item.get("statusAtual") or "Não informado",
        "status_codigo": str(item.get("statusAtual") or ""),
        "data_ppn": item.get("dataEticket") or item.get("dataHora") or item.get("dataHoraStatusAtual") or "",
        "prazo_postagem": item.get("prazoPostagem") or item.get("prazoMaximoPostagem") or "",
        "cartao_postagem": item.get("cartaoPostagem") or item.get("numeroCartaoPostagem") or "",
        "peso": item.get("peso") or item.get("pesoInformado") or 0,
        "comprimento": item.get("comprimentoInformado") or item.get("comprimento") or 0,
        "largura": item.get("larguraInformada") or item.get("largura") or 0,
        "altura": item.get("alturaInformada") or item.get("altura") or 0,
        "tipo_documento": item.get("tipoDocumento") or ("NF-e" if item.get("notaFiscal") else "Declaração de conteúdo"),
        "documento_fiscal": item.get("notaFiscal") or item.get("chaveNfe") or item.get("chaveDce") or "",
        "adicionais": adicionais,
        "itens_conteudo": itens_conteudo,
        "remetente_nome": remetente.get("nome") or "",
        "remetente_documento": remetente.get("documento") or remetente.get("cpfCnpj") or "",
        "cep_origem": end_rem.get("cep") or "",
        "remetente_rua": end_rem.get("logradouro") or "",
        "remetente_numero": end_rem.get("numero") or "S/N",
        "remetente_complemento": end_rem.get("complemento") or "",
        "remetente_bairro": end_rem.get("bairro") or "",
        "remetente_cidade": end_rem.get("cidade") or "",
        "remetente_uf": end_rem.get("uf") or "",
        "destinatario_nome": destinatario.get("nome") or "",
        "destinatario_documento": destinatario.get("documento") or destinatario.get("cpfCnpj") or "",
        "cep_destino": end_dest.get("cep") or "",
        "destinatario_rua": end_dest.get("logradouro") or "",
        "destinatario_numero": end_dest.get("numero") or "S/N",
        "destinatario_complemento": end_dest.get("complemento") or "",
        "destinatario_bairro": end_dest.get("bairro") or "",
        "destinatario_cidade": end_dest.get("cidade") or "",
        "destinatario_uf": end_dest.get("uf") or "",
    }
    obrigatorios = {
        "código do objeto": dados["codigo_etiqueta"], "serviço": dados["servico"],
        "nome do remetente": dados["remetente_nome"], "CPF/CNPJ do remetente": dados["remetente_documento"],
        "CEP do remetente": dados["cep_origem"], "logradouro do remetente": dados["remetente_rua"],
        "nome do destinatário": dados["destinatario_nome"], "CPF/CNPJ do destinatário": dados["destinatario_documento"],
        "CEP do destinatário": dados["cep_destino"], "logradouro do destinatário": dados["destinatario_rua"],
    }
    dados["pendencias"] = [rotulo for rotulo, valor in obrigatorios.items() if not str(valor or "").strip()]
    dados["validado"] = not dados["pendencias"]
    return dados


def consultar_objeto_afaturar(codigo, cep, usuario, senha, mcu):
    """Consulta somente os dados da PPN usados pela tela A Faturar; nunca cria ou altera atendimento."""
    codigo_limpo = re.sub(r"\s+", "", str(codigo or "")).upper()
    cep_limpo = re.sub(r"\D", "", str(cep or ""))
    if not re.fullmatch(r"[A-Z]{2}\d{9}[A-Z]{2}", codigo_limpo):
        return None
    if not re.fullmatch(r"\d{8}", cep_limpo):
        return None
    base = "https://correiosatende.correios.com.br"
    destino = f"{base}/app/atendimento/afaturar/"
    entrada = f"{base}/core/seguranca/entrar.php?" + urllib.parse.urlencode({
        "url_solicitante": destino, "mcugeo": mcu,
    })
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
    cabecalhos = {"User-Agent": "Mozilla/5.0 Flash-House-Info/1.0"}
    with opener.open(urllib.request.Request(entrada, headers=cabecalhos), timeout=25) as resposta:
        pagina_login = resposta.read().decode("utf-8", "replace")
        url_login = resposta.geturl()
    achou = re.search(r'name=["\']execution["\'][^>]*value=["\']([^"\']+)', pagina_login, re.I)
    if not achou:
        raise RuntimeError("O Correios Atende não apresentou a autenticação esperada.")
    dados_login = urllib.parse.urlencode({
        "username": usuario, "password": senha, "execution": html.unescape(achou.group(1)),
        "_eventId": "submit", "geolocation": "", "submitBtn": "",
    }).encode()
    requisicao_login = urllib.request.Request(
        urllib.parse.urljoin(url_login, "login"), data=dados_login,
        headers={**cabecalhos, "Content-Type": "application/x-www-form-urlencoded"},
    )
    with opener.open(requisicao_login, timeout=25) as resposta:
        pagina_autenticada = resposta.read().decode("utf-8", "replace")
        url_autenticada = resposta.geturl()
    if "erro.php" in url_autenticada or "não recebeu delegação" in pagina_autenticada.lower():
        raise RuntimeError(f"A credencial do Correios Atende não possui delegação para o MCU {mcu}.")
    if "auth.correios.com.br/login" in url_autenticada or 'id="fm1"' in pagina_autenticada:
        raise RuntimeError("Credencial de consulta recusada pelos Correios.")
    endpoint = f"{base}/app/prepostagem/prepostagem-rest.php"
    corpo = json.dumps({
        "parametros": {"codigoObjeto": codigo_limpo, "cep": cep_limpo},
        "verbo": "GET",
    }).encode("utf-8")
    requisicao = urllib.request.Request(endpoint, data=corpo, headers={
        **cabecalhos, "Content-Type": "application/json", "Accept": "application/json", "Referer": destino,
    })
    try:
        with opener.open(requisicao, timeout=25) as resposta:
            retorno = json.loads(resposta.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as erro:
        if 400 <= erro.code < 500:
            return None
        raise
    if not isinstance(retorno, dict) or retorno.get("erro"):
        return None
    return retorno


def objetos_reversa_ppn(retorno):
    """Objetos da autorização que já têm código atribuído pelos Correios (nunca usa o e-ticket como código)."""
    if not isinstance(retorno, dict):
        return []
    itens = retorno.get("itens") or retorno.get("prePostagens") or []
    if isinstance(itens, dict):
        itens = [itens]
    objetos = []
    for item in itens:
        if not isinstance(item, dict):
            continue
        dados_item = dados_recepcao_ppn({"itens": [item]}, "")
        if dados_item and re.fullmatch(r"[A-Z]{2}\d{9}[A-Z]{2}", dados_item["codigo_etiqueta"] or ""):
            objetos.append(dados_item)
    return objetos


def objetos_conferencia_reversa(retorno):
    """Peso e medidas declarados em cada objeto da autorização (com ou sem código atribuído)."""
    if not isinstance(retorno, dict):
        return []
    itens = retorno.get("itens") or retorno.get("prePostagens") or [retorno]
    if isinstance(itens, dict):
        itens = [itens]
    objetos = []
    for i, item in enumerate(x for x in itens if isinstance(x, dict)):
        codigo = str(item.get("codigoObjeto") or item.get("objeto") or "").strip().upper()
        objetos.append({
            "chave": str(i), "rotulo": codigo or f"Objeto {i + 1}",
            "peso": item.get("peso") or item.get("pesoInformado") or 0,
            "comprimento": item.get("comprimentoInformado") or item.get("comprimento") or 0,
            "largura": item.get("larguraInformada") or item.get("largura") or 0,
            "altura": item.get("alturaInformada") or item.get("altura") or 0,
        })
    return objetos


def salvar_medidas_criacao(origem, codigo, objetos):
    """Guarda (ou atualiza) as medidas que vieram na criação da PPN/autorização, para comparação futura."""
    garantir_tabelas_medidas()
    agora = datetime.now().isoformat(timespec="seconds")
    conn = db()
    for o in objetos:
        try:
            peso = float(o.get("peso") or 0)
            dims = [float(o.get(c) or 0) for c in ("comprimento", "largura", "altura")]
        except (TypeError, ValueError):
            continue
        tarifado = peso_tarifavel_gramas(peso, *dims)[0] if peso > 0 else None
        conn.execute("""INSERT INTO medidas_criacao(origem,codigo,objeto,peso_g,comprimento,largura,altura,
                peso_tarifado_g,primeira_consulta_em,ultima_consulta_em) VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(origem,codigo,objeto) DO UPDATE SET peso_g=excluded.peso_g,comprimento=excluded.comprimento,
                largura=excluded.largura,altura=excluded.altura,peso_tarifado_g=excluded.peso_tarifado_g,
                ultima_consulta_em=excluded.ultima_consulta_em""",
            (origem, codigo, o["rotulo"], peso, *dims, tarifado, agora, agora))
    conn.commit(); conn.close()


def salvar_conferencia_medidas(origem, codigo, objeto, conferencia, medidas_reais):
    garantir_tabelas_medidas()
    criado = conferencia.get("declarado") or {}
    real = conferencia.get("real") or {}
    usuario = session.get("usuario") or {}
    conn = db()
    conn.execute("""INSERT INTO conferencias_medidas(criado_em,origem,codigo,objeto,criado_peso_g,criado_comprimento,
            criado_largura,criado_altura,criado_tarifado_g,real_peso_g,real_comprimento,real_largura,real_altura,
            real_tarifado_g,sem_divergencia,problemas,usuario_id,usuario_nome) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (datetime.now().isoformat(timespec="seconds"), origem, codigo, objeto.get("rotulo"),
         objeto.get("peso") or None, objeto.get("comprimento") or None, objeto.get("largura") or None,
         objeto.get("altura") or None, criado.get("tarifavel"), real.get("peso"), *medidas_reais,
         real.get("tarifavel"), 1 if conferencia.get("ok") else 0, "; ".join(conferencia.get("problemas") or []),
         usuario.get("id"), usuario.get("nome")))
    conn.commit(); conn.close()


def medidas_conferidas(origem, codigo, objeto):
    """Últimas medidas reais conferidas no balcão para o objeto (None se não houve conferência).
    As medidas da criação continuam guardadas em medidas_criacao; o recibo usa estas."""
    garantir_tabelas_medidas()
    conn = db()
    row = conn.execute("""SELECT real_peso_g,real_comprimento,real_largura,real_altura FROM conferencias_medidas
        WHERE origem=? AND codigo=? AND objeto=? AND real_peso_g>0 AND """ + sem_testes() + " ORDER BY id DESC LIMIT 1",
        (origem, codigo, objeto)).fetchone()
    conn.close()
    if not row:
        return None
    return {"peso": row["real_peso_g"], "comprimento": row["real_comprimento"],
            "largura": row["real_largura"], "altura": row["real_altura"]}


def conferir_e_salvar(origem, codigo, objeto):
    """Lê as medidas reais do formulário, compara com a criação e grava a conferência. Nunca posta."""
    reais = (numero_form("comprimento"), numero_form("largura"), numero_form("altura"))
    conferencia = conferir_medidas_reversa(objeto, numero_form("peso"), *reais)
    conferencia["objeto"] = objeto["rotulo"]
    salvar_conferencia_medidas(origem, codigo, objeto, conferencia, reais)
    registrar_log(f"Conferência de medidas ({origem})",
                  f"Código {codigo}; {objeto['rotulo']}; "
                  f"{'sem divergência' if conferencia['ok'] else '; '.join(conferencia['problemas'])}"[:500])
    return conferencia


def numero_form(nome):
    try:
        return float(str(request.form.get(nome, "")).replace(",", "."))
    except ValueError:
        return 0.0


def conferir_medidas_reversa(objeto, peso_kg, comprimento, largura, altura):
    """Somente conferência: compara as medidas reais com as da autorização e com os limites dos Correios.
    Nenhuma postagem, cotação ou expedição é criada."""
    problemas = []
    lados = sorted([comprimento, largura, altura], reverse=True)
    peso_g = int(math.ceil(peso_kg * 1000))
    if peso_g <= 0 or min(lados) <= 0:
        return {"ok": False, "problemas": ["Informe peso e as três dimensões."], "real": None, "declarado": None}
    if peso_g > 30000:
        problemas.append("Peso real acima de 30 kg.")
    if lados[0] > 100:
        problemas.append("Um dos lados passa de 100 cm.")
    if sum(lados) > 200:
        problemas.append("A soma das dimensões passa de 200 cm.")
    if lados[0] < 16 or lados[1] < 11 or lados[2] < 2:
        problemas.append("Medidas abaixo do mínimo de 16 x 11 x 2 cm.")
    real, cubico_real = peso_tarifavel_gramas(peso_g, comprimento, largura, altura)
    resultado = {"real": {"peso": peso_g, "cubico": cubico_real, "tarifavel": real,
                          "dimensoes": f"{comprimento:g} x {largura:g} x {altura:g} cm"}, "declarado": None}
    try:
        peso_decl = float(objeto.get("peso") or 0)
        dims_decl = [float(objeto.get(c) or 0) for c in ("comprimento", "largura", "altura")]
    except (TypeError, ValueError):
        peso_decl, dims_decl = 0, [0, 0, 0]
    if peso_decl > 0:
        declarado, cubico_decl = peso_tarifavel_gramas(peso_decl, *dims_decl)
        resultado["declarado"] = {"peso": int(peso_decl), "cubico": cubico_decl, "tarifavel": declarado,
                                  "dimensoes": " x ".join(f"{d:g}" for d in dims_decl) + " cm" if all(dims_decl) else "não informadas"}
        if real > declarado:
            problemas.append(f"Peso tarifado real ({real} g) maior que o da autorização ({declarado} g): "
                             "a postagem tende a dar erro de negócio por diferença de tarifação.")
    else:
        problemas.append("A autorização não informa peso e medidas; não foi possível comparar a tarifação.")
    resultado["problemas"] = problemas
    resultado["ok"] = not problemas
    return resultado


def etiqueta_reversa_10x15(objetos, autorizacao):
    """Etiquetas 100 x 150 mm (uma por objeto) com os dados da PPN; não cria nem registra postagem."""
    from reportlab.graphics.barcode import code128
    from reportlab.lib.pagesizes import mm
    from reportlab.pdfgen import canvas
    largura, altura = 100 * mm, 150 * mm
    saida = io.BytesIO(); pdf = canvas.Canvas(saida, pagesize=(largura, altura))
    for objeto in objetos:
        rastreio = str(objeto["codigo_etiqueta"] or "").replace(" ", "").upper()
        pdf.setLineWidth(.65); pdf.rect(2 * mm, 2 * mm, 96 * mm, 146 * mm)
        pdf.setFont("Helvetica-Bold", 10); pdf.drawString(5 * mm, 143 * mm, "CORREIOS")
        pdf.drawRightString(95 * mm, 143 * mm, str(objeto["servico"] or "")[:30])
        pdf.setFont("Helvetica-Bold", 7.5); pdf.drawString(5 * mm, 138.5 * mm, "LOGÍSTICA REVERSA")
        pdf.setFont("Helvetica", 7); pdf.drawRightString(95 * mm, 138.5 * mm, f"Autorização: {autorizacao}"[:48])
        barra = code128.Code128("\xf1" + rastreio, barHeight=15 * mm, barWidth=.32 * mm, humanReadable=False)
        if barra.width > 80 * mm: barra.barWidth *= (80 * mm / barra.width)
        barra.drawOn(pdf, 10 * mm, 119 * mm)
        pdf.setFont("Helvetica-Bold", 9); pdf.drawCentredString(largura / 2, 114.5 * mm, rastreio)
        pdf.line(2 * mm, 111 * mm, 98 * mm, 111 * mm)
        y = 106 * mm; pdf.setFont("Helvetica-Bold", 7); pdf.drawString(5 * mm, y, "DESTINATÁRIO:"); y -= 4.5 * mm
        pdf.setFont("Helvetica-Bold", 9); pdf.drawString(5 * mm, y, str(objeto["destinatario_nome"] or "")[:48]); y -= 4.5 * mm
        endereco_dest = f"{objeto['destinatario_rua']}, {objeto['destinatario_numero']} {objeto['destinatario_complemento']}".strip()
        pdf.setFont("Helvetica", 7.5); pdf.drawString(5 * mm, y, endereco_dest[:64]); y -= 4 * mm
        pdf.drawString(5 * mm, y, f"{objeto['destinatario_bairro']} - {objeto['destinatario_cidade']}/{objeto['destinatario_uf']}"[:64]); y -= 5 * mm
        pdf.setFont("Helvetica-Bold", 10); pdf.drawString(5 * mm, y, f"CEP: {cep_formatado(objeto['cep_destino'])}")
        pdf.line(2 * mm, 76 * mm, 98 * mm, 76 * mm)
        y = 71 * mm; pdf.setFont("Helvetica-Bold", 7); pdf.drawString(5 * mm, y, "REMETENTE:"); y -= 4 * mm
        pdf.setFont("Helvetica", 7); pdf.drawString(5 * mm, y, str(objeto["remetente_nome"] or "")[:64]); y -= 4 * mm
        endereco_rem = f"{objeto['remetente_rua']}, {objeto['remetente_numero']} {objeto['remetente_complemento']}".strip()
        pdf.drawString(5 * mm, y, endereco_rem[:68]); y -= 4 * mm
        pdf.drawString(5 * mm, y, f"{objeto['remetente_bairro']} - {objeto['remetente_cidade']}/{objeto['remetente_uf']}"
                       f"  CEP: {cep_formatado(objeto['cep_origem'])}"[:72])
        pdf.line(2 * mm, 55 * mm, 98 * mm, 55 * mm)
        pdf.setFont("Helvetica-Bold", 7)
        pdf.drawString(5 * mm, 50 * mm, "DOCUMENTO: " + str(objeto["documento_fiscal"] or objeto["tipo_documento"] or "")[:56])
        y = 45.5 * mm
        for indice, item in enumerate((objeto.get("itens_conteudo") or [])[:5], 1):
            if not isinstance(item, dict):
                continue
            descricao = item.get("conteudo") or item.get("descricao") or ""
            pdf.setFont("Helvetica", 6.2)
            pdf.drawString(5 * mm, y, f"{indice}. {str(descricao)[:44]} (Qtd: {item.get('quantidade') or 1})"); y -= 3.8 * mm
        try:
            peso = float(objeto["peso"] or 0)
        except (TypeError, ValueError):
            peso = 0
        pdf.setFont("Helvetica-Bold", 7)
        pdf.drawString(5 * mm, 16 * mm, f"Peso informado: {peso / 1000:.3f} kg" if peso else "Peso informado: -")
        postar_ate = limite_loja_reversa(objeto["prazo_postagem"])
        if postar_ate:
            pdf.drawRightString(95 * mm, 16 * mm, f"Postar até: {postar_ate}"[:40])
        pdf.setFont("Helvetica", 5.5)
        pdf.drawString(5 * mm, 5 * mm, f"Emitida em {datetime.now().strftime('%d/%m/%Y %H:%M')}")
        pdf.showPage()
    pdf.save(); return saida.getvalue()


@app.route("/logistica-reversa", methods=["GET", "POST"])
@perfis_permitidos("Master", "Administrador", "Operador de Balcão")
def logistica_reversa():
    usuario_backend, senha_backend, mcu_backend = credenciais_correios_atende()
    configurada = bool(usuario_backend and senha_backend and mcu_backend)
    codigo = request.form.get("codigo", "").strip() if request.method == "POST" else ""
    gerar_etiqueta = request.method == "POST" and request.form.get("acao") == "gerar_etiqueta"
    conferir = request.method == "POST" and request.form.get("acao") == "conferir_medidas"
    resultado = None
    limite_operacional = validade_correios = conferencia = None
    objetos_conf = []
    medidas = {c: request.form.get(c, "") for c in ("peso", "comprimento", "largura", "altura", "objeto")}
    if request.method == "POST":
        if not configurada:
            resultado = "erro_regras"
        else:
            try:
                consulta = consultar_reversa_correios(
                    codigo, usuario_backend, senha_backend, mcu_backend
                )
                resultado = "valida" if consulta["valida"] and consulta["limite_operacional"] else "erro_regras"
                limite_operacional = consulta["limite_operacional"]
                validade_correios = consulta["validade_correios"]
                if resultado == "valida":
                    objetos_conf = objetos_conferencia_reversa(consulta["dados_ppn"])
                    salvar_medidas_criacao("Reversa", codigo.upper(), objetos_conf)
                if conferir and objetos_conf:
                    # Somente conferência das medidas: nada é postado.
                    escolhido = next((o for o in objetos_conf if o["chave"] == medidas["objeto"]), objetos_conf[0])
                    conferencia = conferir_e_salvar("Reversa", codigo.upper(), escolhido)
                if request.form.get("acao") == "gerar_recibo" and resultado == "valida":
                    # Somente o comprovante com os dados da autorização: nada é postado nem gravado além do log.
                    retorno = consulta["dados_ppn"] if isinstance(consulta["dados_ppn"], dict) else {}
                    itens = retorno.get("itens") or retorno.get("prePostagens") or [retorno]
                    objetos = []
                    rotulos = {i: o["rotulo"] for i, o in enumerate(objetos_conferencia_reversa(retorno))}
                    for indice, item in enumerate(x for x in (itens if isinstance(itens, list) else [itens]) if isinstance(x, dict)):
                        dados_item = dados_recepcao_ppn({"itens": [item]}, codigo.upper())
                        if dados_item:
                            # Recibo com as medidas conferidas no balcão; as da criação ficam em medidas_criacao.
                            reais = medidas_conferidas("Reversa", codigo.upper(), rotulos.get(indice, ""))
                            dados_item.update(reais or {}, medidas_conferidas=bool(reais))
                            codigo_item = dados_item["codigo_etiqueta"]
                            dados_item.update({
                                "codigo": codigo_item if re.fullmatch(r"[A-Z]{2}\d{9}[A-Z]{2}", codigo_item) else "",
                                "documento": dados_item["documento_fiscal"] or dados_item["tipo_documento"],
                                "adicionais": nomes_adicionais_ppn(dados_item["adicionais"])})
                            objetos.append(dados_item)
                    if objetos:
                        registrar_log("Recibo de logística reversa", f"Código {codigo}; {len(objetos)} objeto(s); sem postagem")
                        return render_template("recibo_atendimento.html", r={
                            "titulo": "COMPROVANTE DE LOGÍSTICA REVERSA", "numero": "",
                            "data_hora": datetime.now().isoformat(timespec="seconds"),
                            "operador": session["usuario"]["nome"], "autorizacao": codigo.upper(),
                            "data_limite": limite_operacional, "cliente_nome": objetos[0]["remetente_nome"],
                            "cliente_documento": objetos[0]["remetente_documento"], "objetos": objetos,
                            "observacoes": "", "valor": None, "voltar": url_for("logistica_reversa"),
                            "declaracao": "Comprovante de atendimento da logística reversa com os dados da autorização dos Correios."})
                    resultado = "erro_regras"
                if gerar_etiqueta:
                    # Somente a etiqueta: nenhum registro de postagem, cotação ou expedição é criado.
                    objetos = objetos_reversa_ppn(consulta["dados_ppn"]) if resultado == "valida" else []
                    if objetos:
                        registrar_log("Etiqueta de logística reversa gerada",
                                      f"Código {codigo}; {len(objetos)} etiqueta(s); sem postagem")
                        return send_file(io.BytesIO(etiqueta_reversa_10x15(objetos, codigo)),
                                         mimetype="application/pdf", as_attachment=False,
                                         download_name=f"reversa_{re.sub(r'[^A-Za-z0-9]', '', codigo)}.pdf")
                    resultado = "erro_regras"
                registrar_log(
                    "Consulta de logística reversa",
                    f"Código {codigo}; resultado {resultado}; limite operacional {limite_operacional or 'não informado'}",
                )
            except Exception as exc:
                resultado = "erro_regras"
                registrar_log("Falha na consulta de logística reversa", str(exc)[:500])
    return render_template(
        "logistica_reversa.html", configurada=configurada, codigo=codigo, resultado=resultado,
        limite_operacional=limite_operacional, validade_correios=validade_correios,
        objetos_conf=objetos_conf, conferencia=conferencia, medidas=medidas,
    )


@app.route("/recepcao-objetos", methods=["GET", "POST"])
@perfis_permitidos("Master", "Administrador", "Operador de Balcão")
def recepcao_objetos():
    codigo = (request.values.get("codigo", "").strip().upper().replace(" ", ""))
    cep_consulta = re.sub(r"\D", "", request.values.get("cep", ""))[:8]
    usuario_backend, senha_backend, mcu_backend = credenciais_correios_atende()
    configurada = bool(usuario_backend and senha_backend and mcu_backend)
    conn = db(); objeto = recepcao = conferencia = None; erro_consulta = None
    medidas = {c: request.form.get(c, "") for c in ("peso", "comprimento", "largura", "altura")}
    if codigo or cep_consulta:
        if not configurada:
            erro_consulta = "Não foi possível consultar os dados da PPN agora. Nenhuma operação foi realizada."
        elif not re.fullmatch(r"[A-Z]{2}\d{9}[A-Z]{2}", codigo):
            erro_consulta = "Leia o código de barras do objeto no padrão dos Correios."
        elif not re.fullmatch(r"\d{8}", cep_consulta):
            erro_consulta = "Informe o CEP do destinatário com 8 números."
        else:
            try:
                retorno_afaturar = consultar_objeto_afaturar(
                    codigo, cep_consulta, usuario_backend, senha_backend, mcu_backend
                )
                objeto = dados_recepcao_ppn(retorno_afaturar, codigo)
                if not objeto:
                    erro_consulta = "Objeto não localizado nos dados cadastrados na PPN."
                elif re.sub(r"\D", "", str(objeto.get("cep_destino") or "")) != cep_consulta:
                    objeto = None
                    erro_consulta = "A etiqueta não corresponde ao CEP do destinatário informado."
                else:
                    recepcao = conn.execute(
                        f"SELECT * FROM recepcoes_objetos WHERE UPPER(codigo_objeto)=? AND {sem_testes()} ORDER BY id DESC LIMIT 1",
                        (objeto["codigo_etiqueta"],),
                    ).fetchone()
                    objeto_medidas = {"rotulo": objeto["codigo_etiqueta"], "peso": objeto["peso"],
                                      "comprimento": objeto["comprimento"], "largura": objeto["largura"],
                                      "altura": objeto["altura"]}
                    salvar_medidas_criacao("Recepção", objeto["codigo_etiqueta"], [objeto_medidas])
                    if request.method == "POST" and request.form.get("acao") == "conferir_medidas":
                        # Somente conferência das medidas: nada é recebido nem postado.
                        conferencia = conferir_e_salvar("Recepção", objeto["codigo_etiqueta"], objeto_medidas)
                registrar_log(
                    "Consulta de objeto para recepção",
                    f"Objeto {codigo}; CEP conferido; consulta somente leitura em A Faturar; "
                    f"{'localizado na PPN' if objeto else 'não localizado'}",
                )
            except Exception as exc:
                mensagem_erro = str(exc)
                erro_consulta = (mensagem_erro if "delegação" in mensagem_erro.lower() else
                                 "Não foi possível consultar os dados da PPN agora. Nenhuma operação foi realizada. "
                                 f"Motivo: {type(exc).__name__}: {mensagem_erro[:200]}")
                registrar_log("Falha na consulta PPN para recepção",
                              f"{type(exc).__name__}: {mensagem_erro}"[:500])
    if request.method == "POST" and request.form.get("acao") == "receber":
        if not objeto:
            conn.close(); flash(erro_consulta or "Objeto não localizado nos dados cadastrados na PPN.", "danger")
            return redirect(url_for("recepcao_objetos"))
        if not objeto["validado"]:
            conn.close()
            flash("A PPN foi localizada, mas possui dados obrigatórios incompletos: " + ", ".join(objeto["pendencias"]), "danger")
            return redirect(url_for("recepcao_objetos", codigo=codigo, cep=cep_consulta))
        if recepcao:
            recibo_id = recepcao["id"]; conn.close(); flash("Este objeto já foi recebido; abrimos o comprovante existente.", "warning")
            return redirect(url_for("recibo_recepcao", recepcao_id=recibo_id))
        valor = float(settings().get("preco_recepcao_objeto") or 0)
        # O banco guarda as medidas da criação (medidas_criacao); a recepção e o recibo usam as conferidas no balcão.
        reais = medidas_conferidas("Recepção", objeto["codigo_etiqueta"], objeto["codigo_etiqueta"]) or {}
        medidas_recibo = [reais.get(c) or objeto[c] for c in ("peso", "comprimento", "largura", "altura")]
        criado_em = datetime.now().isoformat(timespec="seconds")
        cur_cotacao = conn.execute("""INSERT INTO cotacoes(
            criado_em,cliente,documento,forma_pagamento,cep_origem,cep_destino,servico,peso,
            comprimento,largura,altura,valor_cliente,preco_vista,preco_contrato,lucro,prazo,modo,etiqueta,rastreio,destinatario,destinatario_nome,
            destinatario_rua,destinatario_bairro,destinatario_cidade,destinatario_uf,
            destinatario_numero,destinatario_complemento,remetente_nome,remetente_rua,
            remetente_bairro,remetente_cidade,remetente_uf,remetente_numero,remetente_complemento,
            remetente_documento,destinatario_documento,operador_id,operador_nome,transportadora,
            servico_transportadora,documento_fiscal,servicos_adicionais,cotacao_externa_id)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", valores_sqlite((
            criado_em, objeto["remetente_nome"], objeto["remetente_documento"],
            request.form.get("forma_pagamento", "Não informado"), objeto["cep_origem"], objeto["cep_destino"],
            objeto["servico"], *medidas_recibo, valor, valor, 0, valor,
            objeto["status_ppn"], "Recepção via Correios Atende", objeto["codigo_etiqueta"],
            objeto["rastreio"], objeto["destinatario_nome"], objeto["destinatario_nome"],
            objeto["destinatario_rua"], objeto["destinatario_bairro"], objeto["destinatario_cidade"],
            objeto["destinatario_uf"], objeto["destinatario_numero"], objeto["destinatario_complemento"],
            objeto["remetente_nome"], objeto["remetente_rua"], objeto["remetente_bairro"],
            objeto["remetente_cidade"], objeto["remetente_uf"], objeto["remetente_numero"],
            objeto["remetente_complemento"], objeto["remetente_documento"], objeto["destinatario_documento"],
            session["usuario"]["id"], session["usuario"]["nome"], "Correios", objeto["servico"],
            str(objeto["documento_fiscal"] or objeto["tipo_documento"]),
            json.dumps(objeto["adicionais"], ensure_ascii=False), str(objeto["ppn_id"] or ""),
        )))
        cur = conn.execute("""INSERT INTO recepcoes_objetos(criado_em,cotacao_id,codigo_objeto,cliente_nome,
            cliente_documento,valor,forma_pagamento,operador_id,operador_nome,observacoes) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (criado_em, cur_cotacao.lastrowid, objeto["codigo_etiqueta"],
             objeto["remetente_nome"], objeto["remetente_documento"], valor,
             request.form.get("forma_pagamento", "Não informado"), session["usuario"]["id"], session["usuario"]["nome"],
             request.form.get("observacoes", "").strip()))
        conn.execute("""INSERT OR IGNORE INTO expedicoes(
            cotacao_id,status,captado_por,captado_em,observacoes)
            VALUES(?,?,?,?,?)""", (
            cur_cotacao.lastrowid, "Pendente", session["usuario"]["id"], criado_em,
            "Objeto recebido no balcão e encaminhado automaticamente à fila de expedição dos Correios.",
        ))
        conn.commit(); recibo_id = cur.lastrowid; conn.close()
        registrar_log(
            "Objeto recebido no balcão",
            f"Recepção #{recibo_id}; objeto {codigo}; operador {session['usuario']['nome']}; "
            f"valor {valor:.2f}; enviado à fila de expedição Correios",
        )
        return redirect(url_for("recibo_recepcao", recepcao_id=recibo_id))
    recentes = conn.execute(f"SELECT * FROM recepcoes_objetos WHERE {sem_testes()} ORDER BY id DESC LIMIT 50").fetchall(); conn.close()
    return render_template("recepcao_objetos.html", codigo=codigo, cep_consulta=cep_consulta,
                           objeto=objeto, recepcao=recepcao, conferencia=conferencia, medidas=medidas,
                           configurada=configurada, erro_consulta=erro_consulta,
                           recentes=recentes, preco=float(settings().get("preco_recepcao_objeto") or 0),
                           meios_pagamento=listar_meios_pagamento())


@app.route("/recepcao-objetos/<int:recepcao_id>/recibo")
@perfis_permitidos("Master", "Administrador", "Operador de Balcão")
def recibo_recepcao(recepcao_id):
    conn = db(); row = conn.execute("""SELECT c.*,r.id AS recepcao_id,r.criado_em AS recebido_em,r.codigo_objeto,
        r.valor AS valor_recepcao,r.forma_pagamento AS pagamento_recepcao,r.operador_nome AS operador_recepcao,
        r.observacoes AS observacoes_recepcao
        FROM recepcoes_objetos r JOIN cotacoes c ON c.id=r.cotacao_id WHERE r.id=?""",
        (recepcao_id,)).fetchone(); conn.close()
    if not row: abort(404)
    try:
        adicionais = json.loads(row["servicos_adicionais"] or "[]")
    except ValueError:
        adicionais = []
    objeto = {chave: row[chave] for chave in row.keys()}
    objeto.update({"codigo": row["codigo_objeto"], "ppn_id": row["cotacao_externa_id"], "status_ppn": row["prazo"],
                   "documento": row["documento_fiscal"], "adicionais": nomes_adicionais_ppn(adicionais),
                   "medidas_conferidas": bool(medidas_conferidas("Recepção", row["codigo_objeto"], row["codigo_objeto"]))})
    recibo = {"titulo": "COMPROVANTE DE RECEPÇÃO", "numero": "%06d" % row["recepcao_id"],
              "data_hora": row["recebido_em"], "operador": row["operador_recepcao"],
              "cliente_nome": row["remetente_nome"], "cliente_documento": row["remetente_documento"],
              "objetos": [objeto], "observacoes": row["observacoes_recepcao"], "valor": float(row["valor_recepcao"] or 0),
              "pagamento": row["pagamento_recepcao"], "voltar": url_for("recepcao_objetos"),
              "declaracao": "Declaramos o recebimento do objeto no balcão para encaminhamento aos Correios."}
    return render_template("recibo_atendimento.html", r=recibo)


def nomes_adicionais_ppn(adicionais):
    nomes = []
    for a in adicionais or []:
        if isinstance(a, dict):
            nome = a.get("nomeServicoAdicional") or a.get("siglaServicoAdicional") or a.get("codigoServicoAdicional")
        else:
            nome = a
        if nome:
            nomes.append(str(nome))
    return nomes


@app.route("/usuarios", methods=["GET", "POST"])
@perfis_permitidos("Master", "Administrador")
def usuarios():
    """Tela de usuarios. Master: todas as lojas e perfis abaixo dele.
    Administrador: apenas a propria loja, perfis Operador de Balcão e Expedidor."""
    atual = session["usuario"]
    eh_master = atual["perfil"] == "Master"
    perfis_ok = {"Administrador", "Operador de Balcão", "Expedidor"} if eh_master else {"Operador de Balcão", "Expedidor"}
    conn = db()
    if request.method == "POST":
        acao = request.form.get("acao")
        try:
            if acao == "cadastrar":
                login_usuario = request.form.get("login", "").strip().lower()
                validar_login_loja(login_usuario)
                perfil = request.form.get("perfil")
                if perfil not in perfis_ok:
                    raise ValueError("Perfil inválido.")
                loja_id = request.form.get("loja_id", type=int) if eh_master else atual["loja_id"]
                if not conn.execute("SELECT 1 FROM lojas WHERE id=? AND ativo=1", (loja_id,)).fetchone():
                    raise ValueError("Loja inválida.")
                senha = request.form.get("senha", "")
                if len(senha) < 6:
                    raise ValueError("A senha deve ter pelo menos 6 caracteres.")
                conn.execute("INSERT INTO usuarios(nome,login,senha_hash,perfil,loja_id) VALUES(?,?,?,?,?)",
                             (request.form.get("nome", "").strip(), login_usuario, generate_password_hash(senha), perfil, loja_id))
                flash("Usuário cadastrado.", "success")
            elif acao in {"ativo", "senha", "editar"}:
                usuario_id = request.form.get("usuario_id", type=int)
                alvo = conn.execute("SELECT * FROM usuarios WHERE id=?", (usuario_id,)).fetchone()
                if not alvo or alvo["perfil"] not in perfis_ok or (not eh_master and alvo["loja_id"] != atual["loja_id"]):
                    raise ValueError("Usuário inválido para esta operação.")
                if acao == "editar":
                    nome = request.form.get("nome", "").strip()
                    perfil = request.form.get("perfil")
                    login_usuario = request.form.get("login", alvo["login"]).strip().lower()
                    if not nome:
                        raise ValueError("Informe o nome.")
                    if perfil not in perfis_ok:
                        raise ValueError("Perfil inválido.")
                    if login_usuario != alvo["login"]:
                        validar_login_loja(login_usuario)
                    conn.execute("UPDATE usuarios SET nome=?, login=?, perfil=?, sessao_token=CASE WHEN perfil<>? THEN NULL ELSE sessao_token END WHERE id=?",
                                 (nome, login_usuario, perfil, perfil, usuario_id))
                    flash("Usuário atualizado.", "success")
                elif acao == "ativo":
                    conn.execute("UPDATE usuarios SET ativo=?, sessao_token=NULL WHERE id=?", (0 if alvo["ativo"] else 1, usuario_id))
                    flash("Usuário " + ("desativado." if alvo["ativo"] else "reativado."), "success")
                else:
                    senha = request.form.get("senha", "")
                    if len(senha) < 6:
                        raise ValueError("A senha deve ter pelo menos 6 caracteres.")
                    conn.execute("UPDATE usuarios SET senha_hash=?, sessao_token=NULL WHERE id=?", (generate_password_hash(senha), usuario_id))
                    flash("Senha redefinida.", "success")
            else:
                abort(400)
            conn.commit()
        except (ValueError, sqlite3.IntegrityError) as exc:
            conn.rollback()
            flash("Esse login já está em uso." if isinstance(exc, sqlite3.IntegrityError) else str(exc), "danger")
        finally:
            conn.close()
        return redirect(url_for("usuarios"))
    if eh_master:
        lojas = conn.execute("SELECT * FROM lojas WHERE ativo=1 ORDER BY nome").fetchall()
        rows = conn.execute("""SELECT u.*,l.nome loja FROM usuarios u LEFT JOIN lojas l ON l.id=u.loja_id
            WHERE u.perfil<>'Master' ORDER BY l.nome,u.nome""").fetchall()
    else:
        lojas = conn.execute("SELECT * FROM lojas WHERE id=?", (atual["loja_id"],)).fetchall()
        rows = conn.execute("""SELECT u.*,l.nome loja FROM usuarios u LEFT JOIN lojas l ON l.id=u.loja_id
            WHERE u.loja_id=? AND u.perfil IN ('Operador de Balcão','Expedidor') ORDER BY u.nome""", (atual["loja_id"],)).fetchall()
    conn.close()
    return render_template("usuarios.html", rows=rows, lojas=lojas, perfis=sorted(perfis_ok), eh_master=eh_master)


@app.route("/painel-master", methods=["GET", "POST"])
@perfis_permitidos("Master")
def painel_master():
    conn = db()
    if request.method == "POST":
        acao = request.form.get("acao")
        try:
            if acao == "loja":
                email = request.form.get("email", "").strip().lower()
                if not email.endswith("@lojadeenvios") or email.count("@") != 1:
                    raise ValueError("O e-mail da loja deve usar o domínio @lojadeenvios.")
                conn.execute("INSERT INTO lojas(nome,email,cnpj,criado_em) VALUES(?,?,?,?)",
                             (request.form["nome"].strip(), email,
                              re.sub(r"\D", "", request.form.get("cnpj", "")), datetime.now().isoformat(timespec="seconds")))
                flash("Loja cadastrada no Painel Master.", "success")
            elif acao == "usuario":
                login_usuario = request.form.get("login", "").strip().lower()
                if not login_usuario.endswith("@lojadeenvios") or login_usuario.count("@") != 1:
                    raise ValueError("O login deve ser um e-mail no domínio @lojadeenvios.")
                perfil = request.form.get("perfil")
                if perfil not in {"Administrador", "Operador de Balcão", "Expedidor"}:
                    raise ValueError("Perfil inválido.")
                loja_id = request.form.get("loja_id", type=int)
                if not conn.execute("SELECT 1 FROM lojas WHERE id=? AND ativo=1", (loja_id,)).fetchone():
                    raise ValueError("Loja inválida.")
                conn.execute("INSERT INTO usuarios(nome,login,senha_hash,perfil,loja_id) VALUES(?,?,?,?,?)",
                             (request.form["nome"].strip(), login_usuario,
                              generate_password_hash(request.form["senha"]), perfil, loja_id))
                flash("Usuário cadastrado no Painel Master.", "success")
            elif acao == "licenca":
                loja_id = request.form.get("loja_id", type=int)
                valida_de = request.form.get("valida_de", "")
                valida_ate = request.form.get("valida_ate", "")
                if not loja_id or not valida_de or not valida_ate or valida_ate < valida_de:
                    raise ValueError("Informe um período de licença válido.")
                chave = "LDE-" + secrets.token_hex(4).upper() + "-" + secrets.token_hex(4).upper()
                conn.execute("INSERT INTO licencas(loja_id,chave,status,valida_de,valida_ate,criado_em,criado_por) VALUES(?,?,?,?,?,?,?)",
                             (loja_id, chave, "Ativa", valida_de, valida_ate,
                              datetime.now().isoformat(timespec="seconds"), session["usuario"]["id"]))
                flash(f"Licença gerada: {chave}", "success")
            elif acao == "status_licenca":
                licenca_id = request.form.get("licenca_id", type=int)
                nova = "Revogada" if request.form.get("status") == "Ativa" else "Ativa"
                conn.execute("UPDATE licencas SET status=? WHERE id=?", (nova, licenca_id))
                flash("Status da licença atualizado.", "success")
            else:
                abort(400)
            conn.commit()
        except (ValueError, sqlite3.IntegrityError) as exc:
            conn.rollback(); flash(str(exc), "danger")
        finally:
            conn.close()
        return redirect(url_for("painel_master"))
    lojas = conn.execute("SELECT * FROM lojas ORDER BY nome").fetchall()
    rows = conn.execute("""SELECT u.id,u.nome,u.login,u.perfil,u.ativo,l.nome loja
        FROM usuarios u LEFT JOIN lojas l ON l.id=u.loja_id ORDER BY u.nome""").fetchall()
    licencas = conn.execute("""SELECT x.*,l.nome loja,l.email loja_email FROM licencas x JOIN lojas l ON l.id=x.loja_id
        ORDER BY x.id DESC""").fetchall()
    conn.close()
    return render_template("painel_master.html", rows=rows, lojas=lojas, licencas=licencas)


@app.route("/estoque", methods=["GET", "POST"])
@perfis_permitidos("Administrador", "Master", "Operador de Balcão")
def estoque():
    conn = db()
    if request.method == "POST":
        acao = request.form.get("acao")
        perfil = session["usuario"]["perfil"]
        if acao in {"cadastrar", "entrada", "transferir", "atender_pedido", "sangria", "fiscal"} and perfil not in {"Administrador", "Master"}:
            conn.close(); abort(403)
        if acao in {"abrir", "fechar", "pedir_suprimento"} and perfil != "Operador de Balcão":
            conn.close(); abort(403)
        if acao == "cadastrar" and session["usuario"]["perfil"] in {"Administrador", "Master"}:
            qtd_inicial = request.form.get("quantidade", type=float) or 0
            custo = request.form.get("custo_unitario", type=float) or 0
            cur = conn.execute("INSERT INTO estoque(item,sku,unidade,quantidade,minimo,preco_venda,custo_unitario,ncm) VALUES(?,?,?,?,?,?,?,?)",
                               (request.form["item"].strip(), request.form["sku"].strip(), request.form.get("unidade", "un"),
                                qtd_inicial, request.form.get("minimo", type=float) or 0,
                                request.form.get("preco_venda", type=float) or 0, custo,
                                re.sub(r"\D", "", request.form.get("ncm", "")) or None))
            if qtd_inicial > 0:
                criado_em = datetime.now().isoformat(timespec="seconds")
                mov = conn.execute("""INSERT INTO movimentos_estoque(criado_em,estoque_id,tipo,quantidade,custo_unitario,
                    valor_total,fornecedor,documento,operador_id,operador_nome) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (criado_em, cur.lastrowid, "Entrada inicial", qtd_inicial, custo, round(qtd_inicial*custo,2),
                     request.form.get("fornecedor", "").strip(), request.form.get("documento_entrada", "").strip(),
                     session["usuario"]["id"], session["usuario"]["nome"])).lastrowid
                conn.execute("""INSERT INTO fluxo_caixa_eventos(criado_em,origem,origem_id,tipo,descricao,valor,payload_json)
                    VALUES(?,?,?,?,?,?,?)""", (criado_em, "Estoque", mov, "Despesa de estoque",
                    f"Entrada inicial — {request.form['item'].strip()}", round(qtd_inicial*custo,2),
                    json.dumps({"estoque_id": cur.lastrowid, "quantidade": qtd_inicial, "custo_unitario": custo}, ensure_ascii=False)))
            flash("Item cadastrado no estoque.", "success")
        elif acao == "fiscal":
            ncm = re.sub(r"\D", "", request.form.get("ncm", ""))
            cfop = re.sub(r"\D", "", request.form.get("cfop", ""))
            if len(ncm) != 8 or (cfop and len(cfop) != 4):
                conn.close(); flash("Informe o NCM com 8 dígitos e, se preenchido, o CFOP com 4.", "danger")
                return redirect(url_for("estoque"))
            conn.execute("UPDATE estoque SET ncm=?,cfop=? WHERE id=?", (ncm, cfop or None, request.form.get("estoque_id", type=int)))
            flash("Dados fiscais do produto salvos.", "success")
        elif acao == "entrada" and session["usuario"]["perfil"] in {"Administrador", "Master"}:
            estoque_id = request.form.get("estoque_id", type=int)
            qtd = request.form.get("quantidade", type=float) or 0
            custo = request.form.get("custo_unitario", type=float) or 0
            item = conn.execute("SELECT id,item,custo_unitario FROM estoque WHERE id=?", (estoque_id,)).fetchone()
            if not item or qtd <= 0:
                conn.close(); flash("Informe um produto e uma quantidade válida para a entrada.", "danger")
                return redirect(url_for("estoque"))
            custo = custo if custo > 0 else float(item["custo_unitario"] or 0)
            conn.execute("UPDATE estoque SET quantidade=COALESCE(quantidade,0)+?,custo_unitario=? WHERE id=?", (qtd, custo, estoque_id))
            criado_em = datetime.now().isoformat(timespec="seconds")
            fornecedor = request.form.get("fornecedor", "").strip()
            documento_entrada = request.form.get("documento_entrada", "").strip()
            mov = conn.execute("""INSERT INTO movimentos_estoque(criado_em,estoque_id,tipo,quantidade,custo_unitario,
                valor_total,fornecedor,documento,operador_id,operador_nome) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (criado_em, estoque_id, "Entrada", qtd, custo, round(qtd*custo,2), fornecedor,
                 documento_entrada, session["usuario"]["id"], session["usuario"]["nome"])).lastrowid
            conn.execute("""INSERT INTO fluxo_caixa_eventos(criado_em,origem,origem_id,tipo,descricao,valor,payload_json)
                VALUES(?,?,?,?,?,?,?)""", (criado_em, "Estoque", mov, "Despesa de estoque",
                f"Entrada de estoque — {item['item']}", round(qtd*custo,2),
                json.dumps({"estoque_id": estoque_id, "quantidade": qtd, "custo_unitario": custo,
                            "fornecedor": fornecedor, "documento": documento_entrada}, ensure_ascii=False)))
            conn.execute("INSERT INTO logs_sistema(criado_em,usuario_id,usuario_nome,acao,detalhes) VALUES(?,?,?,?,?)",
                         (datetime.now().isoformat(timespec="seconds"), session["usuario"]["id"],
                          session["usuario"]["nome"], "Entrada de estoque",
                          f"Produto {item['item']}; quantidade {qtd:g}"))
            flash("Entrada registrada no estoque da loja.", "success")
        elif acao == "transferir" and session["usuario"]["perfil"] in {"Administrador", "Master"}:
            estoque_id, operador_id = request.form.get("estoque_id", type=int), request.form.get("operador_id", type=int)
            qtd = request.form.get("quantidade", type=float) or 0
            item = conn.execute("SELECT quantidade FROM estoque WHERE id=?", (estoque_id,)).fetchone()
            if not item or qtd <= 0 or qtd > item["quantidade"]:
                conn.close(); flash("Quantidade inválida para transferência.", "danger"); return redirect(url_for("estoque"))
            conn.execute("UPDATE estoque SET quantidade=quantidade-? WHERE id=?", (qtd, estoque_id))
            conn.execute("INSERT INTO estoque_caixa(estoque_id,operador_id,quantidade,saldo,transferido_em) VALUES(?,?,?,?,?)",
                         (estoque_id, operador_id, qtd, qtd, datetime.now().isoformat(timespec="seconds")))
            flash("Estoque transferido ao caixa.", "success")
        elif acao in {"abrir", "fechar"}:
            lote_id = request.form.get("lote_id", type=int); contagem = request.form.get("contagem", type=float)
            lote = conn.execute("SELECT * FROM estoque_caixa WHERE id=? AND operador_id=?", (lote_id, session["usuario"]["id"])).fetchone()
            if not lote: conn.close(); abort(403)
            if contagem is None or contagem < 0:
                conn.close(); abort(400)
            if acao == "abrir" and lote["status"] == "Transferido":
                conn.execute("UPDATE estoque_caixa SET conferido_abertura=?,aberto_em=?,status='Aberto' WHERE id=?",
                             (contagem, datetime.now().isoformat(timespec="seconds"), lote_id))
            elif acao == "fechar" and lote["status"] == "Aberto":
                conn.execute("UPDATE estoque_caixa SET conferido_fechamento=?,fechado_em=?,status='Fechado' WHERE id=?",
                             (contagem, datetime.now().isoformat(timespec="seconds"), lote_id))
            else:
                conn.close(); abort(409)
            flash("Contagem do caixa registrada.", "success")
        elif acao == "pedir_suprimento":
            estoque_id = request.form.get("estoque_id", type=int)
            qtd = request.form.get("quantidade", type=float) or 0
            if qtd <= 0 or not conn.execute("SELECT 1 FROM estoque WHERE id=?", (estoque_id,)).fetchone():
                conn.close(); abort(400)
            conn.execute("INSERT INTO pedidos_suprimento(criado_em,estoque_id,operador_id,quantidade,observacoes) VALUES(?,?,?,?,?)",
                         (datetime.now().isoformat(timespec="seconds"), estoque_id, session["usuario"]["id"], qtd,
                          request.form.get("observacoes", "").strip()))
            flash("Pedido de suprimento enviado ao Administrador.", "success")
        elif acao == "atender_pedido":
            pedido_id = request.form.get("pedido_id", type=int)
            pedido = conn.execute("SELECT * FROM pedidos_suprimento WHERE id=? AND status='Pendente'", (pedido_id,)).fetchone()
            item = conn.execute("SELECT quantidade FROM estoque WHERE id=?", (pedido["estoque_id"],)).fetchone() if pedido else None
            if not pedido or not item or pedido["quantidade"] > item["quantidade"]:
                conn.close(); flash("Pedido indisponível ou sem saldo suficiente.", "danger"); return redirect(url_for("estoque"))
            conn.execute("UPDATE estoque SET quantidade=quantidade-? WHERE id=?", (pedido["quantidade"], pedido["estoque_id"]))
            conn.execute("INSERT INTO estoque_caixa(estoque_id,operador_id,quantidade,saldo,transferido_em) VALUES(?,?,?,?,?)",
                         (pedido["estoque_id"], pedido["operador_id"], pedido["quantidade"], pedido["quantidade"], datetime.now().isoformat(timespec="seconds")))
            conn.execute("UPDATE pedidos_suprimento SET status='Atendido',atendido_em=?,atendido_por=? WHERE id=?",
                         (datetime.now().isoformat(timespec="seconds"), session["usuario"]["id"], pedido_id))
            flash("Pedido atendido e estoque transferido ao operador.", "success")
        elif acao == "sangria":
            operador_id = request.form.get("operador_id", type=int)
            valor = request.form.get("valor", type=float) or 0
            fechado = conn.execute("SELECT 1 FROM estoque_caixa WHERE operador_id=? AND status='Fechado' LIMIT 1", (operador_id,)).fetchone()
            if valor <= 0 or not fechado:
                conn.close(); flash("A sangria exige valor positivo e caixa fechado/conferido.", "danger"); return redirect(url_for("estoque"))
            agora = datetime.now().isoformat(timespec="seconds")
            cur = conn.execute("INSERT INTO sangrias(criado_em,operador_id,administrador_id,valor,observacoes) VALUES(?,?,?,?,?)",
                               (agora, operador_id, session["usuario"]["id"], valor, request.form.get("observacoes", "").strip()))
            conn.execute("INSERT INTO livro_caixa(criado_em,tipo,origem,origem_id,descricao,valor,operador_id,administrador_id) VALUES(?,?,?,?,?,?,?,?)",
                         (agora, "Entrada", "Sangria", cur.lastrowid, "Sangria após fechamento e conferência de estoque", valor, operador_id, session["usuario"]["id"]))
            flash("Sangria registrada no Livro Caixa.", "success")
        conn.commit(); conn.close(); return redirect(url_for("estoque"))
    itens = conn.execute("SELECT * FROM estoque ORDER BY item").fetchall()
    operadores = conn.execute("SELECT id,nome FROM usuarios WHERE perfil='Operador de Balcão' AND ativo=1 ORDER BY nome").fetchall()
    pedidos = conn.execute("""SELECT p.*,e.item,u.nome operador FROM pedidos_suprimento p
        JOIN estoque e ON e.id=p.estoque_id JOIN usuarios u ON u.id=p.operador_id
        WHERE p.status='Pendente' ORDER BY p.id DESC""").fetchall() if session["usuario"]["perfil"] in {"Administrador", "Master"} else []
    if session["usuario"]["perfil"] in {"Administrador", "Master"}:
        lotes = conn.execute("SELECT ec.*,e.item,e.sku,u.nome operador FROM estoque_caixa ec JOIN estoque e ON e.id=ec.estoque_id JOIN usuarios u ON u.id=ec.operador_id ORDER BY ec.id DESC").fetchall()
    else:
        lotes = conn.execute("SELECT ec.*,e.item,e.sku,u.nome operador FROM estoque_caixa ec JOIN estoque e ON e.id=ec.estoque_id JOIN usuarios u ON u.id=ec.operador_id WHERE ec.operador_id=? ORDER BY ec.id DESC", (session["usuario"]["id"],)).fetchall()
    conn.close()
    return render_template("estoque.html", itens=itens, operadores=operadores, lotes=lotes, pedidos=pedidos)


@app.route("/livro-caixa")
@perfis_permitidos("Administrador", "Master", "Operador de Balcão")
def livro_caixa():
    # O Operador de Balcão enxerga apenas os lançamentos do próprio caixa.
    # Lançamentos das postagens de teste ficam fora do livro e do saldo.
    filtro, params = (" WHERE NOT (lc.origem='Postagem' AND lc.origem_id IN (SELECT id FROM cotacoes WHERE NOT "
                      + sem_testes() + "))"), ()
    if session["usuario"]["perfil"] == "Operador de Balcão":
        # O lucro das postagens (preço de contrato) fica só para o Administrador.
        filtro, params = " WHERE lc.operador_id=? AND lc.origem<>'Postagem'", (session["usuario"]["id"],)
    conn = db()
    rows = conn.execute("""SELECT lc.*,op.nome operador,adm.nome administrador FROM livro_caixa lc
        LEFT JOIN usuarios op ON op.id=lc.operador_id LEFT JOIN usuarios adm ON adm.id=lc.administrador_id"""
        + filtro + " ORDER BY lc.id DESC", params).fetchall()
    total = conn.execute("SELECT COALESCE(SUM(CASE WHEN tipo='Entrada' THEN valor ELSE -valor END),0) total FROM livro_caixa lc"
                         + filtro, params).fetchone()["total"]
    conn.close()
    return render_template("livro_caixa.html", rows=rows, total=total)





@app.route("/resultado")
@perfis_permitidos("Administrador", "Master")
def resultado():
    """Resultado do dia: para cada postagem (numero de transacao), o que cobramos do cliente
    pela tabela a vista e o que pagamos pelo contrato; a diferenca e o lucro lancado no Livro Caixa."""
    data = request.args.get("data") or datetime.now().strftime("%Y-%m-%d")
    conn = db()
    rows = conn.execute("""SELECT lc.transacao,lc.criado_em,lc.tipo,lc.valor,c.id cotacao_id,c.transportadora,
              COALESCE(NULLIF(c.servico_transportadora,''),c.servico) servico,c.valor_cliente,c.preco_contrato,
              c.custo_produtos,COALESCE(c.remetente_nome,c.cliente) cliente,
              COALESCE(c.operador_nome,'Não identificado') operador
              FROM livro_caixa lc JOIN cotacoes c ON c.id=lc.origem_id
              WHERE lc.origem='Postagem' AND substr(lc.criado_em,1,10)=? AND """ + sem_testes("c.criado_em") + """
              ORDER BY lc.criado_em,lc.id""",
                        (data,)).fetchall()
    conn.close()
    totais = {"postagens": len(rows),
              "cobrado": round(sum(float(r["valor_cliente"] or 0) for r in rows), 2),
              "pago": round(sum(float(r["preco_contrato"] or 0) + float(r["custo_produtos"] or 0) for r in rows), 2),
              "lucro": round(sum(r["valor"] if r["tipo"] == "Entrada" else -r["valor"] for r in rows), 2)}
    return render_template("resultado.html", rows=rows, totais=totais, data=data)


@app.route("/saldo-a-pagar")
@perfis_permitidos("Administrador", "Master")
def saldo_a_pagar():
    """Saldo a pagar do mes: cada objeto enviado (com etiqueta ou rastreio) e o custo pelo contrato,
    com o total por transportadora e a situacao do objeto na ultima conferencia de fatura."""
    mes = request.args.get("mes") or datetime.now().strftime("%Y-%m")
    if not re.fullmatch(r"\d{4}-\d{2}", mes):
        mes = datetime.now().strftime("%Y-%m")
    transportadora = request.args.get("transportadora", "").strip()
    filtro, params = "", [mes]
    if transportadora:
        filtro, params = " AND COALESCE(c.transportadora,'Correios')=?", [mes, transportadora]
    conn = db()
    rows = conn.execute("""SELECT c.id,c.criado_em,COALESCE(c.transportadora,'Correios') transportadora,
              COALESCE(NULLIF(c.servico_transportadora,''),c.servico) servico,
              COALESCE(NULLIF(c.rastreio,''),c.etiqueta) objeto,c.peso,
              COALESCE(c.destinatario_nome,c.destinatario) destinatario,c.destinatario_cidade,c.destinatario_uf,
              CAST(COALESCE(c.preco_contrato,0) AS REAL) custo,
              (SELECT i.status FROM conferencia_fatura_itens i WHERE i.etiqueta=COALESCE(NULLIF(c.rastreio,''),c.etiqueta)
               ORDER BY i.id DESC LIMIT 1) conferencia
              FROM cotacoes c WHERE substr(c.criado_em,1,7)=? AND COALESCE(NULLIF(c.rastreio,''),c.etiqueta,'')<>''
              AND """ + sem_testes("c.criado_em")
                        + filtro + " ORDER BY c.criado_em,c.id", params).fetchall()
    transportadoras = [r[0] for r in conn.execute(
        "SELECT DISTINCT COALESCE(transportadora,'Correios') FROM cotacoes ORDER BY 1")]
    conn.close()
    por_transportadora = {}
    for r in rows:
        t = por_transportadora.setdefault(r["transportadora"], {"objetos": 0, "custo": 0.0})
        t["objetos"] += 1; t["custo"] += r["custo"]
    total = round(sum(r["custo"] for r in rows), 2)
    return render_template("saldo_a_pagar.html", rows=rows, mes=mes, transportadora=transportadora,
                           transportadoras=transportadoras, por_transportadora=por_transportadora, total=total)


def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000")


def backup_do_deploy():
    """Preceito: nada e apagado ou alterado, e todo deploy guarda antes uma copia fiel do banco.
    Roda antes de init_db, uma vez por commit (RENDER_GIT_COMMIT), em BACKUP_DIR ou na pasta
    'backups' ao lado do banco. Os backups nunca sao apagados pelo sistema.
    Devolve True se o banco esta coberto por um backup (feito agora ou por outro worker)."""
    if not os.path.exists(DB):
        return True
    pasta = os.getenv("BACKUP_DIR") or os.path.join(os.path.dirname(os.path.abspath(DB)), "backups")
    os.makedirs(pasta, exist_ok=True)
    versao = re.sub(r"[^A-Za-z0-9]", "", os.getenv("RENDER_GIT_COMMIT", ""))[:12] or "semcommit"
    trava = os.path.join(pasta, f"deploy_{versao}.lock")
    try:
        # Varios workers do gunicorn sobem juntos: so o primeiro faz o backup deste deploy.
        os.close(os.open(trava, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
    except FileExistsError:
        return True
    destino = os.path.join(pasta, f"envios_{datetime.now().strftime('%Y%m%d-%H%M%S')}_{versao}.db")
    try:
        origem = sqlite3.connect(DB, timeout=60); copia = sqlite3.connect(destino + ".parcial")
        origem.backup(copia)
        if copia.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("integrity_check do backup falhou")
        tabelas = [r[0] for r in origem.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for tabela in tabelas:
            consulta = f'SELECT COUNT(*) FROM "{tabela}"'
            if origem.execute(consulta).fetchone()[0] != copia.execute(consulta).fetchone()[0]:
                raise RuntimeError(f"backup difere do banco na tabela {tabela}")
        copia.close(); origem.close()
        os.replace(destino + ".parcial", destino)
        app.logger.warning("Backup do deploy gravado em %s (%d tabelas conferidas)", destino, len(tabelas))
        return True
    except Exception:
        # Libera a trava para o proximo worker/reinicio tentar de novo; o arquivo parcial fica para analise.
        os.remove(trava)
        app.logger.exception("Falha no backup do deploy; o banco nao sera alterado na inicializacao")
        return False


# Em producao (gunicorn) o bloco __main__ nao roda; a inicializacao do banco
# acontece aqui quando PRODUCAO=1 ou no Render (que define RENDER). Localmente nada muda.
# Antes de qualquer ajuste no banco, o deploy faz o backup; sem backup, init_db nao roda.
if os.getenv("PRODUCAO") == "1":
    if backup_do_deploy():
        init_db()
elif os.getenv("RENDER") and __name__ != "__main__":
    # No Render sem PRODUCAO=1 o banco tambem precisa das tabelas e colunas novas; uma falha aqui
    # fica no log do Render e nao derruba o site.
    try:
        if backup_do_deploy():
            init_db(somente_estrutura=True)
    except Exception:
        app.logger.exception("Falha na inicializacao do banco no Render")


if __name__ == "__main__":
    init_db()
    if os.getenv("ABRIR_NAVEGADOR", "1") == "1":
        threading.Timer(1.2, open_browser).start()
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")), debug=False)
