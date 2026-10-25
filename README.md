# Loja de Envios

Sistema de balcão de uma Agência Franqueada dos Correios (AGF): cotação de frete, emissão
de rótulo/etiqueta, expedição e o financeiro da operação de postagem. Aplicativo Flask
(`app.py`) com banco SQLite (`envios.db`) e telas Jinja2 + Bootstrap em `templates/`.
Interface, código e documentação em português (pt-BR).

> O Financeiro AGF / Fluxo Big (`server.py`) morava neste repositório por engano e foi
> retirado daqui; ele continua no histórico do Git até o commit `71feb28`.

## Módulos

Menu em [templates/base.html](templates/base.html):

- **Cotação e postagem**: nova cotação, carga fracionada, carga consolidada, recibo,
  rótulo PPN (HTML, PDF e Zebra/ZPL), etiqueta dos Correios, histórico.
- **Operação**: expedição (leitor de código de barras, fechamento de romaneios),
  triagem por plano de destinos, recepção de objetos, logística reversa, controle de estoque.
- **Comercial/financeiro**: clientes, enviados, cobrança, conferência de faturas,
  livro caixa, resultado do dia, relatórios, exportação por transportadora.
- **Transação e lucro**: cada postagem (PPN criada ou envio externo aceito) recebe um número
  de transação (`TXAAAAMMDD-000123`) e lança no Livro Caixa o lucro dela: valor cobrado
  (tabela à vista + adicionais + produtos) menos o pago (contrato + custo dos produtos).
  A tela **Resultado** (só Administrador e Master) soma esses lançamentos por dia.
- **Regras da tabela à vista** (`data/tarifas/parametros.csv`): peso cúbico, limites de peso e
  medidas, manuseio especial, valor declarado e valores de AR e Mão Própria. A tela Tarifas à
  vista lista essas regras com a fonte de cada uma.
- **Administração**: usuários, tarifas à vista, integrações, Painel Master, logs, configurações.

**Perfis de acesso:** `Master`, `Administrador`, `Operador de Balcão`, `Expedidor`
(decorador `@perfis_permitidos(...)` em cada rota). O `Expedidor` cai direto na tela de
Expedição ao entrar. O `Operador de Balcão` (antigo `Operador de Caixa`, migrado
automaticamente no `init_db()`) vê apenas Envio, Histórico, Enviados, Controle de estoque
(só o próprio caixa), Consultar Reversa, Recepção de Objetos, Tarifas à vista e Livro Caixa
(só os próprios lançamentos, sem o lucro das postagens). Quem abastece o estoque do operador é o Administrador.
Cada usuário altera o próprio nome e login em **Meu usuário**.

**Conta Master:** criada no `init_db()` com o login de `MASTER_LOGIN` (padrão `fifo.edu`)
e a senha de `MASTER_SENHA`. Em produção (`PRODUCAO=1`) a `MASTER_SENHA` é obrigatória.
Sem ela, fora de produção, o código ainda usa uma senha padrão embutida; isso precisa ser
removido antes de distribuir o sistema. Usuários criados pelo Painel Master usam login no
domínio `@lojadeenvios`.

**Licenciamento:** o login valida a licença da loja (tabela `licencas`); sem licença
válida o acesso é bloqueado com HTTP 403. Licenças são geradas em `/painel-master`
(somente Master), no formato `LDE-XXXXXXXX-XXXXXXXX`.

## Cálculo de frete

1. **Tabela à vista local** (padrão, `CORREIOS_MODO=demo`): as tabelas de
   [data/tarifas/](data/tarifas) (`precos_vista.csv`, `enquadramento.csv`, `prazos.csv`)
   são carregadas no banco a cada inicialização. O Master também pode importar uma
   planilha (`.xlsx`/`.csv`) na tela **Tarifas à vista**. O script
   [montar_enquadramento.py](montar_enquadramento.py) gera o `enquadramento.csv`.
2. **API dos Correios** (`CORREIOS_MODO=api`): preço e prazo oficiais, autenticando em
   `api.correios.com.br` com cartão de postagem/contrato.
3. **Transportadoras integradas** (Jadlog, Braspress, J&T, Loggi, Total Express):
   cotação via API na tela **Integrações**, com acompanhamento de SLA.

**Consulta de CEP:** base local `data/cepx.sqlite` e, opcionalmente, a API oficial de
Consulta CEP do Conecta gov.br (credenciais `CONECTAGOV_*`).

## Como rodar

```bat
iniciar_sistema.bat
```

O script cria `.venv`, instala `requirements.txt`, compila `app.py` e abre o sistema.
Manualmente:

```bat
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe app.py
```

Abre em <http://127.0.0.1:5000> (o navegador é aberto sozinho; desative com
`ABRIR_NAVEGADOR=0`). Requer Python 3.11+ (o build empacotado usa 3.14).

O banco se chamava `balcao.db`. Se ele existir e o `envios.db` não, o sistema renomeia o
arquivo sozinho na primeira execução.

## Variáveis de ambiente

Lidas do ambiente (não há carregamento automático de `.env`). Credenciais de integração
**não** são mais lidas do ambiente em uso: ficam só nas telas **Configurações**/**Integrações**,
criptografadas no banco. Se alguma ainda estiver no ambiente, o `init_db()` a importa para o banco
na inicialização (registra no Log) e ela pode ser apagada do Render em seguida. Para isso o
`DB_PATH` e a chave (`CHAVE_SEGREDOS_PATH`) precisam estar em disco persistente.

| Variável | Padrão | Uso |
|---|---|---|
| `SECRET_KEY` | `loja-envios-local` (só fora de produção) | Assina o cookie de sessão. **Obrigatória com `PRODUCAO=1`** |
| `MASTER_LOGIN` / `MASTER_SENHA` | `fifo.edu` / — | Conta Master criada na inicialização. `MASTER_SENHA` obrigatória com `PRODUCAO=1` |
| `DB_PATH` | `./envios.db` | Caminho do SQLite (disco persistente em produção) |
| `HOST` / `PORT` | `127.0.0.1` / `5000` | Endereço de escuta |
| `ABRIR_NAVEGADOR` | `1` | `0` não abre o navegador ao iniciar |
| `PRODUCAO` | — | `1` inicializa o banco sob gunicorn e liga o cookie `Secure` |
| `CORREIOS_MODO` | `demo` | `demo` = tabela local; `api` = API dos Correios |
| `CORREIOS_USUARIO`, `CORREIOS_CODIGO_ACESSO`, `CORREIOS_CARTAO`, `CORREIOS_CONTRATO`, `CORREIOS_DR` | — | Só importação inicial: credenciais da API dos Correios (CWS) |
| `CORREIOS_ATENDE_USUARIO`, `CORREIOS_ATENDE_SENHA`, `CORREIOS_ATENDE_MCU` | — | Só importação inicial: Correios Atende (reversa e recepção) |
| `CONECTAGOV_CLIENT_ID`, `CONECTAGOV_CLIENT_SECRET`, `CONECTAGOV_AMBIENTE` | `producao` | Só importação inicial: CEP oficial via Conecta gov.br |
| `ZERAR_USUARIOS`, `ZERAR_MASTER` | — | `1` apaga usuários/Master na inicialização (uso único; remova em seguida) |

## Segredos e chaves

Senhas e tokens cadastrados nas telas (Correios, Correios Atende, SMTP, Conecta gov.br,
meios de pagamento e transportadoras) ficam **criptografados** no banco com Fernet, usando
a chave `data/secret.key`. Só o backend descriptografa; as telas mostram apenas
"Configurado", e só o Master grava esses campos. Valores antigos em texto puro são
criptografados automaticamente na inicialização.

- `data/secret.key` é criada sozinha na primeira execução, uma por instalação.
- **Guarde uma cópia fora do computador.** Sem ela, as senhas salvas não podem ser lidas
  e precisam ser cadastradas de novo.
- Nunca a coloque no Git (está no [.gitignore](.gitignore)) nem no pacote entregue ao
  cliente (o [.spec](LojaDeEnvios.spec) não a empacota).

## Estrutura

```
app.py                  Aplicação Flask: rotas, regras e schema do envios.db
templates/              Telas Jinja2
static/                 CSS e imagens
data/cepx.sqlite        Base local de CEP (versionada)
data/tarifas/           Tabelas de preço, enquadramento e prazo (versionadas)
data/plano_triagem.csv  Plano de triagem de referência
montar_enquadramento.py Gera data/tarifas/enquadramento.csv
docs/                   Única pasta publicada no GitHub Pages (página institucional)
iniciar_sistema.bat     Prepara o .venv e abre o sistema
build_windows.bat       Gera o executável (PyInstaller)
LojaDeEnvios.spec       Definição do pacote PyInstaller
installer_loja_de_envios.iss  Instalador Inno Setup
```

## Build do executável Windows

```bat
build_windows.bat
```

Gera `dist\LojaDeEnvios\LojaDeEnvios.exe` com PyInstaller a partir de
[LojaDeEnvios.spec](LojaDeEnvios.spec) (`--onedir --windowed`). O pacote leva
`templates/`, `static/`, `data/cepx.sqlite` e `data/tarifas/`. A chave e o banco ficam de
fora de propósito. O instalador Inno Setup está em
[installer_loja_de_envios.iss](installer_loja_de_envios.iss).

## Deploy

Use `gunicorn app:app` com `PRODUCAO=1` e `DB_PATH` apontando para o disco persistente.

### Checklist de produção

- [ ] **`SECRET_KEY` definida** com um valor forte e exclusivo
      (`python -c "import secrets; print(secrets.token_hex(32))"`). Quem conhece o valor
      de desenvolvimento forja um cookie de sessão de Master.
- [ ] **`MASTER_SENHA` definida** com uma senha forte.
- [ ] **`PRODUCAO=1`**, **`DB_PATH`** em disco persistente e servido por **gunicorn**.
- [ ] **`data/secret.key`** presente no servidor e com cópia guardada.
- [ ] **`ZERAR_USUARIOS` e `ZERAR_MASTER` ausentes** do ambiente.
- [ ] Cabeçalhos de segurança (HSTS, `X-Frame-Options`, CSP) configurados no Cloudflare.
- [ ] GitHub Pages publicando **apenas `docs/`** (confira o `path` em
      [.github/workflows/static.yml](.github/workflows/static.yml)).

## Documentação complementar

- [Manual_de_Uso_Loja_de_Envios_v1.1.pdf](Manual_de_Uso_Loja_de_Envios_v1.1.pdf): manual de uso (gerado por `gerar_manual.py`).
- [HISTORICO_DE_REVISOES.txt](HISTORICO_DE_REVISOES.txt): histórico de revisões.

## Pontos de atenção

- **Tabela de tarifas legada.** A cotação à vista usa `tarifas_correios_v2`;
  `tarifas_correios` continua sendo criada no `init_db()` mas não alimenta mais as
  cotações.
- **Histórico do Git.** Bancos com dados e credenciais (`balcao.db`, `data/*.db`) e
  pacotes `.zip` ainda estão em commits antigos. Precisam ser removidos do histórico com
  `git filter-repo`, e as credenciais que estavam neles, trocadas.
