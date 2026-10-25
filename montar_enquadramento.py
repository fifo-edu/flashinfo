# -*- coding: utf-8 -*-
"""Monta data/tarifas/enquadramento.csv: para uma cidade de origem, o grupo
(LOCAL, ESTADUAL, N1..N6) e a base (CAPITAL/INTERIOR) de cada cidade de destino.

Como funciona: para cada cidade da base cepx consulta, uma unica vez, o preco
do PAC a vista (04510) com 300 g na API de preco dos Correios e identifica o
enquadramento comparando o valor com a tabela nacional (precos_vista.csv).
Depois disso a cotacao nao precisa mais da API: acha a cidade pelo CEP, le o
enquadramento e busca o preco de qualquer peso/servico na tabela nacional.

Com --prazos monta data/tarifas/prazos.csv: o prazo de PAC e SEDEX de cada
cidade pela API de prazo. A cotacao usa esse prazo quando a integracao esta
indisponivel.

Uso:
    python montar_enquadramento.py 13201000              # origem Jundiai/SP
    python montar_enquadramento.py 13201000 --limite 30  # amostra
    python montar_enquadramento.py 13201000 --prazos     # prazos de PAC e SEDEX

O arquivo e gravado linha a linha; rodar de novo continua de onde parou.
Rotas cujo preco nao bate com a tabela ficam com grupo "?" para revisao
(nao sao usadas na cotacao); prazos que falharem ficam vazios e sao
consultados de novo na proxima rodada.
"""
import argparse
import csv
import json
import os
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

import app

SAIDA = os.path.join(app.TARIFAS_DIR, "enquadramento.csv")
CAMPOS = ["origem_uf", "origem_cidade", "destino_uf", "destino_cidade", "grupo", "base",
          "cep_consultado", "preco_pac_300g", "consultado_em"]
SAIDA_PRAZOS = os.path.join(app.TARIFAS_DIR, "prazos.csv")
CAMPOS_PRAZOS = ["origem_uf", "origem_cidade", "destino_uf", "destino_cidade", "servico", "prazo",
                 "cep_consultado", "consultado_em"]
SERVICOS_PRAZO = ("PAC", "SEDEX")


def enquadramento_por_preco():
    """preco do PAC 0-300 g -> (grupo, base). Local e Estadual custam o mesmo
    nas duas bases, entao ficam como INTERIOR."""
    mapa = {}
    with open(os.path.join(app.TARIFAS_DIR, "precos_vista.csv"), encoding="utf-8-sig", newline="") as arquivo:
        for r in csv.DictReader(arquivo):
            if r["servico"] == "PAC" and r["peso_min"] == "0":
                chave = f"{float(r['preco']):.2f}"
                if chave not in mapa or r["base"] == "INTERIOR":
                    mapa[chave] = (r["grupo"], r["base"])
    return mapa


def cidades_destino():
    """(uf, cidade, cep) com um CEP de cada cidade da base cepx."""
    cepx = sqlite3.connect(f"file:{app.CEPX_DB}?mode=ro", uri=True)
    linhas = cepx.execute("""SELECT u.sigla, c.nome, MIN(z.cep) FROM ceps z JOIN states u ON u.id=z.uf_id
                             JOIN cities c ON c.id=z.city_id GROUP BY z.uf_id, z.city_id ORDER BY u.sigla, c.nome""").fetchall()
    cepx.close()
    return [(uf, cidade, f"{cep:08d}") for uf, cidade, cep in linhas]


def consultar_pac(token, origem, destino):
    params = {"cepOrigem": origem, "cepDestino": destino, "psObjeto": "300", "tpObjeto": "2",
              "comprimento": "16", "largura": "11", "altura": "2"}
    url = (f"https://api.correios.com.br/preco/v1/nacional/{app.SERVICOS_A_VISTA['PAC']}?"
           + urllib.parse.urlencode(params))
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resposta:
        dados = json.loads(resposta.read())
    valor = dados.get("pcFinal") or dados.get("pcBaseGeral")
    return f"{float(str(valor).replace(',', '.')):.2f}" if valor is not None else None


class Sessao:
    """Token da API reaproveitado entre consultas, renovado quando expira."""

    def __init__(self):
        self.token = app.token_correios()

    def consultar(self, funcao, rotulo):
        """Chama funcao(token) com ate 3 tentativas; None se nao der."""
        for _ in range(3):
            try:
                return funcao(self.token)
            except urllib.error.HTTPError as exc:
                if exc.code == 401:
                    self.token = app.token_correios()
                elif exc.code == 429:
                    time.sleep(30)
                else:
                    print(f"  {rotulo}: {app.detalhe_erro_correios(exc)}")
                    return None
            except RuntimeError as exc:
                # prazo_api converte HTTPError em RuntimeError("HTTP 401: ...")
                if str(exc).startswith("HTTP 401"):
                    self.token = app.token_correios()
                elif str(exc).startswith("HTTP 429"):
                    time.sleep(30)
                else:
                    print(f"  {rotulo}: {exc}")
                    return None
            except Exception as exc:
                print(f"  {rotulo}: {exc}")
                time.sleep(5)
        return None


def ja_feitas(caminho, origem_uf, origem_cidade, chave, valida):
    if not os.path.exists(caminho):
        return set()
    with open(caminho, encoding="utf-8-sig", newline="") as arquivo:
        return {chave(r) for r in csv.DictReader(arquivo)
                if r["origem_uf"] == origem_uf and r["origem_cidade"] == origem_cidade and valida(r)}


def montar_enquadramento(origem_cep, origem_uf, origem_cidade, limite, intervalo):
    mapa = enquadramento_por_preco()
    feitas = ja_feitas(SAIDA, origem_uf, origem_cidade, lambda r: (r["destino_uf"], r["destino_cidade"]),
                       lambda r: r["grupo"] != "?")
    pendentes = [c for c in cidades_destino() if (c[0], c[1]) not in feitas]
    if limite:
        pendentes = pendentes[:limite]
    print(f"Origem {origem_cidade}/{origem_uf} ({origem_cep}): {len(feitas)} ja feitas, {len(pendentes)} a consultar.")

    novo = not os.path.exists(SAIDA)
    sessao, erros = Sessao(), 0
    with open(SAIDA, "a", encoding="utf-8", newline="") as arquivo:
        escritor = csv.DictWriter(arquivo, fieldnames=CAMPOS)
        if novo:
            escritor.writeheader()
        for i, (uf, cidade, cep) in enumerate(pendentes, 1):
            preco = sessao.consultar(lambda token: consultar_pac(token, origem_cep, cep), f"{cidade}/{uf} {cep}")
            grupo, base = mapa.get(preco, ("?", ""))
            if grupo == "?":
                erros += 1
            escritor.writerow({"origem_uf": origem_uf, "origem_cidade": origem_cidade, "destino_uf": uf,
                               "destino_cidade": cidade, "grupo": grupo, "base": base, "cep_consultado": cep,
                               "preco_pac_300g": preco or "", "consultado_em": datetime.now().isoformat(timespec="seconds")})
            arquivo.flush()
            if i % 100 == 0 or i == len(pendentes):
                print(f"  {i}/{len(pendentes)} consultadas; {erros} sem enquadramento")
            time.sleep(intervalo)
    print(f"Concluido. Arquivo: {SAIDA}")


def montar_prazos(origem_cep, origem_uf, origem_cidade, limite, intervalo):
    feitas = ja_feitas(SAIDA_PRAZOS, origem_uf, origem_cidade,
                       lambda r: (r["destino_uf"], r["destino_cidade"], r["servico"]), lambda r: bool(r["prazo"]))
    pendentes = [c for c in cidades_destino() if any((c[0], c[1], s) not in feitas for s in SERVICOS_PRAZO)]
    if limite:
        pendentes = pendentes[:limite]
    print(f"Prazos a partir de {origem_cidade}/{origem_uf} ({origem_cep}): {len(pendentes)} cidade(s) a consultar.")

    novo = not os.path.exists(SAIDA_PRAZOS)
    sessao, erros = Sessao(), 0
    with open(SAIDA_PRAZOS, "a", encoding="utf-8", newline="") as arquivo:
        escritor = csv.DictWriter(arquivo, fieldnames=CAMPOS_PRAZOS)
        if novo:
            escritor.writeheader()
        for i, (uf, cidade, cep) in enumerate(pendentes, 1):
            for servico in SERVICOS_PRAZO:
                if (uf, cidade, servico) in feitas:
                    continue
                prazo = sessao.consultar(lambda token: app.prazo_api(servico, origem_cep, cep, token=token),
                                         f"{cidade}/{uf} {cep} {servico}")
                if not prazo:
                    erros += 1
                escritor.writerow({"origem_uf": origem_uf, "origem_cidade": origem_cidade, "destino_uf": uf,
                                   "destino_cidade": cidade, "servico": servico, "prazo": prazo or "",
                                   "cep_consultado": cep, "consultado_em": datetime.now().isoformat(timespec="seconds")})
                arquivo.flush()
                time.sleep(intervalo)
            if i % 100 == 0 or i == len(pendentes):
                print(f"  {i}/{len(pendentes)} cidades; {erros} prazo(s) sem resposta")
    print(f"Concluido. Arquivo: {SAIDA_PRAZOS}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("cep_origem")
    parser.add_argument("--prazos", action="store_true", help="monta prazos.csv (PAC e SEDEX) em vez do enquadramento")
    parser.add_argument("--limite", type=int, default=0, help="consulta so as N primeiras cidades pendentes")
    parser.add_argument("--intervalo", type=float, default=0.5, help="segundos entre consultas")
    args = parser.parse_args()

    origem_cep = "".join(filter(str.isdigit, args.cep_origem))
    origem = app.localidade_cep(origem_cep)
    if not origem:
        raise SystemExit(f"CEP de origem {origem_cep} nao encontrado na base cepx.")
    origem_uf, _, origem_cidade = origem
    montar = montar_prazos if args.prazos else montar_enquadramento
    montar(origem_cep, origem_uf, origem_cidade, args.limite, args.intervalo)


if __name__ == "__main__":
    main()
