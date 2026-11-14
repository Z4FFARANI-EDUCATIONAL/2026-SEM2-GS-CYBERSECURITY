"""Auditoria do protótipo: ataques e erros simulados contra a API do AJA em execução.

Cada cenário envia uma requisição real, confere a resposta e procura evidências no log e no banco.
No fim, varre o arquivo de log e o banco SQLite atrás de qualquer dado pessoal em texto claro e
gera o relatório `auditoria/RELATORIO_AUDITORIA.md`.

Uso (com a API rodando em outro terminal):
    python -m auditoria.simular_ataques            # execução rápida
    python -m auditoria.simular_ataques --ao-vivo  # com pausas, para acompanhar no dashboard
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import httpx
from pypdf import PdfReader

from app import config
from auditoria.dados_sinteticos import CARLOS, JOANA, LOCAL, VALORES_PROIBIDOS

RAIZ = Path(__file__).resolve().parent
VERDE, VERMELHO, AZUL, CINZA, FIM = "\033[92m", "\033[91m", "\033[94m", "\033[90m", "\033[0m"


@dataclass
class Cenario:
    codigo: str
    titulo: str
    source: str
    sink: str
    esperado: str
    obtido: str = ""
    passou: bool = False
    evidencias: list[str] = field(default_factory=list)


class Auditoria:
    def __init__(self, url: str, pausa: float) -> None:
        self.http = httpx.Client(base_url=url, timeout=60)
        self.pausa = pausa
        self.cenarios: list[Cenario] = []
        cfg = config.obter()
        self.caminho_log = cfg.caminho_log
        self.caminho_banco = cfg.caminho_banco
        self.cfg = cfg
        self.inicio_log = self.caminho_log.stat().st_size if self.caminho_log.exists() else 0

    # --- utilidades -----------------------------------------------------------------------

    def novas_linhas_de_log(self) -> list[str]:
        time.sleep(0.3)
        with open(self.caminho_log, encoding="utf-8") as arquivo:
            arquivo.seek(self.inicio_log)
            linhas = arquivo.read().splitlines()
        self.inicio_log = self.caminho_log.stat().st_size
        return linhas

    def entrar(self, login: str, senha: str) -> dict:
        resposta = self.http.post("/api/v1/auth/login", json={"login": login, "senha": senha})
        resposta.raise_for_status()
        return {"Authorization": f"Bearer {resposta.json()['token']}"}

    def registrar(self, cenario: Cenario, passou: bool, obtido: str, *evidencias: str) -> None:
        cenario.passou, cenario.obtido = passou, obtido
        cenario.evidencias.extend(e for e in evidencias if e)
        self.cenarios.append(cenario)
        marca = f"{VERDE}PASSOU{FIM}" if passou else f"{VERMELHO}FALHOU{FIM}"
        print(f"  [{marca}] {cenario.codigo} {cenario.titulo}")
        print(f"         {CINZA}source: {cenario.source} -> sink: {cenario.sink}{FIM}")
        print(f"         {CINZA}obtido: {obtido}{FIM}")
        if self.pausa:
            time.sleep(self.pausa)

    def secao(self, titulo: str) -> None:
        print(f"\n{AZUL}== {titulo} =={FIM}")

    # --- cenários -------------------------------------------------------------------------

    def preparar(self) -> None:
        self.secao("Preparação")
        gestor = self.entrar(self.cfg.gestor_email, self.cfg.gestor_senha)
        self.http.post("/api/v1/painel/demo/reiniciar", headers=gestor).raise_for_status()
        self.gestor = gestor
        self.novas_linhas_de_log()
        print("  Base de demonstração limpa; farol começa no verde.")
        if self.pausa:
            time.sleep(self.pausa)

    def c01_cadastro_log_ingenuo(self) -> None:
        c = Cenario("C01", "Cadastro com log de depuração ingênuo (logger.info do payload inteiro)",
                    "POST /api/v1/cidadaos (corpo JSON)", "log (arquivo logs/aja.log)",
                    "CPF, senha, saúde e endereço mascarados no log; resposta só com dados mascarados")
        r1 = self.http.post("/api/v1/cidadaos", json=JOANA)
        r2 = self.http.post("/api/v1/cidadaos", json=CARLOS)
        self.joana_id, self.carlos_id = r1.json()["id"], r2.json()["id"]
        linhas = [l for l in self.novas_linhas_de_log() if "Novo cadastro" in l]
        limpo = all(v not in l for l in linhas for v in VALORES_PROIBIDOS)
        bloqueado = any("guarda de taint" in l for l in linhas)
        resposta_ok = JOANA["cpf"] not in r1.text and "***.982.***-25" in r1.text
        self.registrar(c, r1.status_code == 201 and limpo and bloqueado and resposta_ok,
                       f"HTTP {r1.status_code}; linha de log mascarada: {bloqueado}; resposta: {r1.json()['cpf']}",
                       "Linha gravada no log:\n" + (linhas[0] if linhas else "(nenhuma)"),
                       "Resposta HTTP:\n" + json.dumps(r1.json(), ensure_ascii=False, indent=2))

    def c02_validacao_ecoa_cpf(self) -> None:
        c = Cenario("C02", "CPF inválido: o erro 422 padrão do FastAPI devolveria o valor recebido",
                    "POST /api/v1/cidadaos (CPF com dígito errado)", "erro (resposta 422)",
                    "Resposta 422 sem o CPF nem a senha enviados")
        invalido = {**JOANA, "cpf": "123.456.789-00", "email": "outra@example.com"}
        r = self.http.post("/api/v1/cidadaos", json=invalido)
        limpo = "123.456.789-00" not in r.text and JOANA["senha"] not in r.text
        self.registrar(c, r.status_code == 422 and limpo, f"HTTP {r.status_code}; CPF ausente da resposta: {limpo}",
                       "Resposta HTTP:\n" + json.dumps(r.json(), ensure_ascii=False, indent=2))

    def c03_cpf_na_url(self) -> None:
        c = Cenario("C03", "CPF na URL (?cpf=) chega ao log de acesso do servidor",
                    "GET /api/v1/cidadaos/busca?cpf=… (query string)", "log (uvicorn.access)",
                    "Linha de acesso gravada com o CPF mascarado")
        r = self.http.get("/api/v1/cidadaos/busca", params={"cpf": "52998224725"}, headers=self.gestor)
        linhas = [l for l in self.novas_linhas_de_log() if "/cidadaos/busca" in l]
        limpo = linhas and all("52998224725" not in l for l in linhas)
        self.registrar(c, r.status_code == 200 and bool(limpo), f"HTTP {r.status_code}; log de acesso sem o CPF: {bool(limpo)}",
                       "Linha de acesso gravada:\n" + (linhas[-1] if linhas else "(nenhuma)"))

    def c04_relato_com_pii(self) -> None:
        c = Cenario("C04", "Relato público com CPF, telefone, autodeclaração de saúde e assinatura",
                    "POST /api/v1/relatos (texto livre)", "banco + página pública do tópico",
                    "Texto publicado sem os dados pessoais; evento para a autora")
        self.joana = self.entrar(JOANA["email"], JOANA["senha"])
        texto = ("Sou cega e o piso tátil acaba antes da banca, a bengala perde a guia. Me liga no "
                 "(11) 90000-0001 ou procure pelo CPF 529.982.247-25. Obrigada, Joana Exemplo da Silva")
        r = self.http.post("/api/v1/relatos", headers=self.joana, json={
            "descricao": texto, "categoria": "piso_tatil", "local_referencia": LOCAL, "publico_afetado": "visual"})
        publicado = r.json().get("descricao_publicada", "")
        self.topico_id = r.json().get("topico_id")
        limpo = all(v not in publicado for v in VALORES_PROIBIDOS) and "cega" not in publicado
        self.registrar(c, r.status_code == 201 and limpo, f"HTTP {r.status_code}; texto publicado limpo: {limpo}",
                       f"Enviado:\n{texto}", f"Publicado:\n{publicado}")

    def c05_relato_cita_outra_pessoa(self) -> None:
        c = Cenario("C05", "Relato que cita pelo nome outra pessoa que já relatou no tópico",
                    "POST /api/v1/relatos + identidade dos co-autores lida do banco", "página pública do tópico",
                    "Nome da outra pessoa mascarado, mesmo sem frase do tipo 'meu nome é'")
        self.carlos = self.entrar(CARLOS["cpf"], CARLOS["senha"])
        texto = "Confirmo: tropecei ali ontem. Piso tátil para pessoas cegas termina do nada. Falei com a Joana Silva sobre isso."
        r = self.http.post("/api/v1/relatos", headers=self.carlos, json={
            "descricao": texto, "categoria": "piso_tatil", "local_referencia": LOCAL, "publico_afetado": "visual"})
        publicado = r.json().get("descricao_publicada", "")
        self.registrar(c, r.status_code == 201 and "Joana Silva" not in publicado and "pessoas cegas" in publicado,
                       f"HTTP {r.status_code}; nome citado mascarado e público-alvo preservado",
                       f"Enviado:\n{texto}", f"Publicado:\n{publicado}")

    def c06_rota_legada_sem_login(self) -> None:
        c = Cenario("C06", "Rota legada sem controle de acesso, chamada sem login",
                    "banco (perfil decifrado da cidadã)", "resposta HTTP não autenticada",
                    "Resposta trocada por 403 pela guarda; nada do perfil sai")
        r = self.http.get(f"/api/v1/legado/cidadaos/{self.joana_id}")
        limpo = all(v not in r.text for v in VALORES_PROIBIDOS)
        self.registrar(c, r.status_code == 403 and limpo, f"HTTP {r.status_code}; corpo sem PII: {limpo}",
                       "Resposta HTTP:\n" + json.dumps(r.json(), ensure_ascii=False, indent=2))

    def c07_idor(self) -> None:
        c = Cenario("C07", "Outro cidadão logado pede o perfil da Joana (IDOR)",
                    "banco (perfil decifrado, titular = Joana)", "resposta HTTP para outro titular",
                    "403: o dado tem dono e quem pede não é o dono")
        r = self.http.get(f"/api/v1/legado/cidadaos/{self.joana_id}", headers=self.carlos)
        self.registrar(c, r.status_code == 403 and JOANA["cpf"] not in r.text, f"HTTP {r.status_code}",
                       "Resposta HTTP:\n" + json.dumps(r.json(), ensure_ascii=False, indent=2))

    def c08_dono_acessa(self) -> None:
        c = Cenario("C08", "Controle positivo: a própria Joana pede o seu perfil",
                    "banco (perfil decifrado, titular = Joana)", "resposta HTTP para o titular",
                    "200 com os dados completos (a guarda não bloqueia o dono)")
        r = self.http.get(f"/api/v1/legado/cidadaos/{self.joana_id}", headers=self.joana)
        self.registrar(c, r.status_code == 200 and r.json().get("cpf") == JOANA["cpf"],
                       f"HTTP {r.status_code}; dados devolvidos ao titular", "")

    def c09_gravacao_sem_criptografia(self) -> None:
        c = Cenario("C09", "Código legado tenta gravar telefone em texto claro no banco",
                    "POST /api/v1/legado/cidadaos/{id}/contato (corpo JSON)", "banco (tabela contatos_legado)",
                    "INSERT impedido pela guarda; tabela continua vazia")
        r = self.http.post(f"/api/v1/legado/cidadaos/{self.joana_id}/contato", json={"telefone": JOANA["telefone"]})
        with sqlite3.connect(f"file:{self.caminho_banco}?mode=ro", uri=True) as conexao:
            linhas = conexao.execute("SELECT COUNT(*) FROM contatos_legado").fetchone()[0]
        self.registrar(c, r.status_code == 403 and linhas == 0, f"HTTP {r.status_code}; linhas gravadas: {linhas}",
                       "Resposta HTTP:\n" + json.dumps(r.json(), ensure_ascii=False, indent=2))

    def c10_forca_bruta(self) -> None:
        c = Cenario("C10", "Ataque de força bruta: 5 senhas erradas seguidas na conta da Joana",
                    "POST /api/v1/auth/login", "login",
                    "Evento LOGIN_SUSPEITO e farol da Joana em vermelho (padrão de ataque)")
        for tentativa in range(5):
            self.http.post("/api/v1/auth/login", json={"login": JOANA["cpf"], "senha": f"chute-{tentativa}-1234"})
        time.sleep(0.5)
        painel = self.http.get("/api/v1/painel/cidadao", headers=self.joana).json()
        tipos = [a["tipo"] for a in painel["alertas"]]
        self.registrar(c, "LOGIN_SUSPEITO" in tipos and painel["risco"]["nivel"] == "vermelho",
                       f"farol da Joana: {painel['risco']['nivel']} (índice {painel['risco']['indice']})",
                       "Risco da Joana:\n" + json.dumps(painel["risco"], ensure_ascii=False, indent=2))

    def c11_dossie(self) -> None:
        c = Cenario("C11", "Dossiê em PDF para a Prefeitura cujo modelo cita o nome de quem relatou",
                    "banco (nome decifrado dos autores)", "dossiê PDF enviado ao órgão público",
                    "PDF sem nome, CPF ou contato; relatores aparecem como Morador(a) A e B")
        r = self.http.get(f"/api/v1/topicos/{self.topico_id}/dossie")
        saida = RAIZ / "saida"
        saida.mkdir(exist_ok=True)
        (saida / "dossie_exemplo.pdf").write_bytes(r.content)
        texto = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(r.content)).pages)
        nomes = ["Joana", "Carlos", "Pereira", "Exemplo da Silva"]
        limpo = all(v not in texto for v in VALORES_PROIBIDOS) and not any(n in texto for n in nomes)
        trecho = texto[texto.find("2. Relatos"):texto.find("3. Contexto")].strip() if "2. Relatos" in texto else texto[:400]
        self.registrar(c, r.status_code == 200 and limpo and "Morador(a) A" in texto,
                       f"HTTP {r.status_code}; PDF sem identidade: {limpo}", "Trecho do PDF:\n" + trecho)

    # --- varredura final ------------------------------------------------------------------

    def varredura_final(self) -> dict:
        self.secao("Varredura final em repouso (log + banco)")
        log_texto = self.caminho_log.read_text(encoding="utf-8")
        achados_log = [v for v in VALORES_PROIBIDOS if v in log_texto]
        achados_banco = []
        with sqlite3.connect(f"file:{self.caminho_banco}?mode=ro", uri=True) as conexao:
            tabelas = [t[0] for t in conexao.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            for tabela in tabelas:
                for linha in conexao.execute(f"SELECT * FROM {tabela}"):
                    conteudo = " ".join(str(c) for c in linha if isinstance(c, str))
                    achados_banco += [f"{tabela}: {v}" for v in VALORES_PROIBIDOS if v.lower() in conteudo.lower()]
        print(f"  log: {len(achados_log)} ocorrência(s) | banco: {len(achados_banco)} ocorrência(s)")
        return {"log": achados_log, "banco": achados_banco, "valores_testados": len(VALORES_PROIBIDOS)}

    # --- relatório ------------------------------------------------------------------------

    def relatorio(self, varredura: dict, executivo: dict) -> Path:
        passou = sum(c.passou for c in self.cenarios)
        linhas = [
            "# Relatório de auditoria do protótipo",
            "",
            f"Gerado em {datetime.now().strftime('%d/%m/%Y %H:%M:%S')} por `python -m auditoria.simular_ataques`.",
            "Todos os dados usados são fictícios (ver `auditoria/dados_sinteticos.py`).",
            "",
            f"**Resultado: {passou} de {len(self.cenarios)} cenários aprovados.**",
            "",
            "| # | Cenário | Source | Sink | Esperado | Resultado |",
            "|---|---|---|---|---|---|",
        ]
        for c in self.cenarios:
            linhas.append(f"| {c.codigo} | {c.titulo} | {c.source} | {c.sink} | {c.esperado} | "
                          f"{'✅' if c.passou else '❌'} {c.obtido} |")
        linhas += ["", "## Varredura em repouso", "",
                   f"O script procurou {varredura['valores_testados']} valores pessoais fictícios (CPF com e sem pontuação, "
                   "e-mail, senha, telefone, endereço e nome) em todo o arquivo de log e em todas as tabelas do banco.",
                   "", f"- Ocorrências em texto claro no log: **{len(varredura['log'])}**",
                   f"- Ocorrências em texto claro no banco: **{len(varredura['banco'])}**", ""]
        risco = executivo["risco"]
        linhas += ["## Indicador de Risco Cidadão ao fim da auditoria", "",
                   f"- Índice geral: **{risco['indice']}/100** ({risco['rotulo']})",
                   f"- Eventos registrados: {executivo['totais']['eventos']} "
                   f"({executivo['totais']['bloqueados']} bloqueios, {executivo['totais']['mascarados']} mascaramentos)",
                   f"- Mensagens explicadas por IA: {executivo['totais']['traduzidos_por_ia']}", "",
                   "| Tipo de evento | Total |", "|---|---|"]
        linhas += [f"| {t['titulo']} (`{t['tipo']}`) | {t['total']} |" for t in executivo["por_tipo"]]
        linhas += ["", "## Evidências por cenário", ""]
        for c in self.cenarios:
            linhas += [f"### {c.codigo} · {c.titulo}", "", f"- **Source:** {c.source}", f"- **Sink:** {c.sink}",
                       f"- **Esperado:** {c.esperado}", f"- **Obtido:** {c.obtido}", ""]
            for evidencia in c.evidencias:
                linhas += ["```", evidencia, "```", ""]
        destino = RAIZ / "RELATORIO_AUDITORIA.md"
        destino.write_text("\n".join(linhas), encoding="utf-8")
        return destino

    def executar(self) -> int:
        self.preparar()
        self.secao("Sources e sinks")
        for passo in (self.c01_cadastro_log_ingenuo, self.c02_validacao_ecoa_cpf, self.c03_cpf_na_url,
                      self.c04_relato_com_pii, self.c05_relato_cita_outra_pessoa, self.c06_rota_legada_sem_login,
                      self.c07_idor, self.c08_dono_acessa, self.c09_gravacao_sem_criptografia,
                      self.c10_forca_bruta, self.c11_dossie):
            passo()
        varredura = self.varredura_final()
        # Espera as traduções em segundo plano terminarem (até 60 s) antes de fechar o relatório.
        for _ in range(60):
            executivo = self.http.get("/api/v1/painel/executivo", headers=self.gestor).json()
            if all(a["origem_mensagem"] != "pendente" for a in executivo["alertas"]):
                break
            time.sleep(1)
        destino = self.relatorio(varredura, executivo)
        aprovados = sum(c.passou for c in self.cenarios)
        limpo = not varredura["log"] and not varredura["banco"]
        print(f"\n{AZUL}Resultado:{FIM} {aprovados}/{len(self.cenarios)} cenários aprovados; "
              f"varredura em repouso {'limpa' if limpo else 'COM OCORRÊNCIAS'}.")
        print(f"Relatório: {destino.relative_to(RAIZ.parent)}")
        return 0 if aprovados == len(self.cenarios) and limpo else 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--ao-vivo", action="store_true", help="pausa entre os cenários para acompanhar no dashboard")
    parser.add_argument("--pausa", type=float, default=4.0, help="segundos de pausa no modo ao vivo")
    args = parser.parse_args()
    sys.exit(Auditoria(args.url, args.pausa if args.ao_vivo else 0).executar())


if __name__ == "__main__":
    main()
