"""Varre os arquivos do repositório com o motor de PII antes de um commit.

Bloqueia o commit se encontrar chave de API, token, senha ou dado pessoal que não esteja na lista de
dados fictícios do projeto, ou se o arquivo `.env` estiver sendo versionado.

    python scripts/verificar_segredos.py            # todos os arquivos versionados ou novos
    python scripts/verificar_segredos.py --staged   # só o que está no commit (usado pelo hook)
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from app.pii.motor import motor  # noqa: E402
from app.pii.regras import Categoria  # noqa: E402
from app.pii.validadores import digitos  # noqa: E402
from auditoria.dados_sinteticos import CARLOS, JOANA  # noqa: E402

# Dados fictícios do projeto e o exemplo do enunciado podem aparecer em código, testes e documentação.
PERMITIDOS = {v for pessoa in (JOANA, CARLOS) for v in pessoa.values()} | {"123.456.789-00", "12.345.678-9"}
PERMITIDOS_NORMALIZADOS = {digitos(v) for v in PERMITIDOS if len(digitos(v)) >= 8} | {v.lower() for v in PERMITIDOS}
PASTAS_SINTETICAS = ("tests/", "auditoria/")  # dados fictícios de teste e evidências da auditoria
PASTA_DE_TESTES = "tests/"
DOMINIOS_FICTICIOS = ("@example.com", ".example.com", "@exemplo.com", ".exemplo.com")
ARQUIVOS_DE_CODIGO = {".py", ".js", ".html", ".css", ".sh"}
# Em código, "senha: str" é anotação de tipo; o que importa é senha escrita direto no código.
SEGREDO_NO_CODIGO = re.compile(
    r"(?i)\b(senha|password|secret|segredo|api_key|chave_api|token)\w*\s*=\s*[\"']([^\"'\s]{6,})[\"']")
MARCADOR = "pii-ok"  # comentário para exemplos documentados de propósito
EXTENSOES_TEXTO = {".py", ".md", ".txt", ".json", ".toml", ".cfg", ".ini", ".yml", ".yaml", ".html", ".js", ".css",
                   ".sh", ".env", ".example", ""}


def _git(*argumentos: str) -> str:
    return subprocess.run(["git", *argumentos], cwd=RAIZ, capture_output=True, text=True, check=True).stdout


def arquivos(staged: bool) -> list[str]:
    if staged:
        return [a for a in _git("diff", "--cached", "--name-only", "--diff-filter=ACM").splitlines() if a]
    return [a for a in _git("ls-files", "--cached", "--others", "--exclude-standard").splitlines() if a]


def conteudo(caminho: str, staged: bool) -> str | None:
    if Path(caminho).suffix not in EXTENSOES_TEXTO and not caminho.endswith(".example"):
        return None
    try:
        return _git("show", f":{caminho}") if staged else (RAIZ / caminho).read_text(encoding="utf-8")
    except (subprocess.CalledProcessError, UnicodeDecodeError, FileNotFoundError):
        return None


def permitido(valor: str, regra_categoria: Categoria, caminho: str) -> bool:
    if regra_categoria == Categoria.CREDENCIAL:
        return caminho.startswith(PASTA_DE_TESTES)  # chaves falsas usadas nos testes do motor
    if caminho.startswith(PASTAS_SINTETICAS) or valor.lower().endswith(DOMINIOS_FICTICIOS):
        return True
    return valor.lower() in PERMITIDOS_NORMALIZADOS or digitos(valor) in PERMITIDOS_NORMALIZADOS


def verificar(staged: bool) -> int:
    problemas: list[str] = []
    lista = arquivos(staged)
    for caminho in lista:
        if Path(caminho).name == ".env":
            problemas.append(f"{caminho}: o arquivo .env não pode ser versionado")
            continue
        texto = conteudo(caminho, staged)
        if texto is None:
            continue
        codigo = Path(caminho).suffix in ARQUIVOS_DE_CODIGO
        for numero, linha in enumerate(texto.splitlines(), 1):
            if MARCADOR in linha:
                continue
            for achado in motor.analisar_texto(linha):
                if codigo and achado.regra.id == "senha":
                    continue
                if not permitido(achado.valor, achado.categoria, caminho):
                    problemas.append(f"{caminho}:{numero}: {achado.regra.nome} ({achado.mascarado})")
            if codigo and not caminho.startswith(PASTAS_SINTETICAS):
                for match in SEGREDO_NO_CODIGO.finditer(linha):
                    if match.group(2) not in PERMITIDOS:
                        problemas.append(f"{caminho}:{numero}: segredo escrito no código ({match.group(1)}=***)")
    if problemas:
        print("Commit bloqueado: possíveis segredos ou dados pessoais encontrados:")
        print("\n".join(f"  - {p}" for p in problemas))
        return 1
    print(f"Verificação de segredos: {len(lista)} arquivo(s) sem segredos nem dados pessoais reais.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--staged", action="store_true")
    sys.exit(verificar(parser.parse_args().staged))
