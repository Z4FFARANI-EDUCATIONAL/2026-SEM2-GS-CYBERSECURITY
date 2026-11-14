"""Prepara o ambiente local: cria o .env com chaves novas e instala o hook de verificação de segredos.

    python scripts/configurar.py

As chaves de criptografia são geradas na hora e ficam só na sua máquina. A chave da API da
Anthropic é pedida no terminal (sem eco); deixe em branco para usar as mensagens padrão.
"""

from __future__ import annotations

import getpass
import secrets
import stat
from pathlib import Path

from cryptography.fernet import Fernet

RAIZ = Path(__file__).resolve().parent.parent
HOOK = """#!/bin/sh
# Bloqueia commits com segredos ou dados pessoais (gerado por scripts/configurar.py)
if command -v python3 >/dev/null 2>&1; then PY=python3; else PY=python; fi
exec "$PY" scripts/verificar_segredos.py --staged
"""


def criar_env() -> None:
    destino = RAIZ / ".env"
    if destino.exists():
        print(".env já existe; nada foi alterado.")
        return
    chave_api = getpass.getpass("Chave da API da Anthropic (Enter para pular): ").strip()
    senha_gestor = secrets.token_urlsafe(12)
    linhas = [
        f"ANTHROPIC_API_KEY={chave_api}",
        "AJA_LLM_MODELO=claude-haiku-5-5",
        f"AJA_CHAVE_CRIPTO={Fernet.generate_key().decode()}",
        f"AJA_CHAVE_INDICE={secrets.token_hex(32)}",
        "AJA_GESTOR_EMAIL=gestor@aja.exemplo.com",
        f"AJA_GESTOR_SENHA={senha_gestor}",
        "AJA_JANELA_RISCO_MIN=10",
        "AJA_MODO_DEMO=1",
    ]
    destino.write_text("\n".join(linhas) + "\n", encoding="utf-8")
    destino.chmod(stat.S_IRUSR | stat.S_IWUSR)
    print(".env criado. Login da equipe AJA no dashboard:")
    print(f"  e-mail: gestor@aja.exemplo.com\n  senha:  {senha_gestor}")


def instalar_hook() -> None:
    pasta = RAIZ / ".git" / "hooks"
    if not pasta.exists():
        return
    hook = pasta / "pre-commit"
    hook.write_text(HOOK, encoding="utf-8")
    hook.chmod(0o755)
    print("Hook pre-commit instalado: commits com segredos serão bloqueados.")


if __name__ == "__main__":
    criar_env()
    instalar_hook()
