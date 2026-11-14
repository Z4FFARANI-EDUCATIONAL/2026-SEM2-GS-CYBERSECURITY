"""Configuração do AJA lida de variáveis de ambiente.

Os valores sensíveis (chave da API do LLM e chaves de criptografia) ficam no arquivo `.env`,
que nunca vai para o Git. O `.env.example` mostra o formato sem nenhum segredo real.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent


def _carregar_arquivo_env(caminho: Path) -> None:
    """Lê `CHAVE=valor` do .env sem sobrescrever o que já está no ambiente."""
    if not caminho.exists():
        return
    for linha in caminho.read_text(encoding="utf-8").splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#") or "=" not in linha:
            continue
        chave, valor = linha.split("=", 1)
        os.environ.setdefault(chave.strip(), valor.strip().strip('"').strip("'"))


@dataclass(frozen=True)
class Config:
    chave_anthropic: str
    modelo_llm: str
    chave_cripto: str
    chave_indice: str
    gestor_email: str
    gestor_senha: str
    caminho_banco: Path
    caminho_log: Path
    janela_risco_min: float
    modo_demo: bool
    traducao_sincrona: bool


class ConfiguracaoAusente(RuntimeError):
    pass


@lru_cache(maxsize=1)
def obter() -> Config:
    _carregar_arquivo_env(RAIZ / ".env")
    faltando = [nome for nome in ("AJA_CHAVE_CRIPTO", "AJA_CHAVE_INDICE") if not os.getenv(nome)]
    if faltando:
        raise ConfiguracaoAusente(
            f"Variáveis ausentes: {', '.join(faltando)}. Rode `python scripts/configurar.py` "
            "para gerar o arquivo .env."
        )
    return Config(
        chave_anthropic=os.getenv("ANTHROPIC_API_KEY", ""),
        modelo_llm=os.getenv("AJA_LLM_MODELO", "claude-haiku-5-5"),
        chave_cripto=os.environ["AJA_CHAVE_CRIPTO"],
        chave_indice=os.environ["AJA_CHAVE_INDICE"],
        gestor_email=os.getenv("AJA_GESTOR_EMAIL", "gestor@aja.exemplo.com"),
        gestor_senha=os.getenv("AJA_GESTOR_SENHA", ""),
        caminho_banco=Path(os.getenv("AJA_BANCO", str(RAIZ / "dados" / "aja.db"))),
        caminho_log=Path(os.getenv("AJA_LOG", str(RAIZ / "logs" / "aja.log"))),
        janela_risco_min=float(os.getenv("AJA_JANELA_RISCO_MIN", "10")),
        modo_demo=os.getenv("AJA_MODO_DEMO", "1") == "1",
        traducao_sincrona=os.getenv("AJA_TRADUCAO_SINCRONA", "0") == "1",
    )


def redefinir() -> None:
    """Usado nos testes para reler o ambiente."""
    obter.cache_clear()
