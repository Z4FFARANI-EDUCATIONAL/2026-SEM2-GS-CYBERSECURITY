"""Login, sessões e detecção de tentativas repetidas de senha."""

from __future__ import annotations

import secrets
import time

from fastapi import HTTPException, status

from app import banco
from app.seguranca import cripto, eventos
from app.taint.contexto import ContextoTaint, atual

DURACAO_SESSAO = 8 * 3600
JANELA_TENTATIVAS = 10 * 60
LIMITE_TENTATIVAS = 5


def criar_sessao(cidadao_id: int) -> str:
    token = secrets.token_urlsafe(32)
    banco.executar(
        "INSERT INTO sessoes (token_hash, cidadao_id, expira_em) VALUES (?, ?, ?)",
        (cripto.hash_token(token), cidadao_id, time.time() + DURACAO_SESSAO),
    )
    return token


def sessao_por_token(token: str) -> dict | None:
    return banco.consultar_um(
        "SELECT c.id AS cidadao_id, c.perfil FROM sessoes s JOIN cidadaos c ON c.id = s.cidadao_id "
        "WHERE s.token_hash = ? AND s.expira_em > ?",
        (cripto.hash_token(token), time.time()),
    )


def encerrar_sessao(token: str) -> None:
    banco.executar("DELETE FROM sessoes WHERE token_hash = ?", (cripto.hash_token(token),))


def registrar_falha(indice: str, titular_id: int | None) -> None:
    agora = time.time()
    banco.executar("INSERT INTO tentativas_login (indice, momento) VALUES (?, ?)", (indice, agora))
    falhas = banco.consultar_um(
        "SELECT COUNT(*) AS n FROM tentativas_login WHERE indice = ? AND momento > ?",
        (indice, agora - JANELA_TENTATIVAS),
    )["n"]
    if falhas >= LIMITE_TENTATIVAS and falhas % LIMITE_TENTATIVAS == 0:
        eventos.registrar(
            "LOGIN_SUSPEITO", sink="login", decisao="monitorado", categorias_extra=["credencial"],
            detalhe=f"{falhas} tentativas de senha erradas na mesma conta em {JANELA_TENTATIVAS // 60} minutos.",
            titular_id=titular_id,
        )


def limpar_falhas(indice: str) -> None:
    banco.executar("DELETE FROM tentativas_login WHERE indice = ?", (indice,))


# --- dependências do FastAPI ------------------------------------------------------------------

def exigir_login() -> ContextoTaint:
    ctx = atual()
    if ctx is None or not ctx.autenticado:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Entre na sua conta para continuar.")
    return ctx


def exigir_gestor() -> ContextoTaint:
    ctx = exigir_login()
    if ctx.perfil != "gestor":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Área restrita à equipe do AJA.")
    return ctx
