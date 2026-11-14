"""AJA · API com o módulo de segurança de dados pessoais (PII, taint analysis e Risco Cidadão).

Executar:  uvicorn app.main:app --reload
Swagger:   http://127.0.0.1:8000/docs
Dashboard: http://127.0.0.1:8000/painel/
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app import config
from app.rotas import cidadaos, painel, relatos
from app.seguranca import eventos
from app.taint import logs
from app.taint.middleware import MiddlewareTaint
from app.taint.sinks import categorias, inspecionar, titular_principal

PASTA_ESTATICA = Path(__file__).parent / "static"


@asynccontextmanager
async def ciclo_de_vida(_: FastAPI):
    logs.instalar(config.obter().caminho_log)  # de novo: o uvicorn cria handlers depois da importação
    cidadaos.garantir_gestor()
    yield


def criar_app() -> FastAPI:
    cfg = config.obter()
    logs.instalar(cfg.caminho_log)

    app = FastAPI(
        title="AJA · Segurança de dados pessoais",
        version="1.0.0",
        description=(
            "API do AJA, plataforma de participação cidadã para acessibilidade no Parque Doroteia (SP), "
            "com motor de parsing de PII, taint analysis das saídas e tradução de eventos de segurança "
            "via IA para o dashboard de Risco Cidadão."
        ),
        lifespan=ciclo_de_vida,
    )
    app.add_middleware(MiddlewareTaint)

    @app.exception_handler(RequestValidationError)
    async def erro_de_validacao(request: Request, erro: RequestValidationError):
        # O padrão do FastAPI devolve o campo "input" com o valor recebido. Num CPF inválido,
        # isso repetiria o CPF (e às vezes a senha) na resposta. A guarda retira esses campos.
        erros = erro.errors()
        devolvidos = json.dumps([e.get("input") for e in erros], ensure_ascii=False, default=str)
        deteccoes = inspecionar(devolvidos)
        evento_id = None
        if deteccoes:
            ctx = request.scope.get("state", {}).get("contexto_taint")
            evento_id = eventos.registrar(
                "ERRO_SANITIZADO", sink="erro:validacao", deteccoes=deteccoes, decisao="mascarado",
                detalhe=(f"Erro 422 em {request.method} {request.url.path} devolveria "
                         f"{', '.join(categorias(deteccoes))} no campo 'input' da validação; campo removido."),
                titular_id=titular_principal(deteccoes) or (ctx.cidadao_id if ctx else None),
            )
        return JSONResponse(status_code=422, content={
            "erro": "dados_invalidos",
            "mensagem": "Alguns dados não estão no formato esperado.",
            "campos": [{"campo": ".".join(str(p) for p in e["loc"][1:]), "problema": e["msg"]} for e in erros],
            "evento_id": evento_id,
        })

    app.include_router(cidadaos.router)
    app.include_router(relatos.router)
    app.include_router(painel.router)
    app.mount("/painel", StaticFiles(directory=PASTA_ESTATICA, html=True), name="painel")

    @app.get("/", include_in_schema=False)
    def inicio():
        return RedirectResponse("/painel/")

    return app


app = criar_app()
