"""Middleware interceptador: onde o taint começa (sources) e onde a resposta é conferida (sink).

Para cada requisição HTTP:
1. cria o `ContextoTaint` e identifica quem está logado;
2. **sources:** passa o corpo JSON ou de formulário, a query string e o cabeçalho Authorization
   pelo motor de PII e marca cada dado pessoal encontrado;
3. **sink "resposta":** antes de devolver a resposta, confere se ela leva dado pessoal que quem pediu
   não pode ver (sem login, ou dado de outro cidadão). Se levar, troca a resposta por 403;
4. **sink "erro":** uma exceção não tratada nunca mostra a mensagem técnica ao cliente. Ela é
   registrada no log, que tem a sua própria guarda, e o cliente recebe uma mensagem genérica.
"""

from __future__ import annotations

import json
import logging
from urllib.parse import parse_qsl

from app.pii.motor import motor
from app.pii.regras import REGRAS_POR_ID
from app.seguranca import auth, eventos
from app.taint.contexto import ContextoTaint, encerrar, iniciar
from app.taint.sinks import Deteccao, VazamentoBloqueado, categorias, inspecionar, sanear, titular_principal

log = logging.getLogger("aja.http")

MENSAGEM_BLOQUEIO = (
    "Esta resposta continha dados pessoais que você não tem permissão para ver. "
    "O acesso foi bloqueado e registrado."
)
MENSAGEM_ERRO = "Não foi possível concluir o pedido. Nenhum dado pessoal foi exposto."


def _cabecalho(scope, nome: bytes) -> str | None:
    for chave, valor in scope.get("headers", []):
        if chave.lower() == nome:
            return valor.decode("latin-1")
    return None


def _interpretar_corpo(corpo: bytes, tipo: str | None):
    if not corpo:
        return None
    tipo = (tipo or "").lower()
    texto = corpo.decode("utf-8", errors="replace")
    if "json" in tipo:
        try:
            return json.loads(texto)
        except ValueError:
            return texto
    if "x-www-form-urlencoded" in tipo:
        return dict(parse_qsl(texto))
    if tipo.startswith("text/"):
        return texto
    return None


def _json(status: int, dados: dict) -> tuple[int, bytes, list]:
    corpo = json.dumps(dados, ensure_ascii=False).encode("utf-8")
    cabecalhos = [(b"content-type", b"application/json; charset=utf-8"),
                  (b"content-length", str(len(corpo)).encode())]
    return status, corpo, cabecalhos


class MiddlewareTaint:
    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        ctx = ContextoTaint(metodo=scope["method"], rota=scope["path"])
        token_ctx = iniciar(ctx)
        try:
            corpo = await self._ler_corpo(receive)
            self._autenticar(ctx, scope)
            self._marcar_sources(ctx, scope, corpo)
            scope.setdefault("state", {})["contexto_taint"] = ctx

            entregue = False

            async def receber():
                nonlocal entregue
                if not entregue:
                    entregue = True
                    return {"type": "http.request", "body": corpo, "more_body": False}
                return await receive()

            await self._executar_com_guarda(ctx, scope, receber, send)
        finally:
            encerrar(token_ctx)

    @staticmethod
    async def _ler_corpo(receive) -> bytes:
        partes = []
        while True:
            mensagem = await receive()
            if mensagem["type"] != "http.request":
                break
            partes.append(mensagem.get("body", b""))
            if not mensagem.get("more_body"):
                break
        return b"".join(partes)

    @staticmethod
    def _autenticar(ctx: ContextoTaint, scope) -> None:
        autorizacao = _cabecalho(scope, b"authorization") or ""
        if not autorizacao.lower().startswith("bearer "):
            return
        token = autorizacao[7:].strip()
        # O próprio token é uma credencial: fica marcado para nunca sair em log ou resposta.
        ctx.marcar(token, REGRAS_POR_ID["token"], f"{ctx.metodo} {ctx.rota} header Authorization")
        sessao = auth.sessao_por_token(token)
        if sessao:
            ctx.autenticado = True
            ctx.cidadao_id = sessao["cidadao_id"]
            ctx.perfil = sessao["perfil"]
            for m in ctx.marcacoes:
                m.titular_id = ctx.cidadao_id

    @staticmethod
    def _marcar_sources(ctx: ContextoTaint, scope, corpo: bytes) -> None:
        fonte = f"{ctx.metodo} {ctx.rota}"
        dados = _interpretar_corpo(corpo, _cabecalho(scope, b"content-type"))
        if dados is not None:
            ctx.marcar_achados(motor.analisar(dados), f"{fonte} corpo")
        query = scope.get("query_string", b"").decode("utf-8", errors="replace")
        if query:
            ctx.marcar_achados(motor.analisar(dict(parse_qsl(query))), f"{fonte} query")

    async def _executar_com_guarda(self, ctx: ContextoTaint, scope, receive, send) -> None:
        inicio: dict | None = None
        partes: list[bytes] = []
        repassar = False
        iniciada = False

        async def enviar(mensagem):
            nonlocal inicio, repassar, iniciada
            if mensagem["type"] == "http.response.start":
                inicio = mensagem
                tipo = dict(mensagem.get("headers", [])).get(b"content-type", b"").decode().lower()
                # Dados (JSON, HTML, texto) são inspecionados; código estático (JS, CSS) e binários passam.
                repassar = not ("json" in tipo or tipo.startswith(("text/plain", "text/html")))
                if repassar:
                    iniciada = True
                    await send(mensagem)
                return
            if mensagem["type"] != "http.response.body":
                await send(mensagem)
                return
            if repassar:
                await send(mensagem)
                return
            partes.append(mensagem.get("body", b""))
            if mensagem.get("more_body"):
                return
            status, corpo, cabecalhos = self._guarda_resposta(ctx, inicio, b"".join(partes))
            iniciada = True
            await send({"type": "http.response.start", "status": status, "headers": cabecalhos})
            await send({"type": "http.response.body", "body": corpo})

        try:
            await self.app(scope, receive, enviar)
        except Exception as erro:
            if iniciada:
                raise
            await self._responder_erro(ctx, erro, send)

    @staticmethod
    def _guarda_resposta(ctx: ContextoTaint, inicio: dict, corpo: bytes) -> tuple[int, bytes, list]:
        status = inicio["status"]
        cabecalhos = [(k, v) for k, v in inicio.get("headers", []) if k.lower() != b"content-length"]
        texto = corpo.decode("utf-8", errors="replace")
        deteccoes = inspecionar(texto)
        if not deteccoes:
            return status, corpo, cabecalhos + [(b"content-length", str(len(corpo)).encode())]

        if status >= 400:
            # Sink "erro": a mensagem de erro repetiria o dado recebido. Mascara e mantém o status.
            saneado = sanear(texto, deteccoes).encode("utf-8")
            eventos.registrar(
                "ERRO_SANITIZADO", sink="erro:http", deteccoes=deteccoes, decisao="mascarado",
                detalhe=f"Resposta de erro {status} de {ctx.metodo} {ctx.rota} repetia {', '.join(categorias(deteccoes))}.",
                titular_id=titular_principal(deteccoes) or ctx.cidadao_id,
            )
            return status, saneado, cabecalhos + [(b"content-length", str(len(saneado)).encode())]

        proibidas: list[Deteccao] = [
            d for d in deteccoes
            if not (ctx.autenticado and d.titular_id is not None and d.titular_id == ctx.cidadao_id)
        ]
        if not proibidas:
            return status, corpo, cabecalhos + [(b"content-length", str(len(corpo)).encode())]

        motivo = "sem login" if not ctx.autenticado else f"pelo cidadão {ctx.cidadao_id}, que não é o titular"
        evento_id = eventos.registrar(
            "RESPOSTA_BLOQUEADA", sink="resposta:http", deteccoes=proibidas, decisao="bloqueado",
            detalhe=(f"Resposta {status} de {ctx.metodo} {ctx.rota} levaria "
                     f"{', '.join(categorias(proibidas))} {motivo}. Resposta trocada por 403."),
            titular_id=titular_principal(proibidas),
        )
        return _json(403, {"erro": "acesso_bloqueado", "mensagem": MENSAGEM_BLOQUEIO, "evento_id": evento_id})

    @staticmethod
    async def _responder_erro(ctx: ContextoTaint, erro: Exception, send) -> None:
        if isinstance(erro, VazamentoBloqueado):
            # Uma guarda (ex.: banco) já barrou e registrou o evento; o cliente só recebe o aviso.
            log.warning("Gravação bloqueada pela guarda de taint em %s %s: %s", ctx.metodo, ctx.rota, erro)
            status, corpo, cabecalhos = _json(403, {
                "erro": "gravacao_bloqueada",
                "mensagem": "O sistema impediu que um dado pessoal fosse guardado sem proteção.",
                "evento_id": erro.evento_id,
            })
            await send({"type": "http.response.start", "status": status, "headers": cabecalhos})
            await send({"type": "http.response.body", "body": corpo})
            return
        # O log tem guarda própria: se a mensagem da exceção trouxer PII, ela é mascarada lá.
        log.exception("Erro não tratado em %s %s: %s", ctx.metodo, ctx.rota, erro)
        evento_id = None
        deteccoes = inspecionar(str(erro))
        if deteccoes:
            evento_id = eventos.registrar(
                "ERRO_SANITIZADO", sink="erro:http", deteccoes=deteccoes, decisao="mascarado",
                detalhe=(f"Exceção {type(erro).__name__} em {ctx.metodo} {ctx.rota} trazia "
                         f"{', '.join(categorias(deteccoes))} na mensagem; o cliente recebeu mensagem genérica."),
                titular_id=titular_principal(deteccoes) or ctx.cidadao_id,
            )
        status, corpo, cabecalhos = _json(500, {"erro": "erro_interno", "mensagem": MENSAGEM_ERRO,
                                                "evento_id": evento_id})
        await send({"type": "http.response.start", "status": status, "headers": cabecalhos})
        await send({"type": "http.response.body", "body": corpo})
