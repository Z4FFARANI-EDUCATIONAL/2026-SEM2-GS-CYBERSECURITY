"""Sink "log": nenhum dado pessoal é gravado em texto claro nos registros do sistema.

Um `logging.Filter` é instalado em todos os handlers (console e arquivo, inclusive os do uvicorn).
Antes de cada linha ser escrita, a mensagem e o traceback passam pela inspeção de taint. Se houver
dado pessoal, o valor é trocado pela máscara, a linha recebe a marca da guarda e um evento
LOG_BLOQUEADO é registrado.

Exemplos barrados: `logger.info(dados_de_saude)`, `log.info("payload %s", corpo)`, o log de acesso do
uvicorn com `?cpf=...` na URL e uma exceção cuja mensagem repete o CPF recebido.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.pii.motor import motor
from app.taint.sinks import Deteccao, categorias, inspecionar, sanear, titular_principal

MARCA = "  [guarda de taint: dado pessoal bloqueado neste log]"
FORMATO = "%(asctime)s %(levelname)-7s %(name)s | %(message)s"


def _sanear_argumento(valor: Any) -> tuple[Any, list[Deteccao]]:
    if isinstance(valor, str):
        deteccoes = inspecionar(valor)
        return (sanear(valor, deteccoes), deteccoes) if deteccoes else (valor, [])
    if isinstance(valor, (dict, list, tuple)):
        texto = str(valor)
        deteccoes = inspecionar(texto)
        return (motor.mascarar(valor), deteccoes) if deteccoes else (valor, [])
    return valor, []


class FiltroTaintLog(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, "_aja_inspecionado", False):
            return True
        record._aja_inspecionado = True

        from app.seguranca import eventos

        if eventos.registrando.get():
            # Logs escritos durante o registro de um evento já são inspecionados por ele.
            return True

        try:
            mensagem = record.getMessage()
        except Exception:
            return True

        deteccoes = inspecionar(mensagem)
        deteccoes_excecao: list[Deteccao] = []
        if record.exc_info:
            texto_excecao = logging.Formatter().formatException(record.exc_info)
            deteccoes_excecao = inspecionar(texto_excecao)
            if deteccoes_excecao:
                record.exc_text = sanear(texto_excecao, deteccoes_excecao)
                record.exc_info = None

        if not deteccoes and not deteccoes_excecao:
            return True

        if deteccoes:
            if record.name == "uvicorn.access" and isinstance(record.args, tuple):
                # O formatador de acesso do uvicorn precisa dos argumentos separados.
                record.args = tuple(_sanear_argumento(a)[0] for a in record.args)
            else:
                record.msg = sanear(mensagem, deteccoes) + MARCA
                record.args = None

        todas = deteccoes + deteccoes_excecao
        eventos.registrar(
            "LOG_BLOQUEADO",
            sink=f"log:{record.name}",
            deteccoes=todas,
            decisao="mascarado",
            detalhe=(f"Logger '{record.name}' ({record.levelname}) em {record.module}.{record.funcName} "
                     f"tentou gravar {', '.join(categorias(todas))} em texto claro."),
            titular_id=titular_principal(todas),
        )
        return True


_filtro = FiltroTaintLog()
_LOGGERS = ("aja", "uvicorn", "uvicorn.access", "uvicorn.error")


def instalar(caminho_log: Path) -> None:
    """Liga a guarda a todos os handlers relevantes. Pode ser chamada mais de uma vez."""
    caminho_log.parent.mkdir(parents=True, exist_ok=True)
    formatador = logging.Formatter(FORMATO)

    app_logger = logging.getLogger("aja")
    app_logger.setLevel(logging.INFO)
    app_logger.propagate = False
    if not any(getattr(h, "_aja", False) for h in app_logger.handlers):
        arquivo = logging.FileHandler(caminho_log, encoding="utf-8")
        console = logging.StreamHandler()
        for handler in (arquivo, console):
            handler.setFormatter(formatador)
            handler._aja = True
            app_logger.addHandler(handler)

    arquivo_aja = next(h for h in app_logger.handlers if isinstance(h, logging.FileHandler))
    acesso = logging.getLogger("uvicorn.access")
    if arquivo_aja not in acesso.handlers:
        acesso.addHandler(arquivo_aja)

    for nome in (None, *_LOGGERS):
        for handler in logging.getLogger(nome).handlers:
            if _filtro not in handler.filters:
                handler.addFilter(_filtro)
