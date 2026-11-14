"""Eventos de segurança.

Cada bloqueio ou mascaramento feito pelas guardas vira um evento. O evento guarda só metadados
(tipo, sink, categoria do dado, decisão), nunca o dado pessoal em si. É esse evento que o LLM traduz
para o cidadão e que alimenta o indicador de Risco Cidadão do dashboard.
"""

from __future__ import annotations

import json
import time
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Iterable

from app import banco
from app.pii.motor import motor
from app.taint.contexto import atual
from app.taint.sinks import Deteccao, categorias, inspecionar, sanear


@dataclass(frozen=True)
class TipoEvento:
    titulo: str  # rótulo curto para o dashboard
    peso: float  # contribuição para o índice de Risco Cidadão
    descricao: str  # o que aconteceu, em linguagem de negócio (vai para o prompt do LLM)


TIPOS: dict[str, TipoEvento] = {
    "PII_MASCARADA_ENTRADA": TipoEvento(
        "Dado pessoal ocultado no relato", 5,
        "O cidadão escreveu um dado pessoal num relato que será público. O sistema ocultou o dado "
        "antes de publicar o relato."),
    "LOG_BLOQUEADO": TipoEvento(
        "Dado pessoal barrado no registro interno", 12,
        "Uma parte do sistema tentou escrever um dado pessoal no registro interno de funcionamento "
        "(log). O sistema trocou o dado por uma versão mascarada antes de gravar."),
    "ERRO_SANITIZADO": TipoEvento(
        "Mensagem de erro limpa", 12,
        "Aconteceu um erro e a mensagem técnica repetiria dados pessoais na tela. O sistema mostrou "
        "uma mensagem genérica, sem os dados."),
    "RESPOSTA_BLOQUEADA": TipoEvento(
        "Acesso a dados pessoais bloqueado", 25,
        "Alguém tentou obter os dados pessoais de um cidadão sem autorização (sem estar logado ou "
        "usando a conta de outra pessoa). O sistema bloqueou a resposta."),
    "BANCO_BLOQUEADO": TipoEvento(
        "Gravação sem proteção impedida", 30,
        "Uma parte do sistema tentou guardar um dado pessoal sem criptografia no banco de dados. "
        "A gravação foi impedida."),
    "DOSSIE_SANITIZADO": TipoEvento(
        "Identidade preservada no dossiê", 15,
        "O dossiê que vai para a Prefeitura continha dados que identificariam quem fez o relato. "
        "O sistema trocou esses dados por um apelido antes de gerar o documento."),
    "LLM_PROMPT_SANITIZADO": TipoEvento(
        "Dado pessoal retirado antes da IA", 15,
        "O texto que seria enviado ao assistente de inteligência artificial continha um dado "
        "pessoal. O sistema retirou o dado antes do envio."),
    "LOGIN_SUSPEITO": TipoEvento(
        "Muitas tentativas de senha", 35,
        "Houve várias tentativas seguidas de entrar na conta de um cidadão com a senha errada."),
}

FATOR_SENSIVEL = 1.5  # dado de saúde (LGPD art. 5º, II) pesa mais

# Impede que um log escrito durante o registro de um evento gere outro evento (laço).
registrando: ContextVar[bool] = ContextVar("aja_registrando_evento", default=False)


def _texto_seguro(texto: str) -> str:
    """O detalhe técnico nunca carrega o dado em si: tudo o que parecer PII é mascarado."""
    return sanear(texto, inspecionar(texto)) if texto else texto


def registrar(
    tipo: str,
    *,
    sink: str,
    decisao: str,
    detalhe: str,
    deteccoes: Iterable[Deteccao] = (),
    categorias_extra: Iterable[str] = (),
    sensivel: bool | None = None,
    titular_id: int | None = None,
    rota: str | None = None,
) -> int:
    deteccoes = list(deteccoes)
    if tipo not in TIPOS:
        raise ValueError(f"Tipo de evento desconhecido: {tipo}")
    marcador = registrando.set(True)
    try:
        cats = sorted(set(categorias(deteccoes)) | set(categorias_extra))
        if sensivel is None:
            sensivel = any(d.regra.sensivel for d in deteccoes) or "saude" in cats
        ctx = atual()
        if rota is None and ctx is not None:
            rota = f"{ctx.metodo} {ctx.rota}"
        peso = TIPOS[tipo].peso * (FATOR_SENSIVEL if sensivel else 1.0)
        evento_id = banco.executar(
            "INSERT INTO eventos (criado_em, tipo, sink, rota, categorias, sensivel, decisao, "
            "detalhe_tecnico, titular_id, peso) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time(), tipo, sink, motor.mascarar_texto(rota or "-"), json.dumps(cats),
             int(sensivel), decisao, _texto_seguro(detalhe), titular_id, peso),
            verificar=False,  # o conteúdo acabou de ser saneado acima
        )
    finally:
        registrando.reset(marcador)

    from app.ia import tradutor  # import tardio para evitar ciclo

    tradutor.agendar(evento_id)
    return evento_id


def obter(evento_id: int) -> dict | None:
    linha = banco.consultar_um("SELECT * FROM eventos WHERE id = ?", (evento_id,))
    return _formatar(linha) if linha else None


def listar(desde: float | None = None, titular_id: int | None = None, limite: int = 50) -> list[dict]:
    sql = "SELECT * FROM eventos WHERE 1 = 1"
    parametros: list = []
    if desde is not None:
        sql += " AND criado_em >= ?"
        parametros.append(desde)
    if titular_id is not None:
        sql += " AND titular_id = ?"
        parametros.append(titular_id)
    sql += " ORDER BY id DESC LIMIT ?"
    parametros.append(limite)
    return [_formatar(linha) for linha in banco.consultar(sql, parametros)]


def _formatar(linha: dict) -> dict:
    evento = dict(linha)
    evento["categorias"] = json.loads(evento["categorias"])
    evento["sensivel"] = bool(evento["sensivel"])
    evento["remediacao"] = json.loads(evento["remediacao"]) if evento.get("remediacao") else []
    evento["titulo"] = TIPOS[evento["tipo"]].titulo
    return evento
