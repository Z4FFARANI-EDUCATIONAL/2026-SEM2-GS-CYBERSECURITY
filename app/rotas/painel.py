"""Dados do dashboard de Risco Cidadão: visão do cidadão e visão executiva."""

from __future__ import annotations

import time
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, status

from app import banco, config
from app.rotas.cidadaos import garantir_gestor
from app.seguranca import auth, eventos, risco
from app.seguranca.eventos import TIPOS
from app.taint.contexto import ContextoTaint

router = APIRouter(prefix="/api/v1/painel", tags=["Dashboard Risco Cidadão"])

CAMPOS_CIDADAO = ("id", "criado_em", "tipo", "titulo", "categorias", "sensivel", "decisao", "peso",
                  "mensagem", "o_que_fazer", "origem_mensagem")


def _para_cidadao(evento: dict) -> dict:
    return {campo: evento[campo] for campo in CAMPOS_CIDADAO}


@router.get("/status", summary="Estado do tradutor via IA")
def estado():
    cfg = config.obter()
    return {"ia_configurada": bool(cfg.chave_anthropic), "modelo": cfg.modelo_llm,
            "janela_min": cfg.janela_risco_min, "modo_demo": cfg.modo_demo}


@router.get("/cidadao", summary="Meu painel de risco")
def painel_cidadao(ctx: ContextoTaint = Depends(auth.exigir_login)):
    janela = config.obter().janela_risco_min
    lista = eventos.listar(titular_id=ctx.cidadao_id, limite=200)
    nome = banco.consultar_um("SELECT nome_mascarado FROM cidadaos WHERE id = ?", (ctx.cidadao_id,))["nome_mascarado"]
    return {
        "nome": nome,
        "risco": risco.calcular(lista, janela),
        "serie": risco.serie(lista, janela),
        "alertas": [_para_cidadao(e) for e in lista[:20]],
    }


@router.get("/executivo", summary="Painel executivo (equipe AJA)")
def painel_executivo(_: ContextoTaint = Depends(auth.exigir_gestor)):
    janela = config.obter().janela_risco_min
    lista = eventos.listar(limite=1000)
    na_janela = [e for e in lista if time.time() - e["criado_em"] <= janela * 60]
    por_categoria: Counter = Counter()
    for e in lista:
        por_categoria.update(e["categorias"])
    return {
        "risco": risco.calcular(lista, janela),
        "serie": risco.serie(lista, janela),
        "totais": {
            "eventos": len(lista),
            "na_janela": len(na_janela),
            "bloqueados": sum(1 for e in lista if e["decisao"] == "bloqueado"),
            "mascarados": sum(1 for e in lista if e["decisao"] == "mascarado"),
            "dados_de_saude": sum(1 for e in lista if e["sensivel"]),
            "cidadaos_afetados": len({e["titular_id"] for e in lista if e["titular_id"]}),
            "traduzidos_por_ia": sum(1 for e in lista if e["origem_mensagem"] == "ia"),
        },
        "por_tipo": [{"tipo": t, "titulo": TIPOS[t].titulo, "total": n}
                     for t, n in Counter(e["tipo"] for e in lista).most_common()],
        "por_sink": [{"sink": s, "total": n} for s, n in Counter(e["sink"].split(":")[0] for e in lista).most_common()],
        "por_categoria": [{"categoria": c, "total": n} for c, n in por_categoria.most_common()],
        "alertas": lista[:30],
    }


@router.post("/demo/reiniciar", summary="Limpar os dados de demonstração", tags=["Auditoria"])
def reiniciar_demo(_: ContextoTaint = Depends(auth.exigir_gestor)):
    if not config.obter().modo_demo:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Disponível só no modo de demonstração.")
    for sql in (
        "DELETE FROM eventos", "DELETE FROM apoios", "DELETE FROM relatos", "DELETE FROM topicos",
        "DELETE FROM tentativas_login",
        "DELETE FROM sessoes WHERE cidadao_id IN (SELECT id FROM cidadaos WHERE perfil <> 'gestor')",
        "DELETE FROM cidadaos WHERE perfil <> 'gestor'",
    ):
        banco.executar(sql)
    garantir_gestor()
    return {"ok": True}
