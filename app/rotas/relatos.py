"""Relatos de barreiras, tópicos e dossiê para a Prefeitura."""

from __future__ import annotations

import re
import unicodedata
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from app import banco, dossie
from app.rotas.cidadaos import marcar_identidade
from app.seguranca import auth, eventos
from app.taint.contexto import ContextoTaint
from app.taint.sinks import Deteccao, categorias, inspecionar, sanear

router = APIRouter(prefix="/api/v1", tags=["Relatos e tópicos"])

CATEGORIAS = {
    "piso_tatil": "Piso tátil interrompido ou ausente",
    "obstaculo_calcada": "Obstáculo na calçada",
    "travessia_sem_sinal_sonoro": "Travessia sem sinal sonoro",
    "sinalizacao_inadequada": "Sinalização inadequada",
    "comunicacao_inacessivel": "Comunicação sem Libras ou legenda",
}
PUBLICOS = {"visual": "Pessoas com deficiência visual", "auditiva": "Pessoas com deficiência auditiva",
            "ambos": "Pessoas com deficiência visual e auditiva"}


class NovoRelato(BaseModel):
    model_config = ConfigDict(json_schema_extra={"example": {
        "descricao": "O piso tátil acaba no meio da calçada, perto da banca, e a bengala não encontra mais a guia.",
        "categoria": "piso_tatil",
        "local_referencia": "Rua Exemplo do Parque Doroteia, 300 (em frente à banca)",
        "publico_afetado": "visual",
    }})

    descricao: str = Field(min_length=10, max_length=2000, description="Texto público do relato.")
    categoria: Literal[tuple(CATEGORIAS)]  # type: ignore[valid-type]
    local_referencia: str = Field(min_length=3, max_length=160,
                                  description="Onde fica a barreira. É público e não é dado pessoal.")
    publico_afetado: Literal["visual", "auditiva", "ambos"]
    latitude: float | None = Field(None, ge=-90, le=90)
    longitude: float | None = Field(None, ge=-180, le=180)


def _normalizar(texto: str) -> str:
    sem_acento = unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9]+", " ", sem_acento).strip()


def proteger_texto_publico(texto: str) -> tuple[str, list[Deteccao]]:
    """Texto que será publicado: todo dado pessoal (inclusive a identidade do autor) é mascarado.

    A condição de saúde cadastrada pelo autor não é procurada por valor: "baixa visão" num relato
    costuma descrever o público afetado. Nesse caso vale só a regra de autodeclaração ("tenho baixa visão").
    """
    deteccoes = [d for d in inspecionar(texto)
                 if d.regra.id != "token"
                 and not (d.regra.id == "saude" and (d.origem or "").startswith("banco:"))]
    return (sanear(texto, deteccoes), deteccoes) if deteccoes else (texto, [])


@router.post("/relatos", status_code=status.HTTP_201_CREATED, summary="Relatar uma barreira")
def relatar(dados: NovoRelato, ctx: ContextoTaint = Depends(auth.exigir_login)):
    # A identidade do autor (lida do banco) entra no contexto de taint: se ele escrever o próprio
    # nome, telefone ou endereço no relato, a guarda reconhece mesmo sem frase como "meu nome é".
    marcar_identidade(ctx.cidadao_id)
    local, achados = proteger_texto_publico(dados.local_referencia)

    chave = f"{dados.categoria}|{_normalizar(local)}"
    topico = banco.consultar_um("SELECT id FROM topicos WHERE chave = ?", (chave,))
    if topico:
        # Quem já relatou no mesmo tópico também é protegido: "falei com a Joana sobre isso".
        for linha in banco.consultar("SELECT DISTINCT autor_id FROM relatos WHERE topico_id = ?", (topico["id"],)):
            marcar_identidade(linha["autor_id"])
        topico_id = topico["id"]
    else:
        topico_id = banco.executar(
            "INSERT INTO topicos (chave, titulo, categoria, local_referencia, publico_afetado) VALUES (?, ?, ?, ?, ?)",
            (chave, f"{CATEGORIAS[dados.categoria]} - {local}", dados.categoria, local, dados.publico_afetado),
        )

    descricao, achados_descricao = proteger_texto_publico(dados.descricao)
    achados += achados_descricao
    por_titular: dict[int, list[Deteccao]] = {}
    for d in achados:
        por_titular.setdefault(d.titular_id or ctx.cidadao_id, []).append(d)
    for titular_id, deteccoes in por_titular.items():
        quem = "do próprio autor" if titular_id == ctx.cidadao_id else f"do cidadão {titular_id}, citado pelo autor"
        eventos.registrar(
            "PII_MASCARADA_ENTRADA", sink="entrada:relato_publico", deteccoes=deteccoes, decisao="mascarado",
            detalhe=(f"Relato público continha {', '.join(categorias(deteccoes))} {quem}; "
                     "trechos mascarados antes de gravar."),
            titular_id=titular_id,
        )

    relato_id = banco.executar(
        "INSERT INTO relatos (topico_id, autor_id, descricao_publica, latitude, longitude) VALUES (?, ?, ?, ?, ?)",
        (topico_id, ctx.cidadao_id, descricao, dados.latitude, dados.longitude),
    )
    resposta = {"relato_id": relato_id, "topico_id": topico_id, "descricao_publicada": descricao}
    if achados:
        resposta["aviso"] = "Escondemos dados pessoais do seu relato antes de publicar. O relato continua valendo."
    return resposta


@router.get("/topicos", summary="Listar tópicos")
def listar_topicos():
    return banco.consultar(
        "SELECT t.id, t.titulo, t.categoria, t.local_referencia, t.publico_afetado, t.criado_em, "
        "(SELECT COUNT(*) FROM relatos r WHERE r.topico_id = t.id) AS relatos, "
        "(SELECT COUNT(*) FROM apoios a WHERE a.topico_id = t.id) AS apoios "
        "FROM topicos t ORDER BY t.id DESC"
    )


@router.get("/topicos/{topico_id}", summary="Detalhar tópico (relatos sem autor)")
def detalhar_topico(topico_id: int):
    topico = banco.consultar_um("SELECT id, titulo, categoria, local_referencia, publico_afetado, criado_em "
                                "FROM topicos WHERE id = ?", (topico_id,))
    if not topico:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tópico não encontrado.")
    topico["relatos"] = banco.consultar(
        "SELECT descricao_publica, criado_em FROM relatos WHERE topico_id = ? ORDER BY id", (topico_id,))
    topico["apoios"] = banco.consultar_um("SELECT COUNT(*) AS n FROM apoios WHERE topico_id = ?", (topico_id,))["n"]
    return topico


@router.post("/topicos/{topico_id}/apoios", summary="Apoiar tópico")
def apoiar(topico_id: int, ctx: ContextoTaint = Depends(auth.exigir_login)):
    if not banco.consultar_um("SELECT id FROM topicos WHERE id = ?", (topico_id,)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tópico não encontrado.")
    banco.executar("INSERT OR IGNORE INTO apoios (topico_id, cidadao_id) VALUES (?, ?)", (topico_id, ctx.cidadao_id))
    return {"apoios": banco.consultar_um("SELECT COUNT(*) AS n FROM apoios WHERE topico_id = ?", (topico_id,))["n"]}


@router.get("/topicos/{topico_id}/dossie", summary="Gerar dossiê em PDF para o órgão público",
            response_class=Response, responses={200: {"content": {"application/pdf": {}}}})
def gerar_dossie(topico_id: int):
    if not banco.consultar_um("SELECT id FROM topicos WHERE id = ?", (topico_id,)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tópico não encontrado.")
    pdf = dossie.gerar(topico_id)
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'inline; filename="dossie_topico_{topico_id}.pdf"'})
