"""Dossiê em PDF enviado ao órgão público: o sink mais sensível do AJA.

O modelo do dossiê identifica cada relato pelo nome de quem relatou, porque órgãos públicos costumam
pedir isso. A política do AJA é a oposta: **a identidade de quem relatou nunca sai no documento**.
Quem aplica a política é a guarda de taint. A identidade de cada autor é lida do banco e marcada, e
qualquer trecho que a contenha (nome, CPF, telefone, e-mail, endereço) é trocado por um apelido
(Morador(a) A, B…) ou por uma máscara antes de o PDF ser gerado.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fpdf import FPDF

from app import banco
from app.seguranca import eventos
from app.taint.sinks import Deteccao, categorias, inspecionar, sanear

PUBLICOS = {"visual": "Pessoas com deficiência visual", "auditiva": "Pessoas com deficiência auditiva",
            "ambos": "Pessoas com deficiência visual e auditiva"}

CONTEXTO_PUBLICO = {
    "obstaculo_calcada": (
        "Em São Paulo, pedidos ao SP156 de obstáculo na calçada levaram em mediana 266 dias para serem "
        "finalizados entre 2020 e 2026, e só 7% saíram em até 30 dias."),
    "piso_tatil": (
        "Em São Paulo, pedidos ao SP156 ligados a barreiras de acessibilidade na calçada levaram em mediana "
        "mais de 200 dias para serem finalizados entre 2020 e 2026."),
    "travessia_sem_sinal_sonoro": (
        "Na Subprefeitura Cidade Ademar, só 34% dos pedidos de avaliação de travessia foram finalizados em "
        "até 30 dias em 2025-2026."),
}
FONTE_DADOS = "Fonte: Dados do SP156, Portal de Dados Abertos da Prefeitura de São Paulo (jan/2020 a set/2026)."


def _latin1(texto: str) -> str:
    """As fontes padrão do PDF usam Latin-1; troca o que não couber (travessões, aspas curvas)."""
    trocas = {"–": "-", "—": "-", "…": "...", "“": '"', "”": '"', "‘": "'", "’": "'"}
    for original, troca in trocas.items():
        texto = texto.replace(original, troca)
    return texto.encode("latin-1", "replace").decode("latin-1")


def _apelido(indice: int) -> str:
    return f"Morador(a) {chr(ord('A') + indice % 26)}"


def montar_conteudo(topico_id: int) -> tuple[dict, list[str]]:
    """Monta os relatos já com a guarda aplicada. Devolve o tópico e as linhas seguras."""
    from app.rotas.cidadaos import marcar_identidade

    topico = banco.consultar_um("SELECT * FROM topicos WHERE id = ?", (topico_id,))
    relatos = banco.consultar(
        "SELECT r.autor_id, r.descricao_publica, r.criado_em FROM relatos r WHERE r.topico_id = ? ORDER BY r.id",
        (topico_id,),
    )

    apelidos: dict[int, str] = {}
    linhas_brutas = []
    for relato in relatos:
        identidade = marcar_identidade(relato["autor_id"])  # source "banco": identidade decifrada e marcada
        apelidos.setdefault(relato["autor_id"], _apelido(len(apelidos)))
        data = relato["criado_em"][:10]
        linhas_brutas.append(f"Relato de {identidade.get('nome') or 'morador'} em {data}: {relato['descricao_publica']}")

    linhas_seguras = []
    por_titular: dict[int | None, list[Deteccao]] = {}
    for linha in linhas_brutas:
        deteccoes = inspecionar(linha)
        for d in deteccoes:
            por_titular.setdefault(d.titular_id, []).append(d)
        linhas_seguras.append(sanear(
            linha, deteccoes,
            substituir=lambda d: apelidos.get(d.titular_id, "Morador(a)") if d.regra.id == "nome" and d.titular_id
            else d.regra.mascara(d.valor),
        ))

    for titular_id, deteccoes in por_titular.items():
        eventos.registrar(
            "DOSSIE_SANITIZADO", sink="dossie:pdf", deteccoes=deteccoes, decisao="mascarado",
            detalhe=(f"Dossiê do tópico {topico_id} levaria {', '.join(categorias(deteccoes))} de quem relatou; "
                     f"{len(deteccoes)} trecho(s) trocado(s) por apelido ou máscara."),
            titular_id=titular_id,
        )
    return topico, linhas_seguras


def gerar(topico_id: int) -> bytes:
    topico, relatos = montar_conteudo(topico_id)
    apoios = banco.consultar_um("SELECT COUNT(*) AS n FROM apoios WHERE topico_id = ?", (topico_id,))["n"]
    agora = datetime.now(timezone.utc).astimezone().strftime("%d/%m/%Y %H:%M")

    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(18, 18, 18)
    pdf.add_page()

    def titulo(texto: str, tamanho: int = 12) -> None:
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", tamanho)
        pdf.set_text_color(17, 36, 74)
        pdf.multi_cell(0, 7, _latin1(texto), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(30, 30, 30)

    def paragrafo(texto: str, estilo: str = "") -> None:
        pdf.set_font("Helvetica", estilo, 10)
        pdf.multi_cell(0, 5.5, _latin1(texto), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

    titulo("AJA - Dossiê de demanda comunitária", 16)
    paragrafo("Parque Doroteia - Subprefeitura Cidade Ademar - São Paulo/SP")
    paragrafo(f"Gerado em {agora}", "I")

    titulo("1. Demanda")
    paragrafo(f"Tópico: {topico['titulo']}")
    paragrafo(f"Local da barreira: {topico['local_referencia']}")
    paragrafo(f"Público afetado: {PUBLICOS.get(topico['publico_afetado'], topico['publico_afetado'])}")
    paragrafo(f"Relatos da comunidade: {len(relatos)} | Apoios: {apoios}")

    titulo("2. Relatos da comunidade")
    for relato in relatos:
        paragrafo(relato)

    if topico["categoria"] in CONTEXTO_PUBLICO:
        titulo("3. Contexto em dados públicos")
        paragrafo(CONTEXTO_PUBLICO[topico["categoria"]])
        paragrafo(FONTE_DADOS, "I")

    titulo("Proteção de dados")
    paragrafo(
        "As pessoas que relataram aparecem por apelido (Morador(a) A, B...). Dados que as identificam foram "
        "retirados automaticamente, conforme o princípio da necessidade da LGPD (Lei 13.709/2018, art. 6º, III). "
        "O contato com os relatores, se necessário, é feito por meio do AJA."
    )
    return bytes(pdf.output())
