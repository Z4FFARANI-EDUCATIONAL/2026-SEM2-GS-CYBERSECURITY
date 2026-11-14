"""Inspeção das saídas (sinks).

Antes de um conteúdo sair do sistema (log, resposta HTTP, banco, dossiê, prompt do LLM), ele passa
por `inspecionar`, que combina duas verificações:

1. **Marcações de taint:** o conteúdo contém algum valor marcado na entrada ou lido do banco?
   Pega o dado mesmo que ele não tenha formato reconhecível (um nome, por exemplo).
2. **Padrões do motor de PII:** pega dado pessoal que nunca foi marcado, como um CPF digitado
   num lugar inesperado ou um log escrito fora de uma requisição.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from app.pii.motor import motor
from app.pii.regras import Regra
from app.taint.contexto import atual


@dataclass(frozen=True)
class Deteccao:
    regra: Regra
    metodo: str  # "taint" (marcação) ou "padrao" (regex do motor)
    valor: str = field(repr=False)
    inicio: int
    fim: int
    titular_id: int | None = None
    origem: str | None = None  # source de onde o dado veio, quando conhecido

    def resumo(self) -> dict:
        return {
            "tipo": self.regra.nome,
            "categoria": self.regra.categoria.value,
            "sensivel_lgpd": self.regra.sensivel,
            "detectado_por": self.metodo,
            "source": self.origem,
        }


class VazamentoBloqueado(Exception):
    """Levantada quando uma guarda impede um dado pessoal de chegar a um sink."""

    def __init__(self, sink: str, deteccoes: list[Deteccao], evento_id: int | None = None) -> None:
        self.sink = sink
        self.deteccoes = deteccoes
        self.evento_id = evento_id
        tipos = ", ".join(sorted({d.regra.nome for d in deteccoes}))
        super().__init__(f"Taint sink bloqueado em '{sink}': {tipos}")


def inspecionar(conteudo: str) -> list[Deteccao]:
    if not conteudo:
        return []
    ctx = atual()
    deteccoes: list[Deteccao] = []

    if ctx is not None:
        for marcacao, inicio, fim in ctx.encontrar(conteudo):
            deteccoes.append(Deteccao(marcacao.regra, "taint", conteudo[inicio:fim], inicio, fim,
                                      marcacao.titular_id, marcacao.origem))

    for achado in motor.analisar_texto(conteudo):
        if any(not (achado.fim <= d.inicio or achado.inicio >= d.fim) for d in deteccoes):
            continue
        marcacao = ctx.marcacao_de(achado.valor) if ctx is not None else None
        deteccoes.append(Deteccao(
            achado.regra, "padrao", achado.valor, achado.inicio, achado.fim,
            marcacao.titular_id if marcacao else None, marcacao.origem if marcacao else None,
        ))

    # Remove sobreposições (ex.: o nome inteiro e o primeiro+último nome), ficando com o maior trecho.
    finais: list[Deteccao] = []
    for d in sorted(deteccoes, key=lambda d: (d.inicio, -(d.fim - d.inicio))):
        if not finais or d.inicio >= finais[-1].fim:
            finais.append(d)
    return finais


def sanear(conteudo: str, deteccoes: list[Deteccao],
           substituir: Callable[[Deteccao], str] | None = None) -> str:
    """Troca cada trecho detectado pela máscara da regra (ou por outro texto, se indicado)."""
    resultado = conteudo
    for d in sorted(deteccoes, key=lambda d: d.inicio, reverse=True):
        troca = substituir(d) if substituir else d.regra.mascara(d.valor)
        resultado = resultado[:d.inicio] + troca + resultado[d.fim:]
    return resultado


def categorias(deteccoes: list[Deteccao]) -> list[str]:
    return sorted({d.regra.categoria.value for d in deteccoes})


def titular_principal(deteccoes: list[Deteccao]) -> int | None:
    return next((d.titular_id for d in deteccoes if d.titular_id is not None), None)
