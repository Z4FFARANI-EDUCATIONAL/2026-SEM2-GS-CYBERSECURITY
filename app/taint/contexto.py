"""Contexto de taint de cada requisição.

Toda requisição ganha um `ContextoTaint`. Cada dado pessoal que entra (source) é **marcado** ali,
com o tipo do dado, de onde veio e de quem é (titular). As guardas das saídas (sinks) consultam
essas marcações antes de deixar qualquer coisa sair.

A marcação é feita pelo **valor**, e não por um rótulo preso a uma variável. Assim, o dado continua
rastreado mesmo depois de copiado, concatenado ou formatado numa f-string, situações em que um
rótulo preso ao objeto se perderia.
"""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field

from app.pii.motor import Achado
from app.pii.regras import Categoria, Regra
from app.pii.validadores import digitos


@dataclass
class Marcacao:
    valor: str = field(repr=False)
    regra: Regra
    origem: str  # ex.: "POST /api/v1/cidadaos $.cpf" ou "banco:cidadaos.nome"
    titular_id: int | None = None
    _padrao: re.Pattern[str] | None = field(default=None, repr=False)

    def padrao(self) -> re.Pattern[str] | None:
        """Regex que acha o valor em outro texto, tolerando pontuação e maiúsculas."""
        if self._padrao is not None:
            return self._padrao
        valor = self.valor.strip()
        numeros = digitos(valor)
        if len(numeros) >= 8 and len(numeros) >= len(re.sub(r"\s", "", valor)) * 0.7:
            # CPF, RG, telefone, CEP: acha com ou sem pontuação (529.982.247-25 = 52998224725).
            corpo = r"[\s.\-/()]?".join(numeros)
            self._padrao = re.compile(rf"(?<!\d){corpo}(?!\d)")
        elif len(valor) >= (8 if self.regra.categoria == Categoria.CREDENCIAL else 4):
            # Credenciais curtas (uma senha errada digitada como "errada") gerariam falso positivo
            # em qualquer texto; elas continuam protegidas pelo nome do campo e pelos padrões.
            variantes = [re.escape(valor)]
            if self.regra.id == "nome":
                partes = valor.split()
                if len(partes) >= 3:
                    variantes.append(re.escape(f"{partes[0]} {partes[-1]}"))
            self._padrao = re.compile(r"(?i)\b(?:" + "|".join(variantes) + r")\b")
        return self._padrao


@dataclass
class ContextoTaint:
    metodo: str
    rota: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    autenticado: bool = False
    cidadao_id: int | None = None
    perfil: str | None = None
    marcacoes: list[Marcacao] = field(default_factory=list)
    achados_entrada: list[Achado] = field(default_factory=list)

    # --- sources ------------------------------------------------------------------------------

    def marcar(self, valor: str | None, regra: Regra, origem: str, titular_id: int | None = None) -> None:
        if not valor:
            return
        for m in self.marcacoes:
            if m.valor == valor and m.titular_id == titular_id:
                return
        self.marcacoes.append(Marcacao(str(valor), regra, origem, titular_id))

    def marcar_achados(self, achados: list[Achado], fonte: str) -> None:
        for achado in achados:
            self.achados_entrada.append(achado)
            self.marcar(achado.valor, achado.regra, f"{fonte} {achado.caminho}", self.cidadao_id)

    def definir_titular(self, titular_id: int) -> None:
        """No cadastro, o titular só existe depois do INSERT; os dados de entrada passam a ser dele."""
        for m in self.marcacoes:
            if m.titular_id is None:
                m.titular_id = titular_id

    # --- consultas das guardas ----------------------------------------------------------------

    def encontrar(self, texto: str) -> list[tuple[Marcacao, int, int]]:
        encontrados = []
        for m in self.marcacoes:
            padrao = m.padrao()
            if padrao is None:
                continue
            for match in padrao.finditer(texto):
                encontrados.append((m, match.start(), match.end()))
        return encontrados

    def marcacao_de(self, valor: str) -> Marcacao | None:
        alvo_digitos = digitos(valor)
        for m in self.marcacoes:
            if m.valor == valor:
                return m
            if len(alvo_digitos) >= 8 and digitos(m.valor) == alvo_digitos:
                return m
            if m.regra.id in {"email", "nome"} and m.valor.lower() == valor.lower():
                return m
        return None


_contexto: ContextVar[ContextoTaint | None] = ContextVar("aja_contexto_taint", default=None)


def atual() -> ContextoTaint | None:
    return _contexto.get()


def iniciar(ctx: ContextoTaint):
    return _contexto.set(ctx)


def encerrar(token) -> None:
    _contexto.reset(token)
