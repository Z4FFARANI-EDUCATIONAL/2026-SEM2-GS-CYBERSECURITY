"""Motor de parsing de PII.

Recebe qualquer dado que entra no sistema (JSON de uma requisição, parâmetros de URL ou um texto
solto), percorre a estrutura inteira e devolve os **achados**: onde está cada dado pessoal, de que
tipo ele é e como fica mascarado. O valor original de cada achado fica só na memória, durante a
requisição, e nunca é impresso (`repr=False`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from app.pii.regras import REGRAS, Categoria, Regra, normalizar_chave


@dataclass(frozen=True)
class Achado:
    regra: Regra
    caminho: str  # ex.: $.cidadao.cpf ou $.descricao[34:48]
    origem: str  # "campo" (nome da chave) ou "conteudo" (regex no texto)
    valor: str = field(repr=False)
    inicio: int = 0
    fim: int = 0

    @property
    def categoria(self) -> Categoria:
        return self.regra.categoria

    @property
    def sensivel(self) -> bool:
        return self.regra.sensivel

    @property
    def mascarado(self) -> str:
        return self.regra.mascara(self.valor)

    def resumo(self) -> dict[str, Any]:
        """Descrição do achado sem o valor original, segura para log, banco e LLM."""
        return {
            "regra": self.regra.id,
            "tipo": self.regra.nome,
            "categoria": self.categoria.value,
            "sensivel_lgpd": self.sensivel,
            "caminho": self.caminho,
            "detectado_por": self.origem,
            "mascarado": self.mascarado,
        }


def _valor_do_grupo(match, grupo: int) -> tuple[str | None, int, int]:
    if grupo == 0:
        return match.group(0), match.start(0), match.end(0)
    if match.group(grupo) is not None:
        return match.group(grupo), match.start(grupo), match.end(grupo)
    for indice in range(1, (match.re.groups or 0) + 1):
        if match.group(indice) is not None:
            return match.group(indice), match.start(indice), match.end(indice)
    return match.group(0), match.start(0), match.end(0)


class MotorPII:
    def __init__(self, regras: Iterable[Regra] = REGRAS) -> None:
        self.regras = tuple(regras)
        self._regras_de_campo = [r for r in self.regras if r.chave is not None]
        self._regras_de_texto = [r for r in self.regras if r.padrao is not None]

    # --- detecção -----------------------------------------------------------------------------

    def regra_do_campo(self, nome_campo: str) -> Regra | None:
        chave = normalizar_chave(str(nome_campo))
        for regra in self._regras_de_campo:
            if regra.chave.match(chave):
                return regra
        return None

    def analisar_texto(self, texto: str, caminho: str = "$") -> list[Achado]:
        candidatos: list[Achado] = []
        for regra in self._regras_de_texto:
            for match in regra.padrao.finditer(texto):
                valor, inicio, fim = _valor_do_grupo(match, regra.grupo)
                if not valor:
                    continue
                antes = texto[max(0, inicio - 25):inicio]
                if regra.validar and not regra.validar(valor, antes):
                    continue
                candidatos.append(Achado(regra, f"{caminho}[{inicio}:{fim}]", "conteudo", valor, inicio, fim))

        # Quando duas regras disputam o mesmo trecho, fica a de maior prioridade.
        escolhidos: list[Achado] = []
        for achado in sorted(candidatos, key=lambda a: (-a.regra.prioridade, a.inicio)):
            if all(achado.fim <= e.inicio or achado.inicio >= e.fim for e in escolhidos):
                escolhidos.append(achado)
        return sorted(escolhidos, key=lambda a: a.inicio)

    def analisar(self, dado: Any, caminho: str = "$") -> list[Achado]:
        """Percorre dict, lista ou texto e devolve todos os achados de PII."""
        achados: list[Achado] = []
        if isinstance(dado, dict):
            for chave, valor in dado.items():
                sub = f"{caminho}.{chave}"
                regra = self.regra_do_campo(chave)
                if regra is not None:
                    achados.extend(self._achados_do_campo(regra, valor, sub))
                else:
                    achados.extend(self.analisar(valor, sub))
        elif isinstance(dado, (list, tuple)):
            for i, item in enumerate(dado):
                achados.extend(self.analisar(item, f"{caminho}[{i}]"))
        elif isinstance(dado, str):
            achados.extend(self.analisar_texto(dado, caminho))
        return achados

    def _achados_do_campo(self, regra: Regra, valor: Any, caminho: str) -> list[Achado]:
        """Um campo como `dados_de_saude` torna PII tudo o que estiver dentro dele."""
        if valor is None or valor == "":
            return []
        if isinstance(valor, dict):
            return [a for k, item in valor.items() for a in self._achados_do_campo(regra, item, f"{caminho}.{k}")]
        if isinstance(valor, (list, tuple)):
            return [a for i, item in enumerate(valor) for a in self._achados_do_campo(regra, item, f"{caminho}[{i}]")]
        texto = str(valor)
        return [Achado(regra, caminho, "campo", texto, 0, len(texto))]

    # --- mascaramento -------------------------------------------------------------------------

    def mascarar_texto(self, texto: str) -> str:
        resultado = texto
        for achado in sorted(self.analisar_texto(texto), key=lambda a: a.inicio, reverse=True):
            resultado = resultado[:achado.inicio] + achado.mascarado + resultado[achado.fim:]
        return resultado

    def mascarar(self, dado: Any) -> Any:
        """Devolve uma cópia do dado com todo PII mascarado (o original não é alterado)."""
        if isinstance(dado, dict):
            copia = {}
            for chave, valor in dado.items():
                regra = self.regra_do_campo(chave)
                copia[chave] = self._mascarar_campo(regra, valor) if regra else self.mascarar(valor)
            return copia
        if isinstance(dado, list):
            return [self.mascarar(item) for item in dado]
        if isinstance(dado, tuple):
            return tuple(self.mascarar(item) for item in dado)
        if isinstance(dado, str):
            return self.mascarar_texto(dado)
        return dado

    def _mascarar_campo(self, regra: Regra, valor: Any) -> Any:
        if valor is None or valor == "":
            return valor
        if isinstance(valor, dict):
            return {k: self._mascarar_campo(regra, item) for k, item in valor.items()}
        if isinstance(valor, (list, tuple)):
            return [self._mascarar_campo(regra, item) for item in valor]
        return regra.mascara(str(valor))


motor = MotorPII()
