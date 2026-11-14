"""Validações que reduzem falsos positivos do motor de PII.

Um número com cara de CPF só é tratado como CPF no meio de um texto livre se o dígito
verificador bater ou se a palavra "CPF" aparecer logo antes. Assim, um número de protocolo
do SP156 não é confundido com documento pessoal.
"""

from __future__ import annotations

import re

_SO_DIGITOS = re.compile(r"\D")


def digitos(valor: str) -> str:
    return _SO_DIGITOS.sub("", valor)


def cpf_valido(valor: str) -> bool:
    numero = digitos(valor)
    if len(numero) != 11 or numero == numero[0] * 11:
        return False
    for tamanho in (9, 10):
        soma = sum(int(numero[i]) * (tamanho + 1 - i) for i in range(tamanho))
        digito = (soma * 10) % 11 % 10
        if digito != int(numero[tamanho]):
            return False
    return True


def rg_sp_valido(valor: str) -> bool:
    """RG do estado de São Paulo: 8 dígitos e dígito verificador (0-9 ou X), módulo 11."""
    bruto = re.sub(r"[^\dXx]", "", valor).upper()
    if len(bruto) != 9 or not bruto[:8].isdigit():
        return False
    soma = sum(int(bruto[i]) * (i + 2) for i in range(8))
    resto = soma % 11
    esperado = "X" if resto == 10 else str(resto)
    return bruto[8] == esperado


def contexto_contem(antes: str, palavras: tuple[str, ...]) -> bool:
    """Verifica se alguma palavra-chave aparece no trecho imediatamente anterior ao achado."""
    trecho = antes.lower()
    return any(re.search(rf"\b{re.escape(p)}\b", trecho) for p in palavras)
