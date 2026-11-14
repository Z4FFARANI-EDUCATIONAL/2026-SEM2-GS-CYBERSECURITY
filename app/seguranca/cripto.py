"""Proteção dos dados no banco.

- **Criptografia (Fernet = AES-128-CBC + HMAC-SHA256):** CPF, RG, nome, contato, endereço e dados de
  saúde. Só a aplicação, com a chave do `.env`, consegue ler de volta.
- **Índice cego (HMAC-SHA256):** permite achar o cidadão pelo CPF ou e-mail no login sem guardar o
  valor em texto claro e sem precisar decifrar a tabela inteira.
- **Hash de senha (scrypt, com sal aleatório):** irreversível; só dá para conferir se a senha bate.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from cryptography.fernet import Fernet, InvalidToken

from app import config
from app.pii.validadores import digitos

_PREFIXO_SCRYPT = "scrypt"
_N, _R, _P = 2**14, 8, 1


def _fernet() -> Fernet:
    return Fernet(config.obter().chave_cripto.encode())


def cifrar(valor: str | None) -> str | None:
    if valor is None or valor == "":
        return None
    return _fernet().encrypt(str(valor).encode("utf-8")).decode("ascii")


def decifrar(token: str | None) -> str | None:
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken:
        return None


def indice_cego(valor: str) -> str:
    """HMAC do valor normalizado: CPF só com dígitos e e-mail em minúsculas."""
    normalizado = digitos(valor) if "@" not in valor else valor.strip().lower()
    chave = config.obter().chave_indice.encode()
    return hmac.new(chave, normalizado.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_senha(senha: str) -> str:
    sal = secrets.token_bytes(16)
    derivada = hashlib.scrypt(senha.encode("utf-8"), salt=sal, n=_N, r=_R, p=_P)
    return "$".join([_PREFIXO_SCRYPT, base64.b64encode(sal).decode(), base64.b64encode(derivada).decode()])


def conferir_senha(senha: str, guardado: str) -> bool:
    try:
        prefixo, sal_b64, derivada_b64 = guardado.split("$")
    except ValueError:
        return False
    if prefixo != _PREFIXO_SCRYPT:
        return False
    derivada = hashlib.scrypt(senha.encode("utf-8"), salt=base64.b64decode(sal_b64), n=_N, r=_R, p=_P)
    return hmac.compare_digest(derivada, base64.b64decode(derivada_b64))


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def parece_protegido(valor: str) -> bool:
    """Valores já cifrados ou com hash podem ir para o banco sem passar pela guarda de taint."""
    return (
        valor.startswith("gAAAAA")  # token Fernet
        or valor.startswith(_PREFIXO_SCRYPT + "$")
        or (len(valor) == 64 and all(c in "0123456789abcdef" for c in valor))  # SHA-256 / HMAC
    )
