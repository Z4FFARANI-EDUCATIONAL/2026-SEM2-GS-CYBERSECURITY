"""Ambiente isolado para os testes: banco e log temporários, chaves geradas e LLM falso."""

import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

_TEMP = Path(tempfile.mkdtemp(prefix="aja-testes-"))
os.environ.update({
    "AJA_CHAVE_CRIPTO": Fernet.generate_key().decode(),
    "AJA_CHAVE_INDICE": secrets.token_hex(32),
    "AJA_BANCO": str(_TEMP / "aja.db"),
    "AJA_LOG": str(_TEMP / "aja.log"),
    "AJA_GESTOR_EMAIL": "gestor@aja.exemplo.com",
    "AJA_GESTOR_SENHA": "Gestor#Teste2026",
    "AJA_TRADUCAO_SINCRONA": "1",
    "AJA_MODO_DEMO": "1",
    "ANTHROPIC_API_KEY": "",
})

from fastapi.testclient import TestClient  # noqa: E402

from app import banco  # noqa: E402
from app.ia import tradutor  # noqa: E402
from app.main import app  # noqa: E402
from app.rotas.cidadaos import garantir_gestor  # noqa: E402
from auditoria.dados_sinteticos import CARLOS, JOANA  # noqa: E402


class LLMFalso:
    """Substitui a API da Anthropic nos testes e guarda os prompts recebidos."""

    modelo = "llm-falso"

    def __init__(self) -> None:
        self.prompts: list[str] = []
        self.falhar = False

    def gerar(self, sistema: str, prompt: str) -> str:
        self.prompts.append(prompt)
        if self.falhar:
            raise ConnectionError("API indisponível")
        return json.dumps({
            "mensagem": "Tentaram acessar um dado seu, mas o sistema bloqueou. Seus dados estão protegidos.",
            "o_que_fazer": "Nenhuma ação necessária.",
            "remediacao_tecnica": ["Corrigir a rota.", "Adicionar teste."],
        }, ensure_ascii=False)


@pytest.fixture
def llm():
    falso = LLMFalso()
    tradutor.definir_cliente(falso)
    yield falso
    tradutor.definir_cliente(None)


@pytest.fixture
def cliente(llm):
    banco.reiniciar()
    banco.executar("DELETE FROM cache_traducao", verificar=False)
    garantir_gestor()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def cidadaos(cliente):
    """Cadastra Joana e Carlos e devolve ids e cabeçalhos de autenticação."""
    ids = {}
    for pessoa, nome in ((JOANA, "joana"), (CARLOS, "carlos")):
        ids[nome] = cliente.post("/api/v1/cidadaos", json=pessoa).json()["id"]
        token = cliente.post("/api/v1/auth/login", json={"login": pessoa["email"], "senha": pessoa["senha"]}).json()["token"]
        ids[f"{nome}_h"] = {"Authorization": f"Bearer {token}"}
    return ids


def caminho_log() -> Path:
    return Path(os.environ["AJA_LOG"])
