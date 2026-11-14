"""Regras de detecção de PII (Personal Identifiable Information).

Cada regra pode atuar de dois jeitos:
- pelo **nome do campo** (ex.: `cpf`, `senha`, `laudo`): o valor inteiro do campo é PII;
- pelo **conteúdo** (regex): encontra o dado dentro de um texto livre, como a descrição de um relato.

Cada regra também diz se o dado é **sensível** pela LGPD (art. 5º, II, que inclui dados de saúde),
como ele aparece mascarado e como deve ser guardado no banco.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from app.pii import validadores as v


class Categoria(str, Enum):
    IDENTIFICACAO = "identificacao"
    CREDENCIAL = "credencial"
    SAUDE = "saude"
    CONTATO = "contato"
    LOCALIZACAO = "localizacao"


class Tratamento(str, Enum):
    """Como o dado é guardado no banco."""

    CRIPTOGRAFAR = "criptografar"  # Fernet (AES + HMAC); só a aplicação consegue ler
    HASH = "hash"  # irreversível (scrypt para senhas)
    MASCARAR = "mascarar"  # guarda apenas a versão mascarada (texto público)
    DESCARTAR = "descartar"  # não é guardado


ROTULO_CATEGORIA = {
    Categoria.IDENTIFICACAO: "documento de identificação",
    Categoria.CREDENCIAL: "senha ou chave de acesso",
    Categoria.SAUDE: "informação de saúde",
    Categoria.CONTATO: "contato pessoal",
    Categoria.LOCALIZACAO: "endereço residencial",
}


# --- máscaras ---------------------------------------------------------------------------------

def mascarar_cpf(valor: str) -> str:
    d = v.digitos(valor)
    if len(d) != 11:
        return "***.***.***-**"
    return f"***.{d[3:6]}.***-{d[9:]}"


def mascarar_rg(valor: str) -> str:
    bruto = re.sub(r"[^\dXx]", "", valor)
    return "**.***.*" + bruto[-3:-1] + "-" + bruto[-1:] if len(bruto) >= 3 else "**.***.***-*"


def mascarar_nome(valor: str) -> str:
    particulas = {"da", "de", "do", "das", "dos", "e"}
    partes = [p for p in valor.split() if p and p.lower() not in particulas]
    return " ".join(f"{p[0].upper()}." for p in partes) if partes else "[nome protegido]"


def mascarar_email(valor: str) -> str:
    if "@" not in valor:
        return "***@***"
    usuario, dominio = valor.split("@", 1)
    nome_dominio, _, tld = dominio.rpartition(".")
    return f"{usuario[:1]}***@{(nome_dominio or dominio)[:1]}***.{tld or '***'}"


def mascarar_telefone(valor: str) -> str:
    d = v.digitos(valor)
    return f"(**) *****-**{d[-2:]}" if len(d) >= 8 else "(**) *****-****"


def mascarar_cep(valor: str) -> str:
    d = v.digitos(valor)
    return f"{d[:2]}***-***" if len(d) == 8 else "*****-***"


def mascarar_data(valor: str) -> str:
    ano = re.search(r"(19|20)\d{2}", valor)
    return f"**/**/{ano.group(0)}" if ano else "**/**/****"


def _fixo(texto: str) -> Callable[[str], str]:
    return lambda _valor: texto


# --- regras -----------------------------------------------------------------------------------

@dataclass(frozen=True)
class Regra:
    id: str
    nome: str
    categoria: Categoria
    sensivel: bool
    mascara: Callable[[str], str]
    tratamento: Tratamento
    chave: re.Pattern[str] | None = None
    padrao: re.Pattern[str] | None = None
    grupo: int = 0
    validar: Callable[[str, str], bool] | None = None  # (valor, texto_antes) -> é PII?
    prioridade: int = 50


def _chave(*nomes: str) -> re.Pattern[str]:
    return re.compile(r"^(?:" + "|".join(nomes) + r")$")


def _cpf_no_texto(valor: str, antes: str) -> bool:
    return v.cpf_valido(valor) or v.contexto_contem(antes, ("cpf",))


def _cep_no_texto(valor: str, antes: str) -> bool:
    return "-" in valor or v.contexto_contem(antes, ("cep",))


def _telefone_no_texto(valor: str, antes: str) -> bool:
    if len(v.digitos(valor)) < 10:
        return False
    if re.search(r"[()\s-]", valor) or valor.startswith("+"):
        return True
    # Só dígitos (ex.: 11900000001): exige contexto, senão timestamps, protocolos e IDs viram telefone.
    return v.contexto_contem(antes, ("tel", "telefone", "celular", "cel", "whatsapp", "zap", "fone",
                                     "contato", "liga", "ligar"))


REGRAS: tuple[Regra, ...] = (
    Regra(
        id="cpf", nome="CPF", categoria=Categoria.IDENTIFICACAO, sensivel=False,
        mascara=mascarar_cpf, tratamento=Tratamento.CRIPTOGRAFAR,
        chave=_chave("cpf", "documento", "doc", "num_cpf", "nr_cpf", "cpf_cnpj"),
        padrao=re.compile(r"(?<![\d.])(\d{3}\.?\d{3}\.?\d{3}-?\d{2})(?![\d])"), grupo=1,
        validar=_cpf_no_texto, prioridade=90,
    ),
    Regra(
        id="rg", nome="RG", categoria=Categoria.IDENTIFICACAO, sensivel=False,
        mascara=mascarar_rg, tratamento=Tratamento.CRIPTOGRAFAR,
        chave=_chave("rg", "registro_geral", "identidade", "num_rg"),
        padrao=re.compile(r"(?i)\bRG\b[\s:nº°.]*(\d{1,2}\.?\d{3}\.?\d{3}-?[\dX])(?![\w])"), grupo=1,
        prioridade=85,
    ),
    Regra(
        id="nome", nome="Nome completo", categoria=Categoria.IDENTIFICACAO, sensivel=False,
        mascara=mascarar_nome, tratamento=Tratamento.CRIPTOGRAFAR,
        chave=_chave("nome", "nome_completo", "nome_social", "name", "full_name"),
        padrao=re.compile(
            r"(?:[Mm]eu nome é|[Mm]e chamo|[Aa]ssinado:?|[Aa]ss\.:?|[Aa]tenciosamente,?)\s+"
            r"([A-ZÀ-Ý][a-zà-ÿ]+(?:\s+(?:d[aeo]s?\s+)?[A-ZÀ-Ý][a-zà-ÿ]+){1,4})"
        ),
        grupo=1, prioridade=60,
    ),
    Regra(
        id="data_nascimento", nome="Data de nascimento", categoria=Categoria.IDENTIFICACAO,
        sensivel=False, mascara=mascarar_data, tratamento=Tratamento.CRIPTOGRAFAR,
        chave=_chave("data_nascimento", "nascimento", "dt_nascimento", "birth_date"),
        prioridade=40,
    ),
    Regra(
        id="senha", nome="Senha", categoria=Categoria.CREDENCIAL, sensivel=False,
        mascara=_fixo("[senha removida]"), tratamento=Tratamento.HASH,
        chave=_chave("senha", "password", "pass", "pwd", "nova_senha", "senha_atual", "confirmacao_senha"),
        padrao=re.compile(r"(?i)\b(?:senha|password|pwd)\s*(?:[:=]|é|eh)\s*(\S{4,}?)(?=[.,;]?(?:\s|$))"), grupo=1,
        prioridade=95,
    ),
    Regra(
        id="token", nome="Token ou chave de API", categoria=Categoria.CREDENCIAL, sensivel=False,
        mascara=_fixo("[credencial removida]"), tratamento=Tratamento.DESCARTAR,
        chave=_chave("token", "access_token", "refresh_token", "api_key", "apikey", "chave_api",
                     "secret", "segredo", "authorization"),
        padrao=re.compile(
            r"(?i)(?:\bbearer\s+([A-Za-z0-9._~+/-]{19,}[A-Za-z0-9~+/=-])"
            r"|\b(sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}))"
        ),
        grupo=1, prioridade=95,
    ),
    Regra(
        id="saude", nome="Dado de saúde", categoria=Categoria.SAUDE, sensivel=True,
        mascara=_fixo("[informação de saúde protegida]"), tratamento=Tratamento.CRIPTOGRAFAR,
        chave=_chave("laudo", "laudo_medico", "cid", "cid10", "deficiencia", "tipo_deficiencia",
                     "diagnostico", "condicao_saude", "dados_saude", "dados_de_saude", "historico_medico"),
        # Só conta como dado de saúde quando a pessoa fala de si ("sou cega", "tenho baixa visão"),  pii-ok
        # e não quando descreve o público afetado ("piso tátil para pessoas cegas").
        padrao=re.compile(
            r"(?i)(?:\b(CID[-\s]?(?:10)?[\s:]*[A-TV-Z]\d{2}(?:\.\d{1,2})?)\b"
            r"|\b(?:sou|estou|fiquei|tenho|portador[a]? de|convivo com|minha|meu)\s+"
            r"(?:uma?\s+)?(?:pessoa\s+)?(?:com\s+)?(cego|cega|surdo|surda|surdocego|surdocega"
            r"|baixa vis[ãa]o|defici[êe]ncia (?:visual|auditiva)|surdez|cegueira|perda auditiva"
            r"|glaucoma|retinopatia|implante coclear|aparelho auditivo)\b"
            r"|\b(laudo m[ée]dico\b[^.;\n]{0,60}))"
        ),
        grupo=1, prioridade=70,
    ),
    Regra(
        id="email", nome="E-mail", categoria=Categoria.CONTATO, sensivel=False,
        mascara=mascarar_email, tratamento=Tratamento.CRIPTOGRAFAR,
        chave=_chave("email", "e_mail", "email_contato"),
        padrao=re.compile(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"), grupo=1,
        prioridade=80,
    ),
    Regra(
        id="telefone", nome="Telefone", categoria=Categoria.CONTATO, sensivel=False,
        mascara=mascarar_telefone, tratamento=Tratamento.CRIPTOGRAFAR,
        chave=_chave("telefone", "celular", "fone", "phone", "whatsapp"),
        padrao=re.compile(r"(?<![\d.])((?:\+?55\s?)?\(?[1-9]{2}\)?\s?9?\d{4}[-\s]?\d{4})(?!\d)"),
        grupo=1, validar=_telefone_no_texto, prioridade=75,
    ),
    Regra(
        id="endereco", nome="Endereço residencial", categoria=Categoria.LOCALIZACAO, sensivel=False,
        mascara=_fixo("[endereço residencial protegido]"), tratamento=Tratamento.CRIPTOGRAFAR,
        chave=_chave("endereco", "endereco_residencial", "residencia", "logradouro_residencial",
                     "endereco_casa"),
        padrao=re.compile(
            r"(?i)\b(?:moro|resido|minha casa (?:fica|é)|meu endere[çc]o (?:é|e))\s+(?:na|no|em)?\s*"
            r"((?:rua|r\.|avenida|av\.|travessa|tv\.|alameda|al\.|estrada|pra[çc]a)\s+"
            r"[^,.;\n]{2,60}(?:,\s*(?:n[º°o.]?\s*)?\d{1,5})?)"
        ),
        grupo=1, prioridade=65,
    ),
    Regra(
        id="cep", nome="CEP", categoria=Categoria.LOCALIZACAO, sensivel=False,
        mascara=mascarar_cep, tratamento=Tratamento.CRIPTOGRAFAR,
        chave=_chave("cep", "cep_residencial"),
        padrao=re.compile(r"(?<![\d.])(\d{5}-?\d{3})(?!\d)"), grupo=1,
        validar=_cep_no_texto, prioridade=55,
    ),
)

REGRAS_POR_ID = {r.id: r for r in REGRAS}


def normalizar_chave(nome: str) -> str:
    """`E-mail` -> `e_mail`; `Endereço Residencial` -> `endereco_residencial`."""
    sem_acento = unicodedata.normalize("NFKD", nome).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "_", sem_acento.lower()).strip("_")
