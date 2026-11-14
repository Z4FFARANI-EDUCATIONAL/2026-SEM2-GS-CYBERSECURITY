"""Cadastro, login e perfil do cidadão."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app import banco, config
from app.pii.regras import REGRAS_POR_ID, mascarar_cpf, mascarar_email, mascarar_nome
from app.pii.validadores import cpf_valido
from app.seguranca import auth, cripto
from app.taint.contexto import ContextoTaint, atual

router = APIRouter(prefix="/api/v1", tags=["Cidadãos"])
log = logging.getLogger("aja.cidadaos")

# coluna cifrada no banco -> regra de PII usada para marcar o valor quando ele é decifrado
COLUNAS_PROTEGIDAS = {
    "nome_cifrado": "nome",
    "cpf_cifrado": "cpf",
    "rg_cifrado": "rg",
    "email_cifrado": "email",
    "telefone_cifrado": "telefone",
    "nascimento_cifrado": "data_nascimento",
    "deficiencia_cifrada": "saude",
    "endereco_cifrado": "endereco",
}


class CadastroCidadao(BaseModel):
    # Os exemplos da documentação não têm formato de dado real: o próprio openapi.json passa pela
    # guarda de resposta, e um CPF de exemplo bloquearia o Swagger para quem não está logado.
    model_config = ConfigDict(json_schema_extra={"example": {
        "nome": "Nome completo do cidadão",
        "cpf": "CPF com 11 dígitos",
        "email": "e-mail do cidadão",
        "senha": "senha com 8 ou mais caracteres",
        "telefone": "celular com DDD (opcional)",
        "deficiencia": "baixa visão (opcional)",
        "endereco_residencial": "rua e número da casa (opcional)",
    }})

    nome: str = Field(min_length=3, max_length=120)
    cpf: str = Field(description="CPF do cidadão. Guardado criptografado; o login usa um índice cego (HMAC).")
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    senha: str = Field(min_length=8, max_length=128, description="Guardada só como hash scrypt.")
    telefone: str | None = None
    rg: str | None = None
    data_nascimento: str | None = None
    deficiencia: str | None = Field(
        None, max_length=120,
        description="Dado de saúde (LGPD art. 5º, II). Opcional; serve para adaptar os avisos (leitor de tela, Libras).",
    )
    endereco_residencial: str | None = Field(None, max_length=200)

    @field_validator("cpf")
    @classmethod
    def _cpf_valido(cls, valor: str) -> str:
        if not cpf_valido(valor):
            raise ValueError("CPF inválido")
        return valor


class Login(BaseModel):
    login: str = Field(description="CPF ou e-mail")
    senha: str


def _decifrar_e_marcar(linha: dict, ctx: ContextoTaint | None) -> dict[str, str | None]:
    """Source "banco": todo valor decifrado volta a ser marcado, com o titular certo."""
    valores = {}
    for coluna, regra_id in COLUNAS_PROTEGIDAS.items():
        valor = cripto.decifrar(linha.get(coluna))
        valores[regra_id] = valor
        if ctx is not None and valor:
            ctx.marcar(valor, REGRAS_POR_ID[regra_id], f"banco:cidadaos.{coluna}", titular_id=linha["id"])
    return valores


def marcar_identidade(cidadao_id: int) -> dict[str, str | None]:
    linha = banco.consultar_um("SELECT * FROM cidadaos WHERE id = ?", (cidadao_id,))
    return _decifrar_e_marcar(linha, atual()) if linha else {}


def _perfil(linha: dict) -> dict:
    valores = _decifrar_e_marcar(linha, atual())
    return {
        "id": linha["id"],
        "nome": valores["nome"],
        "cpf": valores["cpf"],
        "email": valores["email"],
        "telefone": valores["telefone"],
        "deficiencia": valores["saude"],
        "endereco_residencial": valores["endereco"],
        "criado_em": linha["criado_em"],
    }


@router.post("/cidadaos", status_code=status.HTTP_201_CREATED, summary="Cadastrar cidadão")
def cadastrar(dados: CadastroCidadao):
    # Log de depuração ingênuo, mantido de propósito: imprime o cadastro inteiro.
    # A guarda de taint dos logs precisa barrar aqui o CPF, a senha e o dado de saúde.
    log.info("Novo cadastro recebido: %s", dados.model_dump())

    cpf_indice = cripto.indice_cego(dados.cpf)
    email_indice = cripto.indice_cego(dados.email)
    if banco.consultar_um("SELECT id FROM cidadaos WHERE cpf_indice = ? OR email_indice = ?",
                          (cpf_indice, email_indice)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Já existe uma conta com este CPF ou e-mail.")

    novo_id = banco.executar(
        "INSERT INTO cidadaos (nome_cifrado, nome_mascarado, cpf_indice, cpf_cifrado, cpf_mascarado, "
        "rg_cifrado, email_indice, email_cifrado, email_mascarado, telefone_cifrado, nascimento_cifrado, "
        "deficiencia_cifrada, endereco_cifrado, senha_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            cripto.cifrar(dados.nome), mascarar_nome(dados.nome),
            cpf_indice, cripto.cifrar(dados.cpf), mascarar_cpf(dados.cpf),
            cripto.cifrar(dados.rg),
            email_indice, cripto.cifrar(dados.email), mascarar_email(dados.email),
            cripto.cifrar(dados.telefone), cripto.cifrar(dados.data_nascimento),
            cripto.cifrar(dados.deficiencia), cripto.cifrar(dados.endereco_residencial),
            cripto.hash_senha(dados.senha),
        ),
    )
    ctx = atual()
    if ctx is not None:
        ctx.definir_titular(novo_id)
    log.info("Cidadão %s cadastrado", novo_id)
    return {
        "id": novo_id,
        "nome": mascarar_nome(dados.nome),
        "cpf": mascarar_cpf(dados.cpf),
        "email": mascarar_email(dados.email),
        "mensagem": "Cadastro criado. Seus dados pessoais ficam guardados com criptografia.",
    }


@router.post("/auth/login", summary="Entrar")
def entrar(dados: Login):
    indice = cripto.indice_cego(dados.login)
    linha = banco.consultar_um(
        "SELECT id, perfil, senha_hash, nome_mascarado FROM cidadaos WHERE cpf_indice = ? OR email_indice = ?",
        (indice, indice),
    )
    if not linha or not cripto.conferir_senha(dados.senha, linha["senha_hash"]):
        auth.registrar_falha(indice, linha["id"] if linha else None)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Login ou senha incorretos.")
    auth.limpar_falhas(indice)
    return {"token": auth.criar_sessao(linha["id"]), "perfil": linha["perfil"], "nome": linha["nome_mascarado"]}


@router.get("/cidadaos/me", summary="Meus dados (somente o titular)")
def meus_dados(ctx: ContextoTaint = Depends(auth.exigir_login)):
    linha = banco.consultar_um("SELECT * FROM cidadaos WHERE id = ?", (ctx.cidadao_id,))
    return _perfil(linha)


@router.get("/cidadaos/busca", summary="Buscar cidadão por CPF (equipe AJA)")
def buscar_por_cpf(cpf: str = Query(..., description="CPF a buscar"), _: ContextoTaint = Depends(auth.exigir_gestor)):
    linha = banco.consultar_um("SELECT id, nome_mascarado FROM cidadaos WHERE cpf_indice = ?", (cripto.indice_cego(cpf),))
    return {"encontrado": bool(linha), "id": linha["id"] if linha else None,
            "nome": linha["nome_mascarado"] if linha else None}


@router.get(
    "/legado/cidadaos/{cidadao_id}",
    tags=["Auditoria"],
    summary="Rota legada SEM controle de acesso (mantida para a auditoria)",
    description="Simula um endpoint antigo que devolve o perfil completo sem conferir quem pede. "
                "Serve para provar que a guarda de taint da resposta bloqueia o vazamento mesmo "
                "quando a rota esquece a autorização.",
)
def perfil_legado(cidadao_id: int):
    linha = banco.consultar_um("SELECT * FROM cidadaos WHERE id = ?", (cidadao_id,))
    if not linha:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Cidadão não encontrado.")
    return _perfil(linha)


class ContatoLegado(BaseModel):
    telefone: str


@router.post(
    "/legado/cidadaos/{cidadao_id}/contato",
    tags=["Auditoria"],
    summary="Rota legada que grava o telefone SEM criptografia (mantida para a auditoria)",
    description="Simula um código antigo que salva o contato em texto claro. Serve para provar que a "
                "guarda de taint do banco impede a gravação.",
)
def contato_legado(cidadao_id: int, dados: ContatoLegado):
    banco.executar("INSERT INTO contatos_legado (cidadao_id, telefone) VALUES (?, ?)", (cidadao_id, dados.telefone))
    return {"ok": True}


def garantir_gestor() -> None:
    """Cria a conta da equipe AJA (perfil gestor) a partir do .env, se ainda não existir."""
    cfg = config.obter()
    if not cfg.gestor_senha:
        return
    indice = cripto.indice_cego(cfg.gestor_email)
    if banco.consultar_um("SELECT id FROM cidadaos WHERE email_indice = ?", (indice,)):
        return
    banco.executar(
        "INSERT INTO cidadaos (perfil, nome_cifrado, nome_mascarado, email_indice, email_cifrado, "
        "email_mascarado, senha_hash) VALUES ('gestor', ?, ?, ?, ?, ?, ?)",
        (cripto.cifrar("Equipe AJA"), "Equipe AJA", indice, cripto.cifrar(cfg.gestor_email),
         mascarar_email(cfg.gestor_email), cripto.hash_senha(cfg.gestor_senha)),
        verificar=False,  # conta técnica criada na inicialização, fora de uma requisição
    )
