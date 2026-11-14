"""Banco SQLite do AJA, com a guarda de taint do sink "banco".

Toda gravação passa por `executar`. Antes do SQL rodar, cada parâmetro é inspecionado: se um dado
pessoal chegar aqui em texto claro (sem criptografia, hash ou máscara), a gravação é impedida.
"""

from __future__ import annotations

import sqlite3
import threading
from typing import Any, Iterable

from app import config
from app.seguranca.cripto import parece_protegido
from app.taint.sinks import VazamentoBloqueado, categorias, inspecionar, titular_principal

_ESQUEMA = """
CREATE TABLE IF NOT EXISTS cidadaos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    perfil TEXT NOT NULL DEFAULT 'cidadao',
    nome_cifrado TEXT NOT NULL,
    nome_mascarado TEXT NOT NULL,
    cpf_indice TEXT UNIQUE,
    cpf_cifrado TEXT,
    cpf_mascarado TEXT,
    rg_cifrado TEXT,
    email_indice TEXT UNIQUE NOT NULL,
    email_cifrado TEXT NOT NULL,
    email_mascarado TEXT NOT NULL,
    telefone_cifrado TEXT,
    nascimento_cifrado TEXT,
    deficiencia_cifrada TEXT,
    endereco_cifrado TEXT,
    senha_hash TEXT NOT NULL,
    criado_em TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE TABLE IF NOT EXISTS sessoes (
    token_hash TEXT PRIMARY KEY,
    cidadao_id INTEGER NOT NULL REFERENCES cidadaos(id),
    expira_em REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tentativas_login (
    indice TEXT NOT NULL,
    momento REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS topicos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chave TEXT UNIQUE NOT NULL,
    titulo TEXT NOT NULL,
    categoria TEXT NOT NULL,
    local_referencia TEXT NOT NULL,
    publico_afetado TEXT NOT NULL,
    criado_em TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE TABLE IF NOT EXISTS relatos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    topico_id INTEGER NOT NULL REFERENCES topicos(id),
    autor_id INTEGER NOT NULL REFERENCES cidadaos(id),
    descricao_publica TEXT NOT NULL,
    latitude REAL,
    longitude REAL,
    criado_em TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE TABLE IF NOT EXISTS apoios (
    topico_id INTEGER NOT NULL REFERENCES topicos(id),
    cidadao_id INTEGER NOT NULL REFERENCES cidadaos(id),
    PRIMARY KEY (topico_id, cidadao_id)
);
CREATE TABLE IF NOT EXISTS eventos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    criado_em REAL NOT NULL,
    tipo TEXT NOT NULL,
    sink TEXT NOT NULL,
    rota TEXT,
    categorias TEXT NOT NULL,
    sensivel INTEGER NOT NULL,
    decisao TEXT NOT NULL,
    detalhe_tecnico TEXT NOT NULL,
    titular_id INTEGER,
    peso REAL NOT NULL,
    mensagem TEXT,
    o_que_fazer TEXT,
    remediacao TEXT,
    origem_mensagem TEXT NOT NULL DEFAULT 'pendente',
    modelo TEXT
);
CREATE TABLE IF NOT EXISTS contatos_legado (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidadao_id INTEGER,
    telefone TEXT
);
CREATE TABLE IF NOT EXISTS cache_traducao (
    chave TEXT PRIMARY KEY,
    resposta TEXT NOT NULL,
    modelo TEXT NOT NULL
);
"""

_TABELAS = ("contatos_legado", "eventos", "apoios", "relatos", "topicos", "tentativas_login", "sessoes", "cidadaos")

_trava = threading.RLock()
_conexao: sqlite3.Connection | None = None


def _conectar() -> sqlite3.Connection:
    global _conexao
    if _conexao is None:
        caminho = config.obter().caminho_banco
        caminho.parent.mkdir(parents=True, exist_ok=True)
        _conexao = sqlite3.connect(caminho, check_same_thread=False, isolation_level=None)
        _conexao.row_factory = sqlite3.Row
        _conexao.execute("PRAGMA foreign_keys = ON")
        _conexao.executescript(_ESQUEMA)
    return _conexao


def fechar() -> None:
    global _conexao
    with _trava:
        if _conexao is not None:
            _conexao.close()
            _conexao = None


def guarda_banco(sql: str, parametros: Iterable[Any]) -> None:
    """Sink "banco": nenhum dado pessoal em texto claro pode virar parâmetro de um INSERT/UPDATE."""
    deteccoes = []
    for valor in parametros:
        if isinstance(valor, str) and not parece_protegido(valor):
            deteccoes.extend(inspecionar(valor))
    if not deteccoes:
        return
    from app.seguranca import eventos  # import tardio: eventos também grava no banco

    tabela = sql.split()[2] if sql.lstrip().upper().startswith("INSERT") else "?"
    evento_id = eventos.registrar(
        "BANCO_BLOQUEADO", sink=f"banco:{tabela}", deteccoes=deteccoes, decisao="bloqueado",
        detalhe=f"Tentativa de gravar {', '.join(categorias(deteccoes))} sem proteção na tabela {tabela}.",
        titular_id=titular_principal(deteccoes),
    )
    raise VazamentoBloqueado(f"banco:{tabela}", deteccoes, evento_id)


def executar(sql: str, parametros: Iterable[Any] = (), *, verificar: bool = True) -> int:
    parametros = tuple(parametros)
    if verificar:
        guarda_banco(sql, parametros)
    with _trava:
        cursor = _conectar().execute(sql, parametros)
        return cursor.lastrowid


def consultar(sql: str, parametros: Iterable[Any] = ()) -> list[dict[str, Any]]:
    with _trava:
        return [dict(linha) for linha in _conectar().execute(sql, tuple(parametros)).fetchall()]


def consultar_um(sql: str, parametros: Iterable[Any] = ()) -> dict[str, Any] | None:
    linhas = consultar(sql, parametros)
    return linhas[0] if linhas else None


def reiniciar() -> None:
    """Apaga todos os dados (usado no modo de demonstração e nos testes)."""
    with _trava:
        conexao = _conectar()
        for tabela in _TABELAS:
            conexao.execute(f"DELETE FROM {tabela}")
        conexao.execute("DELETE FROM sqlite_sequence")
