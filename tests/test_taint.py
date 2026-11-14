"""Eficácia do taint analysis: cada sink barra o dado pessoal."""

import io
import logging

import pytest
from pypdf import PdfReader

from app import banco
from app.ia import tradutor
from app.pii.regras import REGRAS_POR_ID
from app.seguranca import eventos
from app.taint import contexto
from app.taint.logs import FiltroTaintLog
from app.taint.sinks import VazamentoBloqueado
from auditoria.dados_sinteticos import CARLOS, JOANA, LOCAL, VALORES_PROIBIDOS
from tests.conftest import caminho_log


def tipos_de_evento():
    return [e["tipo"] for e in eventos.listar(limite=200)]


def test_log_ingenuo_do_cadastro_sai_mascarado(cliente):
    cliente.post("/api/v1/cidadaos", json=JOANA)
    log = caminho_log().read_text(encoding="utf-8")
    linha = next(l for l in log.splitlines() if "Novo cadastro" in l and "J. E. S." in l)
    assert "guarda de taint" in linha
    assert not any(v in linha for v in VALORES_PROIBIDOS)
    assert "LOG_BLOQUEADO" in tipos_de_evento()


def test_filtro_barra_logger_info_de_dados_de_saude(cliente):
    """O exemplo do enunciado: logger.info(dados_de_saude)."""
    ctx = contexto.ContextoTaint("POST", "/teste")
    ctx.marcar("glaucoma avançado", REGRAS_POR_ID["saude"], "teste", titular_id=None)
    token = contexto.iniciar(ctx)
    try:
        registro = logging.getLogger("aja.teste").makeRecord(
            "aja.teste", logging.INFO, __file__, 1, "dados_de_saude=%s", ("glaucoma avançado",), None)
        FiltroTaintLog().filter(registro)
    finally:
        contexto.encerrar(token)
    assert "glaucoma" not in registro.getMessage()
    assert "[informação de saúde protegida]" in registro.getMessage()


def test_excecao_com_cpf_na_mensagem_nao_vaza_no_traceback(cliente):
    try:
        raise ValueError("CPF inválido: 529.982.247-25")
    except ValueError:
        logging.getLogger("aja.teste").exception("falhou")
    assert "529.982.247-25" not in caminho_log().read_text(encoding="utf-8")


def test_erro_422_nao_devolve_o_valor_recebido(cliente):
    r = cliente.post("/api/v1/cidadaos", json={**JOANA, "cpf": "123.456.789-00"})
    assert r.status_code == 422
    assert "123.456.789-00" not in r.text and JOANA["senha"] not in r.text
    assert r.json()["campos"][0]["campo"] == "cpf"
    assert "ERRO_SANITIZADO" in tipos_de_evento()


def test_rota_sem_controle_de_acesso_e_bloqueada_sem_login(cidadaos, cliente):
    r = cliente.get(f"/api/v1/legado/cidadaos/{cidadaos['joana']}")
    assert r.status_code == 403
    assert not any(v in r.text for v in VALORES_PROIBIDOS)
    evento = eventos.listar(limite=1)[0]
    assert evento["tipo"] == "RESPOSTA_BLOQUEADA" and evento["titular_id"] == cidadaos["joana"]


def test_idor_outro_cidadao_logado_e_bloqueado(cidadaos, cliente):
    r = cliente.get(f"/api/v1/legado/cidadaos/{cidadaos['joana']}", headers=cidadaos["carlos_h"])
    assert r.status_code == 403


def test_titular_recebe_os_proprios_dados(cidadaos, cliente):
    r = cliente.get(f"/api/v1/legado/cidadaos/{cidadaos['joana']}", headers=cidadaos["joana_h"])
    assert r.status_code == 200 and r.json()["cpf"] == JOANA["cpf"]
    assert cliente.get("/api/v1/cidadaos/me", headers=cidadaos["joana_h"]).json()["nome"] == JOANA["nome"]


def test_banco_recusa_dado_pessoal_em_texto_claro(cidadaos, cliente):
    r = cliente.post(f"/api/v1/legado/cidadaos/{cidadaos['joana']}/contato", json={"telefone": JOANA["telefone"]})
    assert r.status_code == 403 and r.json()["erro"] == "gravacao_bloqueada"
    assert banco.consultar_um("SELECT COUNT(*) AS n FROM contatos_legado")["n"] == 0
    assert "BANCO_BLOQUEADO" in tipos_de_evento()


def test_guarda_do_banco_direto_no_codigo(cliente):
    ctx = contexto.ContextoTaint("POST", "/teste")
    ctx.marcar("529.982.247-25", REGRAS_POR_ID["cpf"], "teste")
    token = contexto.iniciar(ctx)
    try:
        with pytest.raises(VazamentoBloqueado):
            banco.executar("INSERT INTO contatos_legado (telefone) VALUES (?)", ("52998224725",))
    finally:
        contexto.encerrar(token)


def test_nada_em_texto_claro_no_banco_depois_do_cadastro(cidadaos):
    for linha in banco.consultar("SELECT * FROM cidadaos"):
        conteudo = " ".join(str(v) for v in linha.values())
        assert not any(v in conteudo for v in VALORES_PROIBIDOS)


def test_relato_publico_mascara_autor_e_pessoa_citada(cidadaos, cliente):
    r1 = cliente.post("/api/v1/relatos", headers=cidadaos["joana_h"], json={
        "descricao": "Sou cega, me liga no (11) 90000-0001. Joana Exemplo da Silva",
        "categoria": "piso_tatil", "local_referencia": LOCAL, "publico_afetado": "visual"})
    texto1 = r1.json()["descricao_publicada"]
    assert "cega" not in texto1 and "90000-0001" not in texto1 and "Joana" not in texto1
    r2 = cliente.post("/api/v1/relatos", headers=cidadaos["carlos_h"], json={
        "descricao": "Falei com a Joana Silva: o piso tátil para pessoas cegas acaba ali.",
        "categoria": "piso_tatil", "local_referencia": LOCAL, "publico_afetado": "visual"})
    texto2 = r2.json()["descricao_publicada"]
    assert "Joana Silva" not in texto2 and "pessoas cegas" in texto2


def test_dossie_nao_identifica_quem_relatou(cidadaos, cliente):
    r = cliente.post("/api/v1/relatos", headers=cidadaos["joana_h"], json={
        "descricao": "O piso tátil acaba antes da banca.", "categoria": "piso_tatil",
        "local_referencia": LOCAL, "publico_afetado": "visual"})
    cliente.post("/api/v1/relatos", headers=cidadaos["carlos_h"], json={
        "descricao": "Confirmo o problema.", "categoria": "piso_tatil",
        "local_referencia": LOCAL, "publico_afetado": "visual"})
    pdf = cliente.get(f"/api/v1/topicos/{r.json()['topico_id']}/dossie")
    texto = "".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf.content)).pages)
    assert "Morador(a) A" in texto and "Morador(a) B" in texto
    assert "Joana" not in texto and "Carlos" not in texto
    assert tipos_de_evento().count("DOSSIE_SANITIZADO") == 2


def test_prompt_do_llm_e_inspecionado_antes_do_envio(cliente, llm, monkeypatch):
    original = tradutor.montar_prompt
    monkeypatch.setattr(tradutor, "montar_prompt", lambda ev: original(ev) + "\nContato: (11) 90000-0001")
    eventos.registrar("LOG_BLOQUEADO", sink="log:teste", decisao="mascarado", detalhe="teste")
    assert llm.prompts and all("90000-0001" not in p for p in llm.prompts)
    assert "LLM_PROMPT_SANITIZADO" in tipos_de_evento()


def test_cpf_na_query_string_e_marcado_como_source(cidadaos, cliente):
    login = cliente.post("/api/v1/auth/login", json={"login": "gestor@aja.exemplo.com", "senha": "Gestor#Teste2026"})
    gestor = {"Authorization": f"Bearer {login.json()['token']}"}
    r = cliente.get("/api/v1/cidadaos/busca", params={"cpf": CARLOS["cpf"]}, headers=gestor)
    assert r.status_code == 200 and r.json()["encontrado"] is True
    assert CARLOS["cpf"] not in r.text
