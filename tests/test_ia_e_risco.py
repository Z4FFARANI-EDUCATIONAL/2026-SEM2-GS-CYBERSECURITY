"""Tradução via IA e indicador de Risco Cidadão."""

from app import banco
from app.seguranca import eventos, risco


def test_evento_e_traduzido_pelo_llm(cliente, llm):
    evento_id = eventos.registrar("RESPOSTA_BLOQUEADA", sink="resposta:http", decisao="bloqueado",
                                  detalhe="teste", categorias_extra=["saude"])
    evento = eventos.obter(evento_id)
    assert evento["origem_mensagem"] == "ia" and evento["modelo"] == "llm-falso"
    assert evento["mensagem"].startswith("Tentaram acessar")
    assert evento["remediacao"] == ["Corrigir a rota.", "Adicionar teste."]
    assert "cidadão leigo de 60 anos, em 2 frases" in llm.prompts[-1]


def test_mensagem_padrao_quando_a_api_falha(cliente, llm):
    llm.falhar = True
    evento = eventos.obter(eventos.registrar("LOGIN_SUSPEITO", sink="login", decisao="monitorado", detalhe="x"))
    assert evento["origem_mensagem"] == "padrao"
    assert "senha errada" in evento["mensagem"]


def test_cache_evita_chamar_o_llm_duas_vezes_para_o_mesmo_evento(cliente, llm):
    for _ in range(3):
        eventos.registrar("LOG_BLOQUEADO", sink="log:aja", decisao="mascarado", detalhe="mesmo detalhe")
    assert len(llm.prompts) == 1
    assert banco.consultar_um("SELECT COUNT(*) AS n FROM cache_traducao")["n"] == 1


def test_painel_do_cidadao_mostra_so_os_proprios_alertas_sem_detalhe_tecnico(cidadaos, cliente):
    cliente.get(f"/api/v1/legado/cidadaos/{cidadaos['joana']}")
    painel_joana = cliente.get("/api/v1/painel/cidadao", headers=cidadaos["joana_h"]).json()
    painel_carlos = cliente.get("/api/v1/painel/cidadao", headers=cidadaos["carlos_h"]).json()
    assert [a["tipo"] for a in painel_joana["alertas"]].count("RESPOSTA_BLOQUEADA") == 1
    assert "RESPOSTA_BLOQUEADA" not in [a["tipo"] for a in painel_carlos["alertas"]]
    assert "detalhe_tecnico" not in painel_joana["alertas"][0]


def test_painel_executivo_exige_gestor(cidadaos, cliente):
    assert cliente.get("/api/v1/painel/executivo", headers=cidadaos["joana_h"]).status_code == 403
    assert cliente.get("/api/v1/painel/executivo").status_code == 401


def _evento(tipo, peso, idade_s, titular=1, agora=10_000.0):
    return {"tipo": tipo, "peso": peso, "criado_em": agora - idade_s, "titular_id": titular}


def test_farol_verde_amarelo_vermelho():
    agora = 10_000.0
    assert risco.calcular([], 10, agora)["nivel"] == "verde"
    assert risco.calcular([_evento("LOG_BLOQUEADO", 12, 0)] * 3, 10, agora)["nivel"] == "amarelo"
    ataque = [_evento("RESPOSTA_BLOQUEADA", 25, 0)] * 3
    resultado = risco.calcular(ataque, 10, agora)
    assert resultado["nivel"] == "vermelho" and resultado["padrao_de_ataque"]


def test_peso_cai_com_o_tempo_e_some_apos_a_janela():
    agora = 10_000.0
    novo = risco.calcular([_evento("LOG_BLOQUEADO", 40, 0)], 10, agora)["indice"]
    meia_janela = risco.calcular([_evento("LOG_BLOQUEADO", 40, 300)], 10, agora)["indice"]
    velho = risco.calcular([_evento("LOG_BLOQUEADO", 40, 601)], 10, agora)["indice"]
    assert (novo, meia_janela, velho) == (40, 20, 0)


def test_dado_de_saude_pesa_mais(cliente, llm):
    comum = eventos.obter(eventos.registrar("LOG_BLOQUEADO", sink="log", decisao="mascarado", detalhe="a"))
    saude = eventos.obter(eventos.registrar("LOG_BLOQUEADO", sink="log", decisao="mascarado", detalhe="b",
                                            categorias_extra=["saude"]))
    assert saude["peso"] == comum["peso"] * eventos.FATOR_SENSIVEL
