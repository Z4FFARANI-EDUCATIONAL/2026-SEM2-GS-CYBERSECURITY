"""Robustez do motor de parsing de PII."""

from app.pii.motor import motor
from app.pii.validadores import cpf_valido, rg_sp_valido


def ids(texto):
    return [a.regra.id for a in motor.analisar_texto(texto)]


def test_exemplo_do_enunciado_cpf_no_campo_documento():
    achados = motor.analisar({"documento": "123.456.789-00"})
    assert [a.regra.id for a in achados] == ["cpf"]
    assert achados[0].mascarado == "***.456.***-00"
    assert motor.mascarar({"documento": "123.456.789-00"}) == {"documento": "***.456.***-00"}


def test_cpf_no_texto_exige_digito_verificador_ou_a_palavra_cpf():
    assert ids("meu documento é 529.982.247-25") == ["cpf"]  # dígito verificador válido
    assert ids("CPF 123.456.789-00") == ["cpf"]  # inválido, mas com contexto
    assert ids("protocolo SP156 nº 20261234567") == []  # número qualquer não é CPF


def test_validadores():
    assert cpf_valido("529.982.247-25") and not cpf_valido("529.982.247-26") and not cpf_valido("111.111.111-11")
    assert rg_sp_valido("12.345.678-9") and not rg_sp_valido("12.345.678-0")


def test_rg_precisa_de_contexto_no_texto():
    assert ids("RG 12.345.678-9") == ["rg"]
    assert ids("código 12.345.678-9 do poste") == []


def test_telefone_formatado_sim_timestamp_nao():
    assert ids("me liga no (11) 90000-0001") == ["telefone"]
    assert ids('{"criado_em": 1794626861.63}') == []
    assert ids("whatsapp 11900000001") == ["telefone"]


def test_saude_autodeclaracao_e_detectada_mas_publico_afetado_nao():
    assert ids("Sou cega e tropecei no poste") == ["saude"]
    assert ids("Tenho baixa visão") == ["saude"]
    assert ids("CID H54.1 no laudo") == ["saude"]
    assert ids("o piso tátil ajuda pessoas cegas e com baixa visão") == []


def test_credenciais_em_texto_livre():
    assert ids("senha: Calcada#2026 ") == ["senha"]
    assert ids("chave sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == ["token"]
    assert ids("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123") == ["token"]


def test_endereco_residencial_e_diferente_do_local_da_barreira():
    assert ids("Moro na Rua das Acácias, 120.") == ["endereco"]
    assert ids("O buraco fica na Rua das Acácias, 120.") == []


def test_varredura_recursiva_e_campos_de_saude_inteiros():
    dados = {"cidadao": {"nome": "Joana Exemplo", "contatos": [{"email": "j@example.com"}]},
             "dados_de_saude": {"cid": "H54", "obs": "usa bengala"}}
    caminhos = {a.caminho: a.regra.id for a in motor.analisar(dados)}
    assert caminhos == {"$.cidadao.nome": "nome", "$.cidadao.contatos[0].email": "email",
                        "$.dados_de_saude.cid": "saude", "$.dados_de_saude.obs": "saude"}


def test_mascarar_devolve_copia_sem_alterar_original():
    original = {"senha": "Calcada#Segura2026", "descricao": "CPF 529.982.247-25"}
    mascarado = motor.mascarar(original)
    assert original["senha"] == "Calcada#Segura2026"
    assert mascarado == {"senha": "[senha removida]", "descricao": "CPF ***.982.***-25"}


def test_achado_nunca_imprime_o_valor():
    achado = motor.analisar({"cpf": "529.982.247-25"})[0]
    assert "529.982.247-25" not in repr(achado)
    assert "529.982.247-25" not in str(achado.resumo())
