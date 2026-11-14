"""Pessoas fictícias usadas na auditoria e nos testes.

Nenhum dado é real. Os CPFs são números de exemplo amplamente usados em documentação (dígito
verificador válido, sem titular conhecido), os e-mails usam o domínio reservado example.com e os
telefones seguem o padrão 90000-00xx.
"""

JOANA = {
    "nome": "Joana Exemplo da Silva",
    "cpf": "529.982.247-25",
    "email": "joana.exemplo@example.com",
    "senha": "Calcada#Segura2026",
    "telefone": "(11) 90000-0001",
    "deficiencia": "baixa visão",
    "endereco_residencial": "Rua Fictícia das Acácias, 120",
}

CARLOS = {
    "nome": "Carlos Modelo Pereira",
    "cpf": "111.444.777-35",
    "email": "carlos.modelo@example.com",
    "senha": "Travessia#Sonora26",
    "telefone": "(11) 90000-0002",
    "deficiencia": "surdez",
}

LOCAL = "Rua Exemplo do Parque Doroteia, 300 (em frente à banca)"

# Valores que nunca podem aparecer em texto claro no log nem no banco.
VALORES_PROIBIDOS = [
    JOANA["cpf"], "52998224725", JOANA["email"], JOANA["senha"], JOANA["telefone"], "11900000001",
    JOANA["endereco_residencial"], JOANA["nome"],
    CARLOS["cpf"], "11144477735", CARLOS["email"], CARLOS["senha"], CARLOS["telefone"], CARLOS["nome"],
]
