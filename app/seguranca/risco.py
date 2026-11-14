"""Indicador de Risco Cidadão (0 a 100) e o farol verde / amarelo / vermelho.

Cada evento soma o seu peso (maior para dados de saúde), e esse peso cai em linha reta até zero ao
fim da janela (10 minutos por padrão).

- **Eventos de rotina** (dado mascarado no log, no erro, no relato, no dossiê ou no prompt; gravação
  insegura impedida) mostram que o sistema barrou um vazamento. Sozinhos, levam no máximo ao amarelo.
- **Tentativas de ataque** (acesso aos dados de alguém sem permissão, muitas senhas erradas) são as
  únicas que levam ao vermelho. Três ou mais contra a mesma pessoa somam um adicional.
"""

from __future__ import annotations

import time
from collections import Counter

LIMITE_AMARELO = 30
LIMITE_VERMELHO = 70
ADICIONAL_ATAQUE = 40
TIPOS_DE_ATAQUE = {"RESPOSTA_BLOQUEADA", "LOGIN_SUSPEITO"}

NIVEIS = {
    "verde": {
        "rotulo": "Risco baixo",
        "resumo": "Nenhuma ameaça ativa. Seus dados estão protegidos.",
    },
    "amarelo": {
        "rotulo": "Atenção",
        "resumo": "O sistema barrou situações que poderiam expor dados pessoais.",
    },
    "vermelho": {
        "rotulo": "Risco alto",
        "resumo": "Há tentativas repetidas de acesso indevido. As proteções estão ativas.",
    },
}


def nivel_do_indice(indice: float) -> str:
    if indice >= LIMITE_VERMELHO:
        return "vermelho"
    if indice >= LIMITE_AMARELO:
        return "amarelo"
    return "verde"


def calcular(eventos: list[dict], janela_min: float, agora: float | None = None) -> dict:
    agora = time.time() if agora is None else agora
    janela = janela_min * 60
    rotina, ataque = 0.0, 0.0
    ataques: Counter = Counter()
    considerados = 0
    for evento in eventos:
        idade = agora - evento["criado_em"]
        if idade < 0 or idade > janela:
            continue
        considerados += 1
        peso = evento["peso"] * (1 - idade / janela)
        if evento["tipo"] in TIPOS_DE_ATAQUE:
            ataque += peso
            ataques[evento.get("titular_id")] += 1
        else:
            rotina += peso
    padrao_de_ataque = any(qtd >= 3 for qtd in ataques.values())
    soma = min(rotina, LIMITE_VERMELHO - 1) + ataque  # rotina sozinha não passa do amarelo
    if padrao_de_ataque:
        soma += ADICIONAL_ATAQUE
    indice = min(100, round(soma))
    nivel = nivel_do_indice(indice)
    return {
        "indice": indice,
        "nivel": nivel,
        "rotulo": NIVEIS[nivel]["rotulo"],
        "resumo": NIVEIS[nivel]["resumo"],
        "padrao_de_ataque": padrao_de_ataque,
        "eventos_na_janela": considerados,
        "janela_min": janela_min,
    }


def serie(eventos: list[dict], janela_min: float, pontos: int = 30, agora: float | None = None) -> list[dict]:
    """Índice calculado em momentos passados, para o gráfico de evolução."""
    agora = time.time() if agora is None else agora
    passo = janela_min * 60 / pontos
    return [
        {"t": instante, "indice": calcular(eventos, janela_min, instante)["indice"]}
        for instante in (agora - passo * i for i in range(pontos - 1, -1, -1))
    ]
