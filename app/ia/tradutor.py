"""Tradução via IA: do evento técnico para uma mensagem que o cidadão entende.

O backend captura o evento de segurança, monta um prompt dinâmico com os metadados dele e pede ao
LLM (Claude, da Anthropic) três coisas:
- a mensagem para o cidadão, em duas frases e sem jargão;
- o que o cidadão deve fazer (ou "nenhuma ação necessária");
- a remediação técnica para a equipe do AJA (aparece só na visão executiva do dashboard).

O próprio LLM é tratado como um sink: o prompt passa pela guarda de taint antes do envio, e o
modelo recebe só a descrição do evento, nunca o dado pessoal. Se a API falhar, o sistema usa uma
mensagem padrão, sinalizada como tal no dashboard.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Protocol

from app import banco, config
from app.pii.regras import ROTULO_CATEGORIA, Categoria
from app.taint.sinks import inspecionar, sanear

log = logging.getLogger("aja.ia")

SISTEMA = """Você é o assistente de segurança do AJA, uma plataforma de participação cidadã em que \
moradores do Parque Doroteia (São Paulo) relatam barreiras de acessibilidade nas calçadas e \
travessias. Muitos usuários são pessoas com deficiência visual (usam leitor de tela) ou auditiva \
(muitas têm a Libras como primeira língua e o português como segunda), e muitos são idosos.

Você recebe um evento técnico de segurança e explica o que aconteceu. Regras:
- Português do Brasil, frases curtas e diretas, palavras do dia a dia.
- Sem termos técnicos, siglas, códigos de erro, nomes de arquivos ou de rotas.
- Sem emojis nem símbolos: o texto será lido em voz alta por leitores de tela.
- Fale diretamente com quem vai ler, usando "você", sem supor gênero ("o senhor", "a senhora").
- Diga com clareza se os dados da pessoa ficaram protegidos. Não cause alarme sem motivo e não \
culpe o cidadão.
- Não invente fatos que não estejam no evento.

Responda somente com um objeto JSON, sem texto antes ou depois, neste formato:
{"mensagem": "duas frases para o cidadão", \
"o_que_fazer": "uma frase com uma ação prática, ou Nenhuma ação necessária.", \
"remediacao_tecnica": ["até três ações curtas para a equipe técnica do AJA corrigir a causa"]}"""

DESCRICAO_SINK = {
    "log": "registro interno de funcionamento do sistema (log)",
    "resposta": "resposta enviada pela internet a quem fez o pedido",
    "erro": "mensagem de erro que apareceria na tela",
    "banco": "banco de dados",
    "dossie": "dossiê em PDF enviado à Prefeitura",
    "llm": "texto enviado ao assistente de inteligência artificial",
    "login": "tela de entrada na conta",
    "entrada": "relato público do cidadão",
}

PADRAO = {
    "PII_MASCARADA_ENTRADA": (
        "Seu relato tinha um dado pessoal seu, como documento ou telefone. Escondemos esse dado antes de "
        "publicar, e o relato continua valendo normalmente.",
        "Nenhuma ação necessária.",
        ["Orientar no formulário que o relato é público e não deve conter dados pessoais."],
    ),
    "LOG_BLOQUEADO": (
        "Uma parte do sistema tentou anotar um dado pessoal no registro interno. O sistema escondeu "
        "o dado antes de anotar, e nada foi exposto.",
        "Nenhuma ação necessária.",
        ["Remover a chamada de log que recebe o dado pessoal.", "Registrar só identificadores internos."],
    ),
    "ERRO_SANITIZADO": (
        "Aconteceu um erro ao processar o seu pedido. A mensagem de erro foi limpa para não mostrar "
        "seus dados na tela.",
        "Confira as informações e tente de novo.",
        ["Não incluir valores recebidos nas mensagens de erro.", "Revisar a validação que falhou."],
    ),
    "RESPOSTA_BLOQUEADA": (
        "Alguém tentou ver seus dados pessoais sem permissão. O sistema bloqueou o acesso e seus dados "
        "continuam protegidos.",
        "Se isso se repetir, troque sua senha.",
        ["Exigir login e conferir o dono do dado na rota.", "Investigar a origem dos acessos bloqueados."],
    ),
    "BANCO_BLOQUEADO": (
        "O sistema impediu que um dado pessoal fosse guardado sem proteção. Nenhuma informação ficou "
        "exposta.",
        "Nenhuma ação necessária.",
        ["Criptografar o campo antes de gravar.", "Adicionar teste que cubra essa gravação."],
    ),
    "DOSSIE_SANITIZADO": (
        "O documento enviado à Prefeitura tinha dados que identificariam quem fez o relato. Trocamos "
        "esses dados por um apelido, e a sua identidade foi preservada.",
        "Nenhuma ação necessária.",
        ["Retirar dados do relator do modelo do dossiê.", "Manter apenas a contagem de relatos."],
    ),
    "LLM_PROMPT_SANITIZADO": (
        "Um dado pessoal ia ser enviado ao assistente automático do sistema. O dado foi retirado antes "
        "do envio.",
        "Nenhuma ação necessária.",
        ["Montar o prompt só com metadados do evento."],
    ),
    "LOGIN_SUSPEITO": (
        "Houve várias tentativas de entrar na sua conta com a senha errada. Por segurança, ficamos de "
        "olho nesses acessos.",
        "Se não foi você, troque sua senha agora.",
        ["Aplicar bloqueio temporário após falhas seguidas.", "Avisar o titular por um canal acessível."],
    ),
}


class ClienteLLM(Protocol):
    modelo: str

    def gerar(self, sistema: str, prompt: str) -> str: ...


class ClienteAnthropic:
    def __init__(self, chave: str, modelo: str) -> None:
        import anthropic

        self.modelo = modelo
        self._cliente = anthropic.Anthropic(api_key=chave, timeout=25.0, max_retries=1)

    def gerar(self, sistema: str, prompt: str) -> str:
        import anthropic

        argumentos = {"model": self.modelo, "system": sistema, "messages": [{"role": "user", "content": prompt}]}
        try:
            # Tradução curta não precisa de raciocínio estendido: responde em ~2 s e custa menos.
            resposta = self._cliente.messages.create(**argumentos, max_tokens=600, thinking={"type": "disabled"})
        except anthropic.BadRequestError:
            # Modelos que não aceitam o parâmetro: margem maior para o raciocínio + a resposta.
            resposta = self._cliente.messages.create(**argumentos, max_tokens=3000)
        return "".join(bloco.text for bloco in resposta.content if getattr(bloco, "type", "") == "text")


_cliente: ClienteLLM | None = None
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="aja-ia")


def definir_cliente(cliente: ClienteLLM | None) -> None:
    """Permite trocar o cliente (os testes usam um cliente falso, sem rede)."""
    global _cliente
    _cliente = cliente


def _obter_cliente() -> ClienteLLM | None:
    global _cliente
    if _cliente is None:
        cfg = config.obter()
        if cfg.chave_anthropic:
            _cliente = ClienteAnthropic(cfg.chave_anthropic, cfg.modelo_llm)
    return _cliente


ACOES = (
    ("POST", "/api/v1/cidadaos", "criar uma conta no AJA"),
    ("POST", "/api/v1/auth/login", "entrar na conta"),
    ("POST", "/api/v1/relatos", "enviar um relato de barreira na calçada"),
    ("GET", "/api/v1/cidadaos/busca", "a equipe do AJA procurar um cadastro"),
    ("POST", "/api/v1/legado/", "uma parte antiga do sistema guardar um contato"),
    ("GET", "/api/v1/legado/", "uma parte antiga do sistema consultar o perfil de um cidadão"),
    ("GET", "/api/v1/topicos/", "gerar o dossiê do tópico para a Prefeitura"),
)


def descrever_acao(rota: str | None) -> str:
    metodo, _, caminho = (rota or "").partition(" ")
    for m, prefixo, descricao in ACOES:
        if metodo == m and caminho.startswith(prefixo):
            return descricao
    return "usar o sistema"


def montar_prompt(evento: dict) -> str:
    tipo_sink = evento["sink"].split(":")[0]
    dados = ", ".join(ROTULO_CATEGORIA[Categoria(c)] for c in evento["categorias"]) or "nenhum dado pessoal"
    from app.seguranca.eventos import TIPOS

    return (
        "Traduza esta falha técnica de segurança para um cidadão leigo de 60 anos, em 2 frases.\n\n"
        f"Evento técnico: {evento['tipo']}\n"
        f"O que aconteceu: {TIPOS[evento['tipo']].descricao}\n"
        f"Momento: durante a ação de {descrever_acao(evento.get('rota'))}\n"
        f"Quem vai ler: {'a própria pessoa dona dos dados envolvidos (escreva "seus dados", não "dados de um cidadão")' if evento.get('titular_id') else 'qualquer cidadão que usa o AJA'}\n"
        f"Onde: {DESCRICAO_SINK.get(tipo_sink, tipo_sink)}\n"
        f"Tipo de dado envolvido: {dados}\n"
        f"Dado sensível pela LGPD (saúde): {'sim' if evento['sensivel'] else 'não'}\n"
        f"Decisão do sistema: {evento['decisao']}\n"
        f"Detalhe técnico (para a remediação): {evento['detalhe_tecnico']}"
    )


def _chave_cache(evento: dict, modelo: str) -> str:
    base = json.dumps([modelo, evento["tipo"], evento["sink"].split(":")[0], evento["categorias"],
                       evento["sensivel"], evento["decisao"], evento["detalhe_tecnico"],
                       descrever_acao(evento.get("rota")), bool(evento.get("titular_id")), SISTEMA], ensure_ascii=False)
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def _interpretar(texto: str) -> dict:
    trecho = re.search(r"\{.*\}", texto, re.S)
    if not trecho:
        raise ValueError("Resposta do LLM sem JSON")
    dados = json.loads(trecho.group(0))
    mensagem = str(dados.get("mensagem", "")).strip()
    if not mensagem:
        raise ValueError("Resposta do LLM sem mensagem")
    remediacao = dados.get("remediacao_tecnica") or []
    if isinstance(remediacao, str):
        remediacao = [remediacao]
    return {
        "mensagem": mensagem,
        "o_que_fazer": str(dados.get("o_que_fazer", "")).strip() or "Nenhuma ação necessária.",
        "remediacao": [str(item).strip() for item in remediacao][:3],
    }


def _limpo(texto: str) -> str:
    return sanear(texto, inspecionar(texto))


def traduzir(evento_id: int) -> dict:
    from app.seguranca import eventos

    evento = eventos.obter(evento_id)
    if evento is None:
        raise ValueError(f"Evento {evento_id} não existe")

    prompt = montar_prompt(evento)

    # Sink "llm": o prompt é inspecionado antes de sair para a API externa.
    deteccoes = inspecionar(prompt)
    if deteccoes:
        prompt = sanear(prompt, deteccoes)
    if deteccoes and evento["tipo"] != "LLM_PROMPT_SANITIZADO":  # sem laço: este tipo não gera outro
        eventos.registrar(
            "LLM_PROMPT_SANITIZADO", sink="llm:anthropic", deteccoes=deteccoes, decisao="mascarado",
            detalhe=f"Prompt do evento {evento_id} continha dado pessoal; trecho mascarado antes do envio.",
            titular_id=evento.get("titular_id"),
        )

    cliente = _obter_cliente()
    resultado, origem, modelo = None, "padrao", None
    if cliente is not None:
        chave = _chave_cache(evento, cliente.modelo)
        em_cache = banco.consultar_um("SELECT resposta FROM cache_traducao WHERE chave = ?", (chave,))
        if em_cache:
            resultado, origem, modelo = json.loads(em_cache["resposta"]), "ia", cliente.modelo
        else:
            try:
                resultado = _interpretar(cliente.gerar(SISTEMA, prompt))
                origem, modelo = "ia", cliente.modelo
                banco.executar(
                    "INSERT OR REPLACE INTO cache_traducao (chave, resposta, modelo) VALUES (?, ?, ?)",
                    (chave, json.dumps(resultado, ensure_ascii=False), cliente.modelo), verificar=False,
                )
            except Exception as erro:  # rede, cota, resposta fora do formato
                log.warning("Tradução via LLM indisponível para o evento %s: %s", evento_id, type(erro).__name__)
                resultado = None

    if resultado is None:
        mensagem, o_que_fazer, remediacao = PADRAO[evento["tipo"]]
        resultado = {"mensagem": mensagem, "o_que_fazer": o_que_fazer, "remediacao": remediacao}

    # A resposta do modelo também é conferida antes de ir para o banco e para a tela.
    banco.executar(
        "UPDATE eventos SET mensagem = ?, o_que_fazer = ?, remediacao = ?, origem_mensagem = ?, modelo = ? "
        "WHERE id = ?",
        (_limpo(resultado["mensagem"]), _limpo(resultado["o_que_fazer"]),
         json.dumps([_limpo(r) for r in resultado["remediacao"]], ensure_ascii=False), origem, modelo,
         evento_id),
        verificar=False,
    )
    return {**resultado, "origem": origem, "modelo": modelo}


def agendar(evento_id: int) -> None:
    if config.obter().traducao_sincrona:
        traduzir(evento_id)
    else:
        _executor.submit(_traduzir_com_log, evento_id)


def _traduzir_com_log(evento_id: int) -> None:
    try:
        traduzir(evento_id)
    except Exception:
        log.exception("Falha ao traduzir o evento %s", evento_id)
