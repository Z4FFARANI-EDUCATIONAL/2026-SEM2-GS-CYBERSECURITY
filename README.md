![banner](./assets/banner.png)

# AJA · Cybersecurity

| Integrante | RM |
|---|---|
| [Guilherme Santos Nunes](https://github.com/sannunez) | RM558989 |
| [Kaique Zaffarani](https://github.com/Z4ffarani) | RM556677 |
| [Pedro Josué Pereira Almeida](https://github.com/Pedro-Josue) | RM554913 |

Global Solution 2026.2 · CitizenTech · Engenharia de Software · FIAP

---

## O projeto AJA

O **AJA** é uma plataforma de participação cidadã que transforma relatos da comunidade em propostas
fundamentadas de melhoria da infraestrutura do bairro. O primeiro recorte é a **acessibilidade para
pessoas com deficiência visual e auditiva no Parque Doroteia**, zona sul de São Paulo.

A jornada é simples para quem participa:
1. o morador relata uma barreira (foto, localização, texto ou áudio);
2. o relato vira um **tópico**, que reúne relatos parecidos, evidências locais e dados públicos;
3. a comunidade apoia, confirma a observação ou acrescenta evidências;
4. o AJA consolida um **dossiê** para o órgão responsável;
5. o AJA acompanha o protocolo até a resposta.

Para funcionar, o AJA lida com dados delicados: CPF e contato de quem relata e, muitas vezes, a
própria deficiência da pessoa, que é **dado pessoal sensível de saúde** pela LGPD (art. 5º, II). Quem
relata uma barreira precisa confiar que a sua identidade não vai parar num log, numa tela de erro ou no
documento enviado à Prefeitura.

## Ficha da CitizenTech

| Campo | Descrição |
|---|---|
| **Nome** | AJA |
| **Cidade e bairro** | São Paulo, Parque Doroteia (Subprefeitura Cidade Ademar, zona sul) |
| **Cidadão beneficiado** | Pessoas com deficiência visual e auditiva que circulam a pé pelo bairro |
| **Problema, em uma frase** | Pessoas com deficiência visual e auditiva do Parque Doroteia enfrentam barreiras nas calçadas e travessias, e relatar e acompanhar a solução junto à Prefeitura é trabalhoso e pouco acessível. |
| **Como funciona** | O morador relata a barreira, o relato vira um tópico com evidências, a comunidade apoia ou confirma, o AJA gera um dossiê para o órgão responsável e acompanha o protocolo até a resposta. |
| **O que cada parte faz** | **Motor de PII:** reconhece dados pessoais em tudo o que entra na API.<br>**Taint analysis:** rastreia esses dados até cada saída e bloqueia vazamentos.<br>**Tradução via IA:** transforma cada bloqueio numa mensagem clara para o cidadão.<br>**Dashboard:** mostra o farol de Risco Cidadão e os alertas. |
| **Indicador de impacto** | Barreiras mapeadas; % de demandas com protocolo aberto; tempo médio até a resposta do órgão; nota dada por pessoas com deficiência depois da intervenção. Nesta entrega: zero dado pessoal em texto claro em log e banco (auditoria) |
| **ODS conectados** | ODS 11 (meta 11.7: espaços públicos seguros e acessíveis, inclusive para pessoas com deficiência), ODS 10 (meta 10.2: inclusão independente de deficiência), ODS 9 (infraestrutura de qualidade e inclusiva) |

## Esta entrega: Cybersecurity

Uma API do AJA em **Python + FastAPI** (cadastro, login, relatos, tópicos e dossiê) com um módulo de
segurança que cobre as três partes da missão técnica e o dashboard.

| Entregável | Onde |
|---|---|
| Código-fonte | este repositório |
| Auditoria do protótipo | [`auditoria/RELATORIO_AUDITORIA.md`](auditoria/RELATORIO_AUDITORIA.md) |
| Vídeo do dashboard | [youtu.be/2f9h9YCno48](https://youtu.be/2f9h9YCno48) |

```
 requisição ──► [1] Motor de PII ──► marca cada dado pessoal no contexto de taint (source)
                                              │
            rota executa (banco, dossiê, logs, resposta…)
                                              │
 cada saída ─► [2] guarda de taint ─► mascara ou bloqueia ─► evento de segurança (só metadados)
                                                                  │
                                       [3] Claude traduz o evento para o cidadão
                                                                  │
                                       Dashboard: farol de Risco Cidadão + mensagem
```

### 1. Motor de parsing de PII — [`app/pii/`](app/pii)

Um middleware ([`app/taint/middleware.py`](app/taint/middleware.py)) intercepta **toda requisição** e
passa o corpo JSON ou de formulário, a query string e o cabeçalho `Authorization` pelo motor. O motor
percorre a estrutura inteira (objetos aninhados e listas) e reconhece o dado de dois jeitos:

- **pelo nome do campo** (`cpf`, `documento`, `senha`, `laudo`, `deficiencia`…): o valor inteiro é PII;
- **pelo conteúdo** (regex com validação): acha o dado dentro de texto livre, como a descrição de um relato.

| Regra | Categoria | Sensível (LGPD) | Como aparece mascarado | Como vai para o banco |
|---|---|---|---|---|
| CPF | identificação | não | `***.456.***-00` | criptografado + índice cego |
| RG | identificação | não | `**.***.*78-9` | criptografado |
| Nome | identificação | não | `J. E. S.` | criptografado |
| Data de nascimento | identificação | não | `**/**/1958` | criptografado |
| Senha | credencial | não | `[senha removida]` | hash scrypt |
| Token / chave de API | credencial | não | `[credencial removida]` | descartado |
| Saúde (laudo, CID-10, deficiência) | saúde | **sim** | `[informação de saúde protegida]` | criptografado |
| E-mail | contato | não | `j***@e***.com` | criptografado + índice cego |
| Telefone | contato | não | `(**) *****-**01` | criptografado |
| Endereço residencial e CEP | localização | não | `[endereço residencial protegido]` | criptografado |

Cuidados contra falso positivo, cada um coberto por teste:
- no texto livre, um número só é CPF se o **dígito verificador** bater ou se a palavra "CPF" vier antes;
  assim, um protocolo do SP156 não vira documento;
- o RG exige o contexto "RG";
- o telefone precisa estar formatado ou vir depois de uma palavra como "tel", e por isso um timestamp
  não vira telefone;
- **"sou cega"** é dado de saúde, mas **"piso tátil para pessoas cegas"** não é: o relato precisa <!-- pii-ok -->
  descrever o público afetado;
- **"moro na Rua X, 120"** é endereço residencial, mas **"o buraco fica na Rua X, 120"** é o local da
  barreira, que é público.

### 2. Taint analysis — [`app/taint/`](app/taint)

Cada dado pessoal que entra (**source**) é marcado no contexto da requisição com o tipo, a origem e o
**titular** (de quem é o dado). Valores decifrados do banco também voltam a ser marcados. A marcação
é feita pelo valor, e por isso sobrevive a cópias, concatenações e f-strings. Antes de qualquer
**sink**, uma guarda confere o conteúdo combinando as marcações com os padrões do motor:

| Sink | Guarda | Decisão |
|---|---|---|
| **Log** (app e servidor) | `logging.Filter` em todos os handlers ([`logs.py`](app/taint/logs.py)) | mascara o valor, marca a linha |
| **Erro na tela** | exceções não tratadas e erros 422 de validação ([`middleware.py`](app/taint/middleware.py), [`main.py`](app/main.py)) | mensagem genérica, sem o dado |
| **Resposta HTTP** | só sai dado pessoal se quem pede estiver logado **e** for o titular | troca a resposta por 403 |
| **Banco** | todo parâmetro de SQL é inspecionado ([`banco.py`](app/banco.py)) | impede a gravação em texto claro |
| **Dossiê à Prefeitura** | identidade dos autores lida e marcada ([`dossie.py`](app/dossie.py)) | troca por "Morador(a) A, B…" |
| **Prompt do LLM** | o prompt é inspecionado antes de sair ([`tradutor.py`](app/ia/tradutor.py)) | mascara antes do envio |
| **Relato público** | identidade do autor e de quem já relatou no tópico | mascara antes de publicar |

As duas rotas em `/api/v1/legado/` imitam código antigo com falhas de propósito: uma devolve o perfil
sem conferir quem pede, e a outra grava o telefone sem criptografia. Elas existem para a auditoria
provar que a guarda segura o vazamento mesmo quando a rota erra.

### 3. Tradução via IA — [`app/ia/tradutor.py`](app/ia/tradutor.py)

Cada bloqueio vira um **evento de segurança** que guarda só metadados: tipo, sink, categoria do dado,
decisão e um detalhe técnico já mascarado. O backend monta um **prompt dinâmico** com esses metadados
e o envia ao **Claude (Anthropic, modelo `claude-haiku-5-5`)**, que devolve:

- a mensagem para o cidadão, em duas frases, sem jargão e pronta para leitor de tela;
- o que o cidadão deve fazer;
- a **remediação técnica** para a equipe do AJA.

O próprio LLM é tratado como um sink: o modelo nunca recebe o dado pessoal. Respostas iguais ficam em
cache. Se a API falhar, o sistema usa uma mensagem padrão, sinalizada como tal no painel.

> Exemplo real. Evento técnico: `RESPOSTA_BLOQUEADA em resposta:http · GET /api/v1/legado/cidadaos/2 levaria
> contato, identificacao, localizacao, saude sem login`. Mensagem gerada: *"Alguém tentou ver seus dados
> pessoais sem permissão, incluindo contato, documento, endereço e informações de saúde. O sistema
> bloqueou a tentativa e seus dados não foram entregues a ninguém."*

### Dashboard de Risco Cidadão — [`app/static/`](app/static)

O enunciado pede que a mensagem traduzida pela IA apareça num painel com um **indicador visual de
risco**, e dá como exemplo um farol verde, amarelo e vermelho. Corresponde ao critério “Dashboard Executivo (Risco
Cidadão)”. O painel tem duas visões:

- **Visão do cidadão:** cada pessoa vê só os alertas que envolvem os próprios dados, com a mensagem da
  IA e o que fazer.
- **Visão executiva (equipe AJA):** índice geral, indicadores, evolução do índice, bloqueios por tipo e
  por saída, detalhe técnico e remediação sugerida pela IA.

#### Como ler o farol

O farol **não conta pedidos nem relatos**. Ele mede **eventos de segurança**: cada vez que uma guarda
precisou esconder ou bloquear um dado pessoal, ou percebeu uma tentativa de ataque.

- **Quem vê o quê:** na visão do cidadão, o farol considera só os eventos com os dados daquela pessoa;
  na visão executiva, considera todos os eventos do sistema. Cada cidadão tem o seu farol.
- **Como o índice (0 a 100) é calculado:** cada evento soma um peso, que diminui em linha reta até zerar
  em 10 minutos. Por isso o índice funciona como a “temperatura” do momento, e não como um placar
  acumulado: se as tentativas param, o farol volta sozinho para o verde.
- **Rotina × ataque:** eventos de rotina (dado mascarado no log, no erro, no relato, no dossiê ou no
  prompt; gravação insegura impedida) mostram que o sistema barrou um vazamento e, sozinhos, levam no
  máximo ao amarelo (69). Só tentativas de ataque (acesso sem permissão, senhas erradas em sequência)
  levam ao vermelho.

| Evento | Peso | Com dado de saúde (×1,5) |
|---|---|---|
| Dado pessoal escondido num relato público | 5 | 7,5 |
| Log que tentou gravar dado pessoal | 12 | 18 |
| Erro que repetiria dado pessoal na tela | 12 | 18 |
| Dado pessoal retirado do dossiê ou do prompt da IA | 15 | 22,5 |
| Acesso aos dados de alguém sem permissão | 25 | 37,5 |
| Tentativa de gravar dado sem criptografia | 30 | 45 |
| Muitas tentativas de senha seguidas | 35 | 52,5 |
| **Padrão de ataque** (3 ou mais acessos bloqueados ou ataques de senha contra a mesma pessoa) | +40 | — |

| Faixa | Nível | O que significa |
|---|---|---|
| 0 a 29 | 🟢 Risco baixo | nenhuma ameaça ativa, ou só mascaramentos de rotina |
| 30 a 69 | 🟡 Atenção | o sistema barrou situações que poderiam expor dados |
| 70 a 100 | 🔴 Risco alto | tentativas repetidas de acesso indevido; as proteções estão segurando |

**Exemplo:** alguém tenta duas vezes ver o perfil da Joana, que tem dado de saúde, sem permissão:
2 × 37,5 = 75, e o farol dela fica vermelho. Cinco minutos depois, sem novas tentativas, o índice cai
para cerca de 37 (amarelo); em dez minutos, volta ao verde. Vermelho não quer dizer que algo vazou: quer
dizer que alguém está tentando, e as guardas estão bloqueando. O cálculo está em
[`app/seguranca/risco.py`](app/seguranca/risco.py) e o próprio painel mostra a legenda das faixas.

#### Acessibilidade e segurança da tela

- A cor nunca é a única pista: o nível também aparece em texto e em número, com a legenda das faixas.
- `aria-live` anuncia os alertas novos ao leitor de tela; o botão “Ouvir mensagem” lê o alerta em voz
  alta; o widget **VLibras** traduz para Libras.
- Todo texto vindo da API, inclusive o gerado pela IA, entra na página por `textContent`, nunca por
  `innerHTML`, o que evita XSS.

## Como executar

Requer Python 3.11 ou superior.

```bash
pip install -r requirements.txt
python scripts/configurar.py          # gera o .env com chaves novas e instala o hook de segredos
uvicorn app.main:app --reload
```

- Dashboard: <http://127.0.0.1:8000/painel/>. Entre com o login da equipe que o `configurar.py` mostra,
  ou com um cidadão criado pela auditoria.
- Documentação da API (Swagger): <http://127.0.0.1:8000/docs>

Em outro terminal, gere atividade e acompanhe o farol mudando no dashboard:

```bash
python -m auditoria.simular_ataques --ao-vivo
```

## Auditoria do protótipo

[`auditoria/simular_ataques.py`](auditoria/simular_ataques.py) dispara 11 cenários contra a API em
execução e depois varre o arquivo de log e todas as tabelas do banco atrás de dado pessoal em texto
claro. O resultado completo, com as evidências de cada cenário, está em
[`auditoria/RELATORIO_AUDITORIA.md`](auditoria/RELATORIO_AUDITORIA.md).

| # | Cenário | Resultado |
|---|---|---|
| C01 | `logger.info` do cadastro inteiro (CPF, senha, saúde) | linha gravada mascarada |
| C02 | CPF inválido: o 422 padrão do FastAPI ecoaria o valor | resposta sem o CPF |
| C03 | CPF na URL chega ao log de acesso do servidor | log de acesso mascarado |
| C04 | relato público com CPF, telefone, "sou cega" e assinatura | texto publicado limpo <!-- pii-ok --> |
| C05 | relato cita pelo nome outra pessoa do mesmo tópico | nome mascarado |
| C06 | rota legada sem controle de acesso, sem login | 403 |
| C07 | outro cidadão logado pede o perfil (IDOR) | 403 |
| C08 | a própria titular pede o perfil (controle positivo) | 200 |
| C09 | código legado grava telefone em texto claro | INSERT impedido |
| C10 | 5 senhas erradas seguidas | alerta e farol vermelho |
| C11 | dossiê cujo modelo cita o nome de quem relatou | PDF só com apelidos |
| — | varredura final do log e do banco | **0 ocorrências** |

## Testes

```bash
python -m pytest -q
```

35 testes cobrem o motor de PII, cada guarda de taint, a tradução via IA (com um LLM falso, sem rede)
e o cálculo do índice de risco.

## Decisões de segurança

- **Dados em repouso:** criptografia Fernet (AES-128-CBC + HMAC-SHA256) para os dados pessoais;
  **índice cego** HMAC-SHA256 para achar CPF e e-mail no login sem decifrar a tabela; senhas com
  **scrypt** e sal aleatório; tokens de sessão guardados só como hash.
- **Minimização (LGPD art. 6º, III):** o texto público do relato guarda só a versão mascarada, e o
  dossiê leva apelidos, nunca identidades.
- **Segredos:** chaves só no `.env`, fora do Git. O hook `pre-commit`
  ([`scripts/verificar_segredos.py`](scripts/verificar_segredos.py)) roda o próprio motor de PII sobre
  os arquivos do commit e o bloqueia se achar chave de API, senha no código ou dado pessoal real.
- **Defesa em profundidade:** a marcação de taint pega dados sem formato fixo (um nome, por exemplo), e
  os padrões do motor pegam dados que nunca foram marcados (um CPF num log escrito fora de uma
  requisição).

## Limitações conhecidas

- Nome em texto livre só é reconhecido com frase de contexto ("meu nome é", "assinado:") ou quando
  pertence a alguém cuja identidade está marcada; um nome qualquer de terceiro pode passar.
- O SQLite e o índice de risco atendem ao protótipo; em produção, a chave de criptografia ficaria num
  cofre (KMS) com rotação, e os eventos num armazenamento próprio.
- A tradução depende da API da Anthropic; sem ela, o painel usa as mensagens padrão.

## Estrutura

```
app/
├── main.py                 aplicação FastAPI, erro 422 seguro, dashboard estático
├── pii/                    motor de parsing: regras, validadores, varredura e máscaras
├── taint/                  contexto por requisição, middleware, guardas de saída e de log
├── seguranca/              criptografia, login, eventos e índice de Risco Cidadão
├── ia/tradutor.py          prompt dinâmico, cliente do Claude, cache e mensagens padrão
├── rotas/                  cidadãos, relatos e tópicos, painel
├── dossie.py               dossiê em PDF com a identidade protegida
└── static/                 dashboard (HTML, CSS e JavaScript)
auditoria/                  ataques simulados, dados fictícios e relatório de evidências
scripts/                    configuração do .env e verificação de segredos
tests/                      testes automatizados (pytest)
```

---

## Tecnologias

[![Python](https://img.shields.io/badge/Python_3.13-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white)](https://www.sqlite.org)
[![Anthropic](https://img.shields.io/badge/Claude_(Anthropic)-191919?style=flat-square&logo=anthropic&logoColor=white)](https://docs.claude.com)
[![cryptography](https://img.shields.io/badge/cryptography-Fernet-4B5563?style=flat-square)](https://cryptography.io)
[![pytest](https://img.shields.io/badge/pytest-0A9EDC?style=flat-square&logo=pytest&logoColor=white)](https://pytest.org)
[![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black)](https://developer.mozilla.org/docs/Web/JavaScript)

---

## Referências

| # | Referência | Aplicação no Projeto |
|---|---|---|
| 1 | [Lei nº 13.709/2018 — LGPD](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm) | Dado sensível de saúde (art. 5º, II), necessidade (art. 6º, III) e segurança (art. 46) |
| 2 | [Schwartz, E.; Avgerinos, T.; Brumley, D. (2010) — *All You Ever Wanted to Know About Dynamic Taint Analysis and Forward Symbolic Execution* — IEEE S&P](https://doi.org/10.1109/SP.2010.26) | Conceitos de source, sink e propagação de taint |
| 3 | [OWASP Top 10 (2021) — A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) | Cenários de acesso sem login e IDOR (C06, C07) |
| 4 | [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | Dados que nunca devem ir para o log |
| 5 | [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | Texto da API e da IA inserido por `textContent` |
| 6 | [Receita Federal — cálculo do dígito verificador do CPF](https://www.gov.br/receitafederal/pt-br) | Validação que evita falso positivo no motor |
| 7 | [Fernet specification](https://github.com/fernet/spec/blob/master/Spec.md) | Criptografia dos dados pessoais no banco |
| 8 | [RFC 7914 — The scrypt Password-Based Key Derivation Function](https://www.rfc-editor.org/rfc/rfc7914) | Hash das senhas |
| 9 | [Anthropic — documentação da API Messages](https://docs.claude.com/en/api/messages) | Tradução dos eventos de segurança |
| 10 | [VLibras — Governo Federal](https://www.gov.br/governodigital/pt-br/vlibras) | Tradução do painel para Libras |
| 11 | [Lei nº 13.146/2015 — Lei Brasileira de Inclusão](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2015/lei/l13146.htm) | Direito à acessibilidade, inclusive na comunicação |
