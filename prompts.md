# Prompts usados com IA

Registro do uso de IA como copiloto nesta entrega, como pede o briefing da Global Solution. O
desenvolvimento foi híbrido: a equipe e a ferramenta trabalharam juntas, em idas e vindas, por isso as
etapas abaixo não separam com exatidão o que veio de cada lado. Os objetivos aparecem resumidos por
etapa, na ordem do trabalho, com o resultado alcançado. As decisões de escopo, revisão e aprovação
foram da equipe.

Os prompts que o próprio sistema envia ao LLM em tempo de execução, para traduzir os eventos de
segurança, não fazem parte deste registro: eles estão no código, em
[`app/ia/tradutor.py`](app/ia/tradutor.py).

---

## 1. Entender a tarefa

**Objetivo:** ler o briefing da GS e o documento adicional de Cybersecurity e identificar o que mudou
em relação ao enunciado original.

**Resultado:** o documento adicional não remove nenhum item. Ele detalha as três partes da missão
técnica (parsing de PII, taint analysis e tradução via IA) e muda o formato de entrega para dois envios
separados: um PDF de documentação e o link do repositório no GitHub.

**Objetivo:** confirmar o entendimento da missão: um middleware que identifica PII na entrada, o taint
analysis acompanhando o dado até as saídas e um LLM que gera uma mensagem de segurança para o cidadão
no dashboard.

**Resultado:** entendimento ajustado: o middleware não impede a entrada do dado pessoal. Ele marca o
dado e o mascara ou criptografa antes de log e banco; o que é bloqueado é a saída insegura (log, erro
na tela e resposta HTTP sem autenticação).

## 2. Planejar o escopo

**Objetivo:** definir o ambiente da entrega, a stack, a necessidade de integração com outra aplicação,
o LLM e a complexidade do projeto.

**Resultado:** a equipe escolheu uma mini-API do AJA em Python + FastAPI, em ambiente próprio, sem
ligação com as outras disciplinas, com dados fictícios, LLM acessado por API e código no GitHub.
Complexidade estimada como média-baixa.

**Objetivo:** definir como o sistema seria testado e onde guardar a chave da API do LLM.

**Resultado:** testes automatizados e auditoria rodando no ambiente de desenvolvimento. A chave fica só
num arquivo `.env` fora do Git, e o script `scripts/verificar_segredos.py` barra segredos e dados
pessoais reais antes de cada commit.

## 3. Construir a API e o módulo de segurança

**Objetivo:** desenvolver o motor de PII, o taint analysis, a tradução dos eventos via IA e o
dashboard, com o contexto do AJA no README.

**Resultado:** API com cadastro, login, relatos, tópicos e dossiê em PDF, e um módulo de segurança com:
- motor de PII (`app/pii/`) com regras por nome de campo e por conteúdo, validadores (dígito
  verificador do CPF, RG, telefone e CEP com formato ou contexto) e máscaras;
- dados pessoais no banco com criptografia Fernet, índice cego HMAC e senhas com scrypt;
- taint analysis (`app/taint/`) que guarda o titular de cada dado e bloqueia vazamentos em log, erro,
  resposta HTTP, banco, dossiê, prompt do LLM e relato público;
- tradutor de eventos (`app/ia/tradutor.py`) que envia ao LLM só os metadados do evento, nunca o dado
  pessoal, e usa uma mensagem padrão quando a chave não está configurada;
- dashboard de Risco Cidadão (`app/static/`) com farol, índice de 0 a 100 e a mensagem traduzida;
- 35 testes automatizados e o script de auditoria `auditoria/simular_ataques.py`, com 11 cenários.

**Objetivo:** definir o framework do dashboard e do backend.

**Resultado:** FastAPI no backend e HTML, CSS e JavaScript puros no dashboard, servidos pela própria
API, para rodar com um único comando.

## 4. Revisar o dashboard

**Objetivo:** deixar a interface com cores mais neutras (tons de preto, azul ainda predominante, sem
tanto contraste entre as cores).

**Resultado:** paleta grafite com azul só nos destaques. O contraste do botão principal foi corrigido
para atender o WCAG AA.

**Objetivo:** confirmar se o dashboard é acessível, se o projeto usa banco de dados e o que as cores do
farol significam.

**Resultado:** verificação com axe-core sem violações (WCAG 2.1 A/AA), leitura em voz alta da mensagem
e VLibras. Banco SQLite local, com os dados pessoais criptografados. Faixas do farol: verde até 29,
amarelo de 30 a 69 e vermelho a partir de 70.

**Objetivo:** entender se o farol conta pedidos, se vale para todos os usuários e se é requisito da
entrega, e explicar melhor o farol no repositório, no PDF e no vídeo.

**Resultado:** o farol mede eventos de segurança dos últimos 10 minutos, não pedidos. Cada cidadão vê
o farol dos eventos que envolvem os próprios dados, e a equipe vê o farol geral. O painel ganhou legenda
das faixas, e o README, o PDF e o vídeo ganharam a explicação. A revisão mostrou que eventos de rotina
sozinhos levavam o farol ao vermelho; o cálculo em `app/seguranca/risco.py` foi corrigido para que a
rotina pare no amarelo e só tentativas de ataque cheguem ao vermelho, com um teste para garantir isso.

## 5. Documentar a entrega

**Objetivo:** montar o PDF de documentação com as seções pedidas no documento adicional (Source,
Auditoria e Vídeo do Dashboard), com prints claros do código e das evidências.

**Resultado:** PDF de 22 páginas com trechos reais do código numerados, evidências da auditoria (11 de
11 cenários bloqueados e varredura de log e banco sem dado pessoal em texto claro), testes, verificação
de segredos, acessibilidade, explicação do farol e quadros do dashboard.

## 6. Produzir o vídeo do dashboard

**Objetivo:** criar um vídeo do dashboard em atividade, com roteiro de narração, unindo cenas animadas
e a gravação real do painel.

**Resultado:** roteiro em nove cenas; abertura e encerramento animados e, no meio, a gravação do painel
durante a auditoria, na fonte e na paleta do dashboard, com a narração gravada pela equipe.

**Objetivo:** dar mais tempo ao trecho do painel e destacar a parte mencionada na narração.

**Resultado:** versão final de 3min23s, com contornos, textos explicativos e escurecimento do que não
está sendo mencionado, publicada no YouTube como não listada.

## 7. Revisar e entregar

**Objetivo:** fazer uma revisão final, confirmar se a chave da API pode ser excluída e listar o que deve
ser entregue.

**Resultado:** teste do repositório do zero. Foram conferidos:
- clone novo, instalação limpa e configuração sem chave;
- 35 testes aprovados e API, painel e documentação interativa respondendo;
- auditoria com 11 de 11 cenários, usando as mensagens padrão;
- histórico do Git sem chave e sem arquivo `.env`;
- links do PDF e do README.

A chave pode ser revogada, porque o sistema funciona sem ela. A entrega é o PDF de documentação e o
link do repositório, enviados separadamente.
