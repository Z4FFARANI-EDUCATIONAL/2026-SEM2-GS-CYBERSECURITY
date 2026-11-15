# Prompts usados com IA

Registro dos pedidos feitos ao assistente de IA (Claude, da Anthropic) durante o desenvolvimento desta
entrega, como pede o briefing da Global Solution. Os pedidos estão resumidos e reescritos por etapa, na
ordem do trabalho, com o que resultou de cada um. As decisões de escopo, revisão e aprovação foram da
equipe.

Os prompts que o próprio sistema envia ao Claude em tempo de execução (tradução dos eventos de
segurança) não fazem parte deste registro: eles estão no código, em
[`app/ia/tradutor.py`](app/ia/tradutor.py).

---

## 1. Entender a tarefa

**Pedido:** ler o briefing da GS e o documento adicional do professor de Cybersecurity e apontar o que
mudou em relação ao enunciado original.

**Resultado:** o adicional não remove nenhum item; detalha os três pontos (parsing de PII, taint analysis
e tradução via IA) e muda o formato de entrega para um PDF de documentação e um link do GitHub,
enviados separadamente.

**Pedido:** confirmar o entendimento: um middleware que identifica PII na entrada, o taint analysis
acompanhando o dado até as saídas e um LLM que gera uma mensagem de segurança para o usuário no
dashboard.

**Resultado:** ajuste no entendimento: o middleware não impede a entrada do dado pessoal; ele marca o
dado e o mascara ou criptografa, e o que é bloqueado é a saída insegura.

## 2. Planejar o escopo

**Pedido:** definir o ambiente da entrega (separado do protótipo e sem ligação com outras disciplinas),
a stack, se seria preciso integrar com outra aplicação, o LLM a usar e a complexidade do projeto.

**Resultado:** mini-API do AJA em Python + FastAPI, ambiente próprio, dados fictícios, Claude via API e
código no GitHub. Estimativa de complexidade média-baixa.

**Pedido:** explicar como o sistema seria testado e se a chave da API poderia ficar no repositório.

**Resultado:** testes automatizados e auditoria rodando no ambiente de desenvolvimento; a chave fica só
num arquivo `.env` fora do Git, com um verificador de segredos antes de cada commit.

## 3. Construir a entrega

**Pedido:** desenvolver o motor de PII, o taint analysis, a tradução via IA e o dashboard, com o
contexto do projeto AJA no README (com base no README da entrega de IA & ML).

**Resultado:** API com cadastro, login, relatos, tópicos e dossiê; motor de PII com regras por campo e
por conteúdo; guardas de taint em log, erro, resposta HTTP, banco, dossiê, prompt do LLM e relato
público; tradutor de eventos com mensagem padrão de reserva; dashboard com farol de Risco Cidadão;
testes automatizados; script de auditoria; README.

**Pedido:** perguntar qual framework seria usado no dashboard e no backend.

**Resultado:** FastAPI no backend e HTML, CSS e JavaScript puros no dashboard, servidos pela própria API,
para rodar com um único comando.

## 4. Revisar o dashboard

**Pedido:** deixar a interface com cores mais neutras (tons de preto, azul ainda predominante, sem tanto
contraste entre as cores).

**Resultado:** paleta grafite com azul só nos destaques; o contraste do botão principal foi corrigido
para atender o WCAG AA.

**Pedido:** responder se o dashboard é acessível, se o projeto usa banco de dados e o que as cores do
farol significam.

**Resultado:** verificação automática de acessibilidade sem violações; banco SQLite com os dados
pessoais criptografados; explicação das faixas do farol.

**Pedido:** esclarecer se o farol conta pedidos, se vale para todos os usuários, se é requisito da
entrega e pedir que ele seja explicado melhor no repositório, no PDF e no vídeo.

**Resultado:** o farol mede eventos de segurança (não pedidos); cada cidadão vê o próprio farol e a
equipe vê o geral; legenda e explicação no painel, no README, no PDF e no vídeo. A revisão também
mostrou que eventos de rotina sozinhos levavam o farol ao vermelho, e o cálculo foi corrigido para que
só tentativas de ataque cheguem ao vermelho.

## 5. Documentar

**Pedido:** montar o PDF de documentação com as seções pedidas pelo professor (Source, Auditoria e
Vídeo do Dashboard), com prints do código e das evidências.

**Resultado:** PDF com trechos reais do código, evidências da auditoria, testes, verificação de
segredos, acessibilidade e quadros do dashboard.

**Pedido:** retirar de todos os materiais qualquer menção à pontuação da atividade.

**Resultado:** tabela de critérios sem valores no PDF e no README.

## 6. Produzir o vídeo do dashboard

**Pedido:** preparar o roteiro de narração e definir estilo, fonte, paleta, duração e trilha do vídeo.

**Resultado:** roteiro em nove cenas; vídeo misto (abertura e encerramento animados com a gravação real
do painel no meio), fonte IBM Plex Sans, paleta do painel e tom sóbrio, com a narração gravada pela
equipe.

**Pedido:** cortar as tentativas repetidas de uma frase da narração e montar o vídeo.

**Resultado:** primeira versão com a gravação real do painel durante a auditoria.

**Pedido:** abaixar uma das músicas, inverter a ordem das faixas, aumentar as pausas no trecho do painel
e destacar a parte mencionada na narração, escurecendo o restante da tela.

**Resultado:** segunda versão, publicada no YouTube, com destaques, contornos e textos explicativos.

## 7. Revisar e entregar

**Pedido:** revisar tudo com cautela, dizer se a chave da API pode ser excluída e listar o que deve ser
entregue.

**Resultado:** teste do repositório do zero (clone novo, instalação limpa, sem chave), conferência do
histórico do Git e do PDF; a chave pode ser revogada, porque o sistema funciona sem ela usando as
mensagens padrão.
