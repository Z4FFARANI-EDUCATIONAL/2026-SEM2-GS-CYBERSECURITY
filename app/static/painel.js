// Painel de Risco Cidadão.
// Todo texto que vem da API (inclusive o gerado pela IA) entra na página por textContent,
// nunca por innerHTML: assim um texto malicioso não vira código (XSS).

const API = "/api/v1";
const INTERVALO_MS = 2500;
const ROTULO_SINK = {
  entrada: "Relato público", log: "Registro interno (log)", resposta: "Resposta HTTP",
  erro: "Mensagem de erro", banco: "Banco de dados", dossie: "Dossiê à Prefeitura",
  llm: "Envio à IA", login: "Tela de login",
};
const ROTULO_CATEGORIA = {
  identificacao: "Documento", credencial: "Senha ou chave", saude: "Saúde",
  contato: "Contato", localizacao: "Endereço",
};

const estado = { token: null, perfil: null, nome: null, temporizador: null, ultimaMensagem: null, ultimoId: null };

// --- utilidades ----------------------------------------------------------------------------

function el(tag, atributos = {}, ...filhos) {
  const no = document.createElement(tag);
  for (const [chave, valor] of Object.entries(atributos)) {
    if (chave === "classe") no.className = valor;
    else if (chave === "dados") Object.assign(no.dataset, valor);
    else no.setAttribute(chave, valor);
  }
  for (const filho of filhos.flat()) {
    if (filho === null || filho === undefined || filho === false) continue;
    no.append(filho instanceof Node ? filho : document.createTextNode(String(filho)));
  }
  return no;
}

function hora(segundos) {
  return new Date(segundos * 1000).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function gravidade(peso) {
  if (peso >= 25) return "alta";
  if (peso >= 12) return "media";
  return "baixa";
}

function guardar(chave, valor) {
  try { valor === null ? sessionStorage.removeItem(chave) : sessionStorage.setItem(chave, valor); } catch (_) { /* sem storage */ }
}
function ler(chave) {
  try { return sessionStorage.getItem(chave); } catch (_) { return null; }
}

async function chamar(caminho, opcoes = {}) {
  const cabecalhos = { "Content-Type": "application/json" };
  if (estado.token) cabecalhos.Authorization = `Bearer ${estado.token}`;
  const resposta = await fetch(API + caminho, { ...opcoes, headers: cabecalhos });
  if (resposta.status === 401) { sair(); throw new Error("Sessão expirada"); }
  const corpo = await resposta.json().catch(() => ({}));
  if (!resposta.ok) throw new Error(corpo.detail || corpo.mensagem || "Falha na comunicação");
  return corpo;
}

// --- sessão --------------------------------------------------------------------------------

async function entrar(evento) {
  evento.preventDefault();
  const erro = document.getElementById("erro-login");
  erro.hidden = true;
  try {
    const dados = await chamar("/auth/login", {
      method: "POST",
      body: JSON.stringify({ login: document.getElementById("login").value, senha: document.getElementById("senha").value }),
    });
    Object.assign(estado, { token: dados.token, perfil: dados.perfil, nome: dados.nome });
    guardar("aja_token", dados.token); guardar("aja_perfil", dados.perfil); guardar("aja_nome", dados.nome);
    document.getElementById("senha").value = "";
    mostrarPainel();
  } catch (e) {
    erro.textContent = e.message;
    erro.hidden = false;
  }
}

function sair() {
  clearInterval(estado.temporizador);
  Object.assign(estado, { token: null, perfil: null, nome: null, ultimaMensagem: null, ultimoId: null });
  ["aja_token", "aja_perfil", "aja_nome"].forEach((c) => guardar(c, null));
  document.getElementById("tela-painel").hidden = true;
  document.getElementById("tela-login").hidden = false;
  document.getElementById("usuario").hidden = true;
  document.getElementById("sair").hidden = true;
}

function mostrarPainel() {
  document.getElementById("tela-login").hidden = true;
  document.getElementById("tela-painel").hidden = false;
  const usuario = document.getElementById("usuario");
  usuario.textContent = estado.perfil === "gestor" ? `${estado.nome} · visão executiva` : `Olá, ${estado.nome}`;
  usuario.hidden = false;
  document.getElementById("sair").hidden = false;
  document.getElementById("executivo").hidden = estado.perfil !== "gestor";
  atualizar();
  clearInterval(estado.temporizador);
  estado.temporizador = setInterval(atualizar, INTERVALO_MS);
}

// --- renderização --------------------------------------------------------------------------

function renderFarol(risco) {
  const cartao = document.querySelector(".cartao-farol");
  cartao.dataset.nivel = risco.nivel;
  document.getElementById("nivel-rotulo").textContent = risco.rotulo;
  document.getElementById("indice").textContent = risco.indice;
  document.getElementById("nivel-resumo").textContent = risco.resumo;
  document.getElementById("janela").textContent = risco.janela_min;
}

function etiquetas(evento) {
  const lista = evento.categorias.map((c) =>
    el("span", { classe: `etiqueta ${c === "saude" ? "saude" : ""}` }, ROTULO_CATEGORIA[c] || c));
  if (evento.sensivel) lista.push(el("span", { classe: "etiqueta saude" }, "Dado sensível (LGPD)"));
  lista.push(evento.origem_mensagem === "ia"
    ? el("span", { classe: "etiqueta ia" }, "Explicado por IA")
    : el("span", { classe: "etiqueta" }, evento.origem_mensagem === "pendente" ? "Traduzindo…" : "Mensagem padrão"));
  return el("div", { classe: "etiquetas" }, lista);
}

function renderMensagem(evento) {
  const alvo = document.getElementById("mensagem-recente");
  const ouvir = document.getElementById("ouvir");
  if (!evento) {
    alvo.replaceChildren(el("p", { classe: "vazio" }, "Nenhum alerta até agora. Seus dados estão protegidos."));
    ouvir.disabled = true;
    estado.ultimaMensagem = null;
    return;
  }
  const chave = `${evento.id}:${evento.origem_mensagem}`;
  if (estado.ultimoId === chave) return; // evita reler a mesma mensagem no leitor de tela
  estado.ultimoId = chave;
  const texto = evento.mensagem || "Analisando o que aconteceu…";
  alvo.replaceChildren(
    el("p", { classe: "mensagem-titulo" }, evento.titulo),
    el("p", { classe: "mensagem-texto" }, texto),
    evento.o_que_fazer ? el("p", { classe: "mensagem-acao" }, `O que fazer: ${evento.o_que_fazer}`) : null,
    el("span", { classe: "origem" }, `${hora(evento.criado_em)} · ${evento.origem_mensagem === "ia" ? "texto explicado por IA" : "texto padrão do sistema"}`),
  );
  estado.ultimaMensagem = evento.mensagem ? `${evento.titulo}. ${evento.mensagem} ${evento.o_que_fazer || ""}` : null;
  ouvir.disabled = !estado.ultimaMensagem;
}

function renderAlertas(lista, executivo) {
  const alvo = document.getElementById("alertas");
  if (!lista.length) {
    alvo.replaceChildren(el("li", { classe: "vazio" }, "Sem alertas registrados."));
    return;
  }
  alvo.replaceChildren(...lista.map((e) => {
    const tecnico = executivo ? el("div", { classe: "tecnico" },
      el("div", {}, "Técnico: ", el("code", {}, e.tipo), " em ", el("code", {}, e.sink), ` · decisão: ${e.decisao} · peso ${e.peso.toFixed(1)}`),
      el("div", {}, e.detalhe_tecnico),
      e.remediacao && e.remediacao.length
        ? el("div", {}, "Remediação sugerida:", el("ul", {}, e.remediacao.map((r) => el("li", {}, r))))
        : null,
    ) : null;
    return el("li", { classe: "alerta", dados: { gravidade: gravidade(e.peso) } },
      el("div", { classe: "alerta-topo" },
        el("p", { classe: "alerta-titulo" }, e.titulo),
        el("span", { classe: "alerta-hora" }, hora(e.criado_em))),
      el("p", { classe: "alerta-texto" }, e.mensagem || "Analisando o que aconteceu…"),
      e.o_que_fazer ? el("p", { classe: "alerta-acao" }, `O que fazer: ${e.o_que_fazer}`) : null,
      etiquetas(e),
      tecnico,
    );
  }));
}

function renderKpis(totais) {
  const itens = [
    ["Eventos registrados", totais.eventos], ["Acessos bloqueados", totais.bloqueados],
    ["Dados mascarados", totais.mascarados], ["Envolvendo saúde", totais.dados_de_saude],
    ["Cidadãos afetados", totais.cidadaos_afetados], ["Explicados por IA", totais.traduzidos_por_ia],
  ];
  document.getElementById("kpis").replaceChildren(...itens.map(([rotulo, valor]) =>
    el("div", { classe: "kpi" }, el("p", { classe: "kpi-valor" }, valor), el("p", { classe: "kpi-rotulo" }, rotulo))));
}

function renderBarras(id, itens, rotular) {
  const maximo = Math.max(1, ...itens.map((i) => i.total));
  const alvo = document.getElementById(id);
  if (!itens.length) { alvo.replaceChildren(el("p", { classe: "vazio" }, "Sem dados ainda.")); return; }
  alvo.replaceChildren(...itens.map((item) => {
    const barra = el("div", { classe: "barra-valor" });
    barra.style.width = `${(item.total / maximo) * 100}%`;
    return el("div", {},
      el("div", { classe: "barra-rotulo" }, el("span", {}, rotular(item)), el("strong", {}, item.total)),
      el("div", { classe: "barra-trilho", role: "img", "aria-label": `${rotular(item)}: ${item.total}` }, barra));
  }));
}

function renderSerie(serie) {
  const ns = "http://www.w3.org/2000/svg";
  const L = 520, A = 280, m = { e: 30, d: 8, t: 8, b: 22 };
  const x = (i) => m.e + (i / Math.max(1, serie.length - 1)) * (L - m.e - m.d);
  const y = (v) => m.t + (1 - v / 100) * (A - m.t - m.b);
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${L} ${A}`);
  svg.setAttribute("role", "img");
  const atual = serie.length ? serie[serie.length - 1].indice : 0;
  svg.setAttribute("aria-label", `Evolução do índice de risco; valor atual ${atual}`);
  const faixa = (de, ate, cor) => {
    const r = document.createElementNS(ns, "rect");
    r.setAttribute("x", m.e); r.setAttribute("width", L - m.e - m.d);
    r.setAttribute("y", y(ate)); r.setAttribute("height", y(de) - y(ate));
    r.setAttribute("fill", cor); r.setAttribute("opacity", "0.07");
    svg.append(r);
  };
  faixa(0, 30, "#4FAE7C"); faixa(30, 70, "#D8B455"); faixa(70, 100, "#D5675F");
  for (const v of [0, 30, 70, 100]) {
    const t = document.createElementNS(ns, "text");
    t.setAttribute("x", 4); t.setAttribute("y", y(v) + 4);
    t.setAttribute("fill", "#A2A8B3"); t.setAttribute("font-size", "11");
    t.textContent = v;
    svg.append(t);
  }
  const linha = document.createElementNS(ns, "polyline");
  linha.setAttribute("points", serie.map((p, i) => `${x(i)},${y(p.indice)}`).join(" "));
  linha.setAttribute("fill", "none"); linha.setAttribute("stroke", "#93AEDB");
  linha.setAttribute("stroke-width", "3"); linha.setAttribute("stroke-linejoin", "round");
  svg.append(linha);
  const legenda = document.createElementNS(ns, "text");
  legenda.setAttribute("x", L - m.d); legenda.setAttribute("y", A - 4); legenda.setAttribute("text-anchor", "end");
  legenda.setAttribute("fill", "#A2A8B3"); legenda.setAttribute("font-size", "11");
  legenda.textContent = "agora";
  svg.append(legenda);
  document.getElementById("grafico-serie").replaceChildren(svg);
}

async function atualizar() {
  try {
    if (estado.perfil === "gestor") {
      const dados = await chamar("/painel/executivo");
      renderFarol(dados.risco);
      renderMensagem(dados.alertas[0]);
      renderKpis(dados.totais);
      renderSerie(dados.serie);
      renderBarras("por-tipo", dados.por_tipo, (i) => i.titulo);
      renderBarras("por-sink", dados.por_sink, (i) => ROTULO_SINK[i.sink] || i.sink);
      renderAlertas(dados.alertas, true);
    } else {
      const dados = await chamar("/painel/cidadao");
      renderFarol(dados.risco);
      renderMensagem(dados.alertas[0]);
      renderAlertas(dados.alertas, false);
    }
  } catch (_) { /* tenta de novo no próximo ciclo */ }
}

async function estadoIA() {
  const selo = document.getElementById("estado-ia");
  try {
    const dados = await fetch(`${API}/painel/status`).then((r) => r.json());
    selo.textContent = dados.ia_configurada ? `Tradutor IA ativo · ${dados.modelo}` : "Tradutor IA desligado · mensagens padrão";
    selo.classList.toggle("ativo", dados.ia_configurada);
  } catch (_) {
    selo.textContent = "Sem conexão com a API";
  }
}

function ouvir() {
  if (!estado.ultimaMensagem || !("speechSynthesis" in window)) return;
  window.speechSynthesis.cancel();
  const fala = new SpeechSynthesisUtterance(estado.ultimaMensagem);
  fala.lang = "pt-BR";
  fala.rate = 0.95;
  window.speechSynthesis.speak(fala);
}

async function reiniciar() {
  if (!estado.token) return;
  await chamar("/painel/demo/reiniciar", { method: "POST" }).catch(() => {});
  estado.ultimoId = null;
  atualizar();
}

document.getElementById("form-login").addEventListener("submit", entrar);
document.getElementById("sair").addEventListener("click", sair);
document.getElementById("ouvir").addEventListener("click", ouvir);
document.getElementById("reiniciar").addEventListener("click", reiniciar);

estadoIA();
estado.token = ler("aja_token");
estado.perfil = ler("aja_perfil");
estado.nome = ler("aja_nome");
if (estado.token) mostrarPainel();

// VLibras (tradução para Libras) é carregado depois, sem travar o painel se o servidor externo demorar.
const vlibras = document.createElement("script");
vlibras.src = "https://vlibras.gov.br/app/vlibras-plugin.js";
vlibras.async = true;
vlibras.onload = () => {
  try { new window.VLibras.Widget("https://vlibras.gov.br/app"); } catch (_) { /* indisponível */ }
};
document.body.append(vlibras);
