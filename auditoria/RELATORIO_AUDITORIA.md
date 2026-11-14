# Relatório de auditoria do protótipo

Gerado em 14/11/2026 03:48:17 por `python -m auditoria.simular_ataques`.
Todos os dados usados são fictícios (ver `auditoria/dados_sinteticos.py`).

**Resultado: 11 de 11 cenários aprovados.**

| # | Cenário | Source | Sink | Esperado | Resultado |
|---|---|---|---|---|---|
| C01 | Cadastro com log de depuração ingênuo (logger.info do payload inteiro) | POST /api/v1/cidadaos (corpo JSON) | log (arquivo logs/aja.log) | CPF, senha, saúde e endereço mascarados no log; resposta só com dados mascarados | ✅ HTTP 201; linha de log mascarada: True; resposta: ***.982.***-25 |
| C02 | CPF inválido: o erro 422 padrão do FastAPI devolveria o valor recebido | POST /api/v1/cidadaos (CPF com dígito errado) | erro (resposta 422) | Resposta 422 sem o CPF nem a senha enviados | ✅ HTTP 422; CPF ausente da resposta: True |
| C03 | CPF na URL (?cpf=) chega ao log de acesso do servidor | GET /api/v1/cidadaos/busca?cpf=… (query string) | log (uvicorn.access) | Linha de acesso gravada com o CPF mascarado | ✅ HTTP 200; log de acesso sem o CPF: True |
| C04 | Relato público com CPF, telefone, autodeclaração de saúde e assinatura | POST /api/v1/relatos (texto livre) | banco + página pública do tópico | Texto publicado sem os dados pessoais; evento para a autora | ✅ HTTP 201; texto publicado limpo: True |
| C05 | Relato que cita pelo nome outra pessoa que já relatou no tópico | POST /api/v1/relatos + identidade dos co-autores lida do banco | página pública do tópico | Nome da outra pessoa mascarado, mesmo sem frase do tipo 'meu nome é' | ✅ HTTP 201; nome citado mascarado e público-alvo preservado |
| C06 | Rota legada sem controle de acesso, chamada sem login | banco (perfil decifrado da cidadã) | resposta HTTP não autenticada | Resposta trocada por 403 pela guarda; nada do perfil sai | ✅ HTTP 403; corpo sem PII: True |
| C07 | Outro cidadão logado pede o perfil da Joana (IDOR) | banco (perfil decifrado, titular = Joana) | resposta HTTP para outro titular | 403: o dado tem dono e quem pede não é o dono | ✅ HTTP 403 |
| C08 | Controle positivo: a própria Joana pede o seu perfil | banco (perfil decifrado, titular = Joana) | resposta HTTP para o titular | 200 com os dados completos (a guarda não bloqueia o dono) | ✅ HTTP 200; dados devolvidos ao titular |
| C09 | Código legado tenta gravar telefone em texto claro no banco | POST /api/v1/legado/cidadaos/{id}/contato (corpo JSON) | banco (tabela contatos_legado) | INSERT impedido pela guarda; tabela continua vazia | ✅ HTTP 403; linhas gravadas: 0 |
| C10 | Ataque de força bruta: 5 senhas erradas seguidas na conta da Joana | POST /api/v1/auth/login | login | Evento LOGIN_SUSPEITO e farol da Joana em vermelho (padrão de ataque) | ✅ farol da Joana: vermelho (índice 100) |
| C11 | Dossiê em PDF para a Prefeitura cujo modelo cita o nome de quem relatou | banco (nome decifrado dos autores) | dossiê PDF enviado ao órgão público | PDF sem nome, CPF ou contato; relatores aparecem como Morador(a) A e B | ✅ HTTP 200; PDF sem identidade: True |

## Varredura em repouso

O script procurou 14 valores pessoais fictícios (CPF com e sem pontuação, e-mail, senha, telefone, endereço e nome) em todo o arquivo de log e em todas as tabelas do banco.

- Ocorrências em texto claro no log: **0**
- Ocorrências em texto claro no banco: **0**

## Indicador de Risco Cidadão ao fim da auditoria

- Índice geral: **100/100** (Risco alto)
- Eventos registrados: 12 (3 bloqueios, 8 mascaramentos)
- Mensagens explicadas por IA: 12

| Tipo de evento | Total |
|---|---|
| Dado pessoal barrado no registro interno (`LOG_BLOQUEADO`) | 3 |
| Identidade preservada no dossiê (`DOSSIE_SANITIZADO`) | 2 |
| Acesso a dados pessoais bloqueado (`RESPOSTA_BLOQUEADA`) | 2 |
| Dado pessoal ocultado no relato (`PII_MASCARADA_ENTRADA`) | 2 |
| Muitas tentativas de senha (`LOGIN_SUSPEITO`) | 1 |
| Gravação sem proteção impedida (`BANCO_BLOQUEADO`) | 1 |
| Mensagem de erro limpa (`ERRO_SANITIZADO`) | 1 |

## Evidências por cenário

### C01 · Cadastro com log de depuração ingênuo (logger.info do payload inteiro)

- **Source:** POST /api/v1/cidadaos (corpo JSON)
- **Sink:** log (arquivo logs/aja.log)
- **Esperado:** CPF, senha, saúde e endereço mascarados no log; resposta só com dados mascarados
- **Obtido:** HTTP 201; linha de log mascarada: True; resposta: ***.982.***-25

```
Linha gravada no log:
2026-11-14 03:48:03,301 INFO    aja.cidadaos | Novo cadastro recebido: {'nome': 'J. E. S.', 'cpf': '***.982.***-25', 'email': 'j***@e***.com', 'senha': '[senha removida]', 'telefone': '(**) *****-**01', 'rg': None, 'data_nascimento': None, 'deficiencia': '[informação de saúde protegida]', 'endereco_residencial': '[endereço residencial protegido]'}  [guarda de taint: dado pessoal bloqueado neste log]
```

```
Resposta HTTP:
{
  "id": 2,
  "nome": "J. E. S.",
  "cpf": "***.982.***-25",
  "email": "j***@e***.com",
  "mensagem": "Cadastro criado. Seus dados pessoais ficam guardados com criptografia."
}
```

### C02 · CPF inválido: o erro 422 padrão do FastAPI devolveria o valor recebido

- **Source:** POST /api/v1/cidadaos (CPF com dígito errado)
- **Sink:** erro (resposta 422)
- **Esperado:** Resposta 422 sem o CPF nem a senha enviados
- **Obtido:** HTTP 422; CPF ausente da resposta: True

```
Resposta HTTP:
{
  "erro": "dados_invalidos",
  "mensagem": "Alguns dados não estão no formato esperado.",
  "campos": [
    {
      "campo": "cpf",
      "problema": "Value error, CPF inválido"
    }
  ],
  "evento_id": 3
}
```

### C03 · CPF na URL (?cpf=) chega ao log de acesso do servidor

- **Source:** GET /api/v1/cidadaos/busca?cpf=… (query string)
- **Sink:** log (uvicorn.access)
- **Esperado:** Linha de acesso gravada com o CPF mascarado
- **Obtido:** HTTP 200; log de acesso sem o CPF: True

```
Linha de acesso gravada:
2026-11-14 03:48:03,716 INFO    uvicorn.access | 127.0.0.1:44680 - "GET /api/v1/cidadaos/busca?cpf=***.982.***-25 HTTP/1.1" 200
```

### C04 · Relato público com CPF, telefone, autodeclaração de saúde e assinatura

- **Source:** POST /api/v1/relatos (texto livre)
- **Sink:** banco + página pública do tópico
- **Esperado:** Texto publicado sem os dados pessoais; evento para a autora
- **Obtido:** HTTP 201; texto publicado limpo: True

```
Enviado:
Sou cega e o piso tátil acaba antes da banca, a bengala perde a guia. Me liga no (11) 90000-0001 ou procure pelo CPF 529.982.247-25. Obrigada, Joana Exemplo da Silva
```

```
Publicado:
Sou [informação de saúde protegida] e o piso tátil acaba antes da banca, a bengala perde a guia. Me liga no (**) *****-**01 ou procure pelo CPF ***.982.***-25. Obrigada, J. E. S.
```

### C05 · Relato que cita pelo nome outra pessoa que já relatou no tópico

- **Source:** POST /api/v1/relatos + identidade dos co-autores lida do banco
- **Sink:** página pública do tópico
- **Esperado:** Nome da outra pessoa mascarado, mesmo sem frase do tipo 'meu nome é'
- **Obtido:** HTTP 201; nome citado mascarado e público-alvo preservado

```
Enviado:
Confirmo: tropecei ali ontem. Piso tátil para pessoas cegas termina do nada. Falei com a Joana Silva sobre isso.
```

```
Publicado:
Confirmo: tropecei ali ontem. Piso tátil para pessoas cegas termina do nada. Falei com a J. S. sobre isso.
```

### C06 · Rota legada sem controle de acesso, chamada sem login

- **Source:** banco (perfil decifrado da cidadã)
- **Sink:** resposta HTTP não autenticada
- **Esperado:** Resposta trocada por 403 pela guarda; nada do perfil sai
- **Obtido:** HTTP 403; corpo sem PII: True

```
Resposta HTTP:
{
  "erro": "acesso_bloqueado",
  "mensagem": "Esta resposta continha dados pessoais que você não tem permissão para ver. O acesso foi bloqueado e registrado.",
  "evento_id": 7
}
```

### C07 · Outro cidadão logado pede o perfil da Joana (IDOR)

- **Source:** banco (perfil decifrado, titular = Joana)
- **Sink:** resposta HTTP para outro titular
- **Esperado:** 403: o dado tem dono e quem pede não é o dono
- **Obtido:** HTTP 403

```
Resposta HTTP:
{
  "erro": "acesso_bloqueado",
  "mensagem": "Esta resposta continha dados pessoais que você não tem permissão para ver. O acesso foi bloqueado e registrado.",
  "evento_id": 8
}
```

### C08 · Controle positivo: a própria Joana pede o seu perfil

- **Source:** banco (perfil decifrado, titular = Joana)
- **Sink:** resposta HTTP para o titular
- **Esperado:** 200 com os dados completos (a guarda não bloqueia o dono)
- **Obtido:** HTTP 200; dados devolvidos ao titular

### C09 · Código legado tenta gravar telefone em texto claro no banco

- **Source:** POST /api/v1/legado/cidadaos/{id}/contato (corpo JSON)
- **Sink:** banco (tabela contatos_legado)
- **Esperado:** INSERT impedido pela guarda; tabela continua vazia
- **Obtido:** HTTP 403; linhas gravadas: 0

```
Resposta HTTP:
{
  "erro": "gravacao_bloqueada",
  "mensagem": "O sistema impediu que um dado pessoal fosse guardado sem proteção.",
  "evento_id": 9
}
```

### C10 · Ataque de força bruta: 5 senhas erradas seguidas na conta da Joana

- **Source:** POST /api/v1/auth/login
- **Sink:** login
- **Esperado:** Evento LOGIN_SUSPEITO e farol da Joana em vermelho (padrão de ataque)
- **Obtido:** farol da Joana: vermelho (índice 100)

```
Risco da Joana:
{
  "indice": 100,
  "nivel": "vermelho",
  "rotulo": "Risco alto",
  "resumo": "Há tentativas repetidas de acesso indevido. As proteções estão ativas.",
  "padrao_de_ataque": true,
  "eventos_na_janela": 5,
  "janela_min": 10.0
}
```

### C11 · Dossiê em PDF para a Prefeitura cujo modelo cita o nome de quem relatou

- **Source:** banco (nome decifrado dos autores)
- **Sink:** dossiê PDF enviado ao órgão público
- **Esperado:** PDF sem nome, CPF ou contato; relatores aparecem como Morador(a) A e B
- **Obtido:** HTTP 200; PDF sem identidade: True

```
Trecho do PDF:
2. Relatos da comunidade
Relato de Morador(a) A em 2026-11-14: Sou [informação de saúde protegida] e o piso tátil acaba antes da
banca, a bengala perde a guia. Me liga no (**) *****-**01 ou procure pelo CPF ***.982.***-25. Obrigada, J. E.
S.
Relato de Morador(a) B em 2026-11-14: Confirmo: tropecei ali ontem. Piso tátil para pessoas cegas termina
do nada. Falei com a J. S. sobre isso.
```
