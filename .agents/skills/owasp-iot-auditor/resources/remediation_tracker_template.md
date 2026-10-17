# 🛠️ Plano de Resolução e Reteste Pontual por ID OWASP

**Projeto:** `<NOME_DO_PROJETO>`  
**Última Atualização:** `<YYYY-MM-DD HH:MM>`  
**Relatório Vinculado:** `[owasp_iot_relatorio_final.md](./owasp_iot_relatorio_final.md)`  
**Checklist Vinculado:** `[owasp_iot_checklist_progresso.md](./owasp_iot_checklist_progresso.md)`

---

## 💡 Como Usar Este Arquivo para Resolver os Problemas (2 Formas)

Você pode resolver os itens abaixo usando os **IDs OWASP** de duas maneiras:

### Opção A — Pedir para ESTE próprio Agente Solucionar + Verificar em Loop (Modo 3 $\leftrightarrow$ Modo 2 — Recomendado)
Basta indicar quais IDs OWASP você quer resolver de uma vez:
> `"Solucione os IDs OWASP <ID_1>, <ID_2> e <ID_3>"` *(ex.: `"Solucione os IDs OWASP ISTG-FW-SCRT-003, EMB-APPSEC-01"`)*
- O agente no **Modo 3** aplica a correção inicial e aciona o **Modo 2 (Verificador)** (sem assumir `PASS` automaticamente).
- Se o **Modo 2** detectar que a correção ficou `PARTIAL` (ou `FAIL`), o **Modo 2 chama de volta o Modo 3 passando exatamente o que faltou concluir**, mantendo esse **loop fechado** até o **Modo 2 garantir o `PASS`** e atualizar o relatório!

### Opção B — Corrigir com Outro Agente (ou Manualmente) e Chamar ESTE Agente no Modo 2
1. Copie o **"Prompt Pronto para Outro Agente Solucionador"** do card abaixo e envie para outro agente implementar.
2. Depois, chame este Agente Verificador passando apenas o ID OWASP:
   > `"Verifique o ID <ID_OWASP>"` *(ex.: `"Verifique o ID ISTG-FW-SCRT-003"`)*
   *(Se a correção externa tiver ficado `PARTIAL`, o Modo 2 apontará exatamente o que faltou e acionará o Modo 3 em loop até garantir o `PASS`!)*

---

## 📊 Painel de Progresso das Resoluções

| Status da Resolução | Quantidade |
| :--- | :---: |
| 🔴 **Pendentes de Correção (`FAIL`)** | `<N>` |
| 🟡 **Pendentes de Ajuste (`PARTIAL`)** | `<N>` |
| 🔵 **Corrigidos pelo Dev (Aguardando Reteste do Verificador)** | `<N>` |
| 🟢 **Retestados e Aprovados (`PASS`)** | `<N>` |

---

## 🔴 1. Fila de Resolução — Prioridade Alta (Itens `FAIL` / Totalmente em Desacordo)

### [ ] `<ID_OWASP>` — `<Nome do Tópico>`
- **Status Atual:** `❌ FAIL (Aguardando Correção)`
- **Módulo (6.2) / Componente:** `<Ex.: Módulo 1 / EMB-APPSEC-01 ou ISTG-DES-INPV-001>`
- **📍 Localização Exata (Arquivo(s) e Linha(s)):**
  - `[src/main.c:L42-L48](file:///caminho/absoluto/src/main.c#L42-L48)` — Função `parse_uart_cmd()`: uso de `strcpy(buf, rx_data)` sem verificação de limite (`buf[64]`).
  - `[src/network.c:L115](file:///caminho/absoluto/src/network.c#L115)` — Função `handle_mqtt_msg()`: uso de `sprintf(topic_buf, ...)` sem limite de tamanho.
- **Descrição da Falha:** `<Explicação objetiva do problema encontrado>`
- **O que precisa ser feito (Critério de Aceite OWASP):** `<Descrição exata da substituição/correção necessária em cada arquivo e linha listados acima>`
- ⚡ **Comando Direto (Modo 3 — Este Agente Soluciona + Auto-Verifica + Marca `PASS`):**
  > `"Solucione o ID OWASP <ID_OWASP>"`
- 📋 **Prompt Pronto para Outro Agente Solucionador (Caso use a Opção B — Zero Esforço de Busca):**
  > `"Corrija a vulnerabilidade <ID_OWASP> (<Nome do Tópico>) exatamente nos seguintes arquivos e linhas: (1) <caminho_arquivo_1> linhas <X-Y> na função <func_1>, (2) <caminho_arquivo_2> linha <Z> na função <func_2>. Aplique a seguinte correção: <descrição_da_correção_segura>."`
- 🔍 **Comando de Reteste Isolado (Modo 2 — Caso já tenha corrigido fora):**
  > `"Verifique o ID <ID_OWASP>"`

---

## 🟡 2. Fila de Resolução — Prioridade Média (Itens `PARTIAL` / Parcialmente de Acordo)

### [ ] `<ID_OWASP>` — `<Nome do Tópico>`
- **Status Atual:** `⚠️ PARTIAL (Mitigação Incompleta)`
- **Módulo (6.2) / Componente:** `<Ex.: Módulo 4 / FW[UPDT]>`
- **📍 Localização Exata (Arquivo(s) e Linha(s)):**
  - `[src/ota.c:L40-L60](file:///caminho/absoluto/src/ota.c#L40-L60)` — Função `verify_ota_header()`
  - `[sdkconfig:L112](file:///caminho/absoluto/sdkconfig#L112)` — Flag `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK` desativada
- **O que já existe vs. O que falta:** `<Resumo do que já foi feito e do que falta para ficar 100% de acordo>`
- ⚡ **Comando Direto (Modo 3 — Este Agente Soluciona + Auto-Verifica + Marca `PASS`):**
  > `"Solucione o ID OWASP <ID_OWASP>"`
- 📋 **Prompt Pronto para Outro Agente Solucionador (Caso use a Opção B — Zero Esforço de Busca):**
  > `"Complete a implementação do controle <ID_OWASP> (<Nome do Tópico>) exatamente no arquivo <caminho_do_arquivo> (linhas <X-Y>, função <nome_funcao>): <ajuste_necessario>."`
- 🔍 **Comando de Reteste Isolado (Modo 2 — Caso já tenha corrigido fora):**
  > `"Verifique o ID <ID_OWASP>"`

---

## 🟢 3. Histórico de Problemas Resolvidos e Aprovados no Reteste (`PASS`)

| Data/Hora do Reteste | ID OWASP | Tópico | Modo Utilizado | Status Anterior | Novo Status | Evidência da Correção Validada |
| :---: | :--- | :--- | :---: | :---: | :---: | :--- |
| `<YYYY-MM-DD HH:MM>` | `<Ex.: ISTG-FW-SCRT-003>` | Uso de Segredos Hardcoded | `Modo 3 (Auto-Verificado)` | `❌ FAIL` | `✅ PASS` | Segredos removidos de `[config.h](file:///caminho)` e migrados para NVS criptografada. |
