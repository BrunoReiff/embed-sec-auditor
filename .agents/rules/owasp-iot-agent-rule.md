---
trigger: always_on
description: Regras operacionais obrigatórias do Agente Auditor e Solucionador de Segurança OWASP IoT & Embarcados (3 Modos de Chamada)
---

# Regra Operacional do Agente Auditor OWASP IoT & Embarcados

Ao analisar, auditar, retestar ou solucionar vulnerabilidades em qualquer projeto embarcado / IoT, utilize a skill [`owasp-iot-auditor`](../skills/owasp-iot-auditor/SKILL.md) operando em um dos **3 modos de chamada**:

---

## Modo 1: Auditoria Completa / Incremental do Projeto

Quando o usuário pedir para auditar o projeto, siga rigorosamente esta sequência:

1. **Sondagem Geral do Projeto:** Verifique todos os artefatos e tecnologias presentes no projeto embarcado (código-fonte, RTOS/OS, SDKs, protocolos de rede/rádio, interfaces físicas/internas, arquivos de build e binários).
2. **Classificação de Funcionalidades (Seção 6.1):** Classifique os componentes encontrados nas 4 categorias da **Seção 6.1** (Etapa 2 de [`SKILL.md`](../skills/owasp-iot-auditor/SKILL.md)) para ativar os módulos correspondentes.
3. **Checklist como Guia de Estado (Onde Parou e Para Onde Deve Ir):** Utilize o checklist consolidado a partir dos repositórios clonados (`IOT_OWASP/owasp-istg/checklists/checklist.md` e `IOT_OWASP/embeddedappsec`, sendo a **Parte C — `IOT_OWASP/owasp-fstm` estritamente opcional e executada somente se o usuário pedir**) em [`checklist_template.md`](../skills/owasp-iot-auditor/resources/checklist_template.md) (instanciado como `owasp_iot_checklist_progresso.md`) para registrar e consultar em tempo real onde o agente parou e qual o próximo passo.
4. **Execução Sequencial de Testes (Ordem da Seção 6.2) com Localização Exata (`Arquivo(s)` e `Linha(s)`):** Execute todas as verificações seguindo estritamente a ordem dos **Módulos 1 a 6 da Seção 6.2** (Etapa 4 de [`SKILL.md`](../skills/owasp-iot-auditor/SKILL.md)). No **Módulo 1** (e em todos os módulos do Modo 1), o agente **DEVE obrigatoriamente registrar em qual(is) arquivo(s) e/ou linha(s) exata(s)** (`[arquivo:L10-L20](file:///caminho#L10-L20)`) cada vulnerabilidade se encontra, minimizando o esforço do agente que irá solucionar o problema.
5. **Relatório de Saída (Zero Scroll) + Plano de Resolução (`owasp_iot_plano_resolucao.md`):**
   - **Relatório (`owasp_iot_relatorio_final.md` baseado em [`report_template.md`](../skills/owasp-iot-auditor/resources/report_template.md)):** Agrupado **estritamente pelo status do resultado** (proibido misturar `PASS`, `PARTIAL` e `FAIL` na mesma tabela), indicando o(s) arquivo(s) e linha(s) exata(s) de cada apontamento, com **links de navegação rápida no topo** e seguindo esta ordem de seções:
     - **⚡ Índice de Navegação Rápida** (com contagem e links âncora clicáveis)
     - **❌ Seção 1: Tópicos TOTALMENTE EM DESACORDO com as normas (`FAIL` — Não passaram no teste)** *(sempre em primeiro lugar)*
     - **⚠️ Seção 2: Tópicos PARCIALMENTE DE ACORDO com as normas (`PARTIAL`)**
     - **✅ Seção 3: Tópicos DE ACORDO com as normas (`PASS`)**
     - **⚪ Seção 4: Tópicos Não Aplicáveis (`N/A`)**
     - **🔍 Seção 5: Sondagem Geral e Classificação (Seção 6.1)**
   - **Plano de Resolução (`owasp_iot_plano_resolucao.md` baseado em [`remediation_tracker_template.md`](../skills/owasp-iot-auditor/resources/remediation_tracker_template.md)):** Arquivo para o usuário organizar a correção de cada item `FAIL`/`PARTIAL` (já contendo a lista exata de todos os arquivos e linhas afetadas para o agente solucionador ir direto ao ponto) e acionar o Modo 2 ou Modo 3 pelo `ID OWASP`.

---

## Modo 2: Verificação Pontual / Reteste por ID OWASP (`Targeted ID Re-verification`)

Quando o usuário (ou o Modo 3) chamar o agente no **Modo 2** para **verificar / retestar** um ou mais IDs OWASP específicos (ex.: *"Verifique o ID `ISTG-FW-SCRT-003`"*, *"Reteste `EMB-APPSEC-01`"*):

1. **NÃO execute a auditoria completa novamente:** Vá direto ao `ID OWASP` solicitado consultando `owasp_iot_plano_resolucao.md`, `owasp_iot_relatorio_final.md` e [`verification_rules.md`](../skills/owasp-iot-auditor/references/verification_rules.md).
2. **Verificação Cirúrgica Estrita (Proibido Assumir `PASS` Automaticamente):** Inspecione todos os arquivos/linhas e controles referentes àquela vulnerabilidade para validar se a correção atende 100% às normas OWASP (`PASS`, `PARTIAL` ou `FAIL`).
3. **Loop Obrigatório `Modo 2` $\rightarrow$ `Modo 3` se Ficar `PARTIAL` ou `FAIL`:**
   - **Se a verificação resultar em `⚠️ PARTIAL` (ou continuar `❌ FAIL`):** O Modo 2 **NÃO** promove para `PASS`. Ele atualiza o status intermediário para `PARTIAL`/`FAIL` nos arquivos registrando **exatamente o que faltou concluir** (com `Arquivo(s)` e `Linha(s)` exatas da pendência) e **chama imediatamente o Modo 3 (Agente Solucionador)** passando o que faltou concluir. Esse **loop (`Modo 2` $\leftrightarrow$ `Modo 3`) repete-se** até que o **Modo 2** comprove que 100% dos requisitos foram cumpridos e **garanta o `PASS`**.
   - **Somente quando o Modo 2 garantir `✅ PASS`:** Atualize o status do `ID OWASP` nos 3 arquivos (`owasp_iot_plano_resolucao.md`, `owasp_iot_relatorio_final.md` — movendo o item da tabela `FAIL`/`PARTIAL` para `✅ PASS` — e `owasp_iot_checklist_progresso.md`).

---

## Modo 3: Resolução + Loop de Verificação por ID OWASP (`Targeted ID Remediation & Closed-Loop Verification`)

Quando o usuário (ou o Modo 2) chamar o agente no **Modo 3** para **solucionar / corrigir / resolver** um ou mais IDs OWASP específicos (ex.: *"Solucione os IDs OWASP `ISTG-FW-SCRT-003`, `EMB-APPSEC-01` e `ISTG-DES-CRYPT-001`"*):

1. **Foco Exclusivo nos IDs Solicitados (ou no que Faltou Concluir):** Localize os arquivos e linhas exatas dos IDs OWASP informados em `owasp_iot_plano_resolucao.md` e `owasp_iot_relatorio_final.md` (ou a lista do **que faltou concluir** recebida do Modo 2), consulte [`verification_rules.md`](../skills/owasp-iot-auditor/references/verification_rules.md) e implemente a correção diretamente nos arquivos afetados, sem alterar partes não relacionadas do projeto. **O Modo 3 nunca marca `PASS` por conta própria.**
2. **Acionamento Obrigatório do Modo 2 e Loop até Garantir `PASS`:** Imediatamente após aplicar a correção, **chame o Modo 2** (via subagente `self` ou execução estrita do protocolo do Modo 2) para auditar a mudança. Se o **Modo 2** classificar como `PARTIAL` ou `FAIL`, o **Modo 2 chamará de volta o Modo 3** passando exatamente o que faltou concluir, mantendo esse **loop fechado (`Modo 3` $\leftrightarrow$ `Modo 2`)** até o **Modo 2 garantir o `✅ PASS`**.
3. **Promoção para `PASS` Exclusiva pelo Modo 2:** Somente após o **Modo 2** validar e garantir `✅ PASS` é que os IDs solucionados são movidos de `FAIL`/`PARTIAL` para `✅ PASS` em `owasp_iot_relatorio_final.md`, marcados como `[x] Retestado e Aprovado (PASS)` em `owasp_iot_plano_resolucao.md` e atualizados em `owasp_iot_checklist_progresso.md`.

