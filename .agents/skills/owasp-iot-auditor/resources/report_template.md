# Relatório de Auditoria de Segurança OWASP IoT & Embarcados

**Projeto Analisado:** `<NOME_DO_PROJETO>`  
**Data da Auditoria:** `<YYYY-MM-DD>`  
**Referenciais Aplicados:** OWASP Embedded AppSec Best Practices, OWASP ISTG (86 Casos de Teste) e OWASP ISVS.  
**Plano de Resolução e Reteste por ID:** `[owasp_iot_plano_resolucao.md](./owasp_iot_plano_resolucao.md)`

---

## ⚡ Navegação Rápida por Categoria de Resultado (Clique para ir direto à seção)

| Categoria de Conformidade | Quantidade | Ir Direto para a Seção |
| :--- | :---: | :--- |
| ❌ **Totalmente em Desacordo (`FAIL` — Não Passaram)** | `<N>` | [👉 Ir para Totalmente em Desacordo (`FAIL`)](#-1-tópicos-totalmente-em-desacordo-com-as-normas-fail) |
| ⚠️ **Parcialmente de Acordo (`PARTIAL` — Incompletos)** | `<N>` | [👉 Ir para Parcialmente de Acordo (`PARTIAL`)](#️-2-tópicos-parcialmente-de-acordo-com-as-normas-partial) |
| ✅ **De Acordo com as Normas (`PASS` — Aprovados)** | `<N>` | [👉 Ir para De Acordo com as Normas (`PASS`)](#-3-tópicos-de-acordo-com-as-normas-pass) |
| ⚪ **Não Aplicáveis ao Projeto (`N/A`)** | `<N>` | [👉 Ir para Não Aplicáveis (`N/A`)](#-4-tópicos-não-aplicáveis-na) |
| 🛠️ **Plano de Resolução e Reteste por ID OWASP** | `<N>` | [👉 Abrir `owasp_iot_plano_resolucao.md`](./owasp_iot_plano_resolucao.md) |
| 🔍 **Sondagem Geral e Escopo (Seção 6.1)** | — | [👉 Ir para Sondagem e Classificação](#-5-sondagem-geral-e-classificação-do-projeto-seção-61) |

> [!TIP]
> **Como resolver ou retestar por ID OWASP (Loop Fechado `Modo 3` $\leftrightarrow$ `Modo 2`):**
> - **Para este próprio agente corrigir + verificar em loop (Modo 3):** Diga `"Solucione os IDs OWASP <ID_1>, <ID_2>"` (ex.: `"Solucione os IDs OWASP ISTG-FW-SCRT-003, EMB-APPSEC-01"`). O Modo 3 corrige e chama o Modo 2; se ficar `PARTIAL`, o Modo 2 devolve ao Modo 3 passando o que faltou concluir em loop até o Modo 2 garantir `PASS`!
> - **Para verificar após outro agente corrigir (Modo 2):** Diga `"Verifique o ID <ID_OWASP>"`. Se o Modo 2 identificar que ficou `PARTIAL`, ele registrará o que faltou e acionará o Modo 3 em loop até garantir o `PASS`.

---

## ❌ 1. Tópicos TOTALMENTE EM DESACORDO com as Normas (`FAIL`)

> *Estes tópicos **não passaram no teste** (controle ausente ou vulnerabilidade confirmada) e exigem correção prioritária. Todos os arquivos e linhas exatas afetados estão mapeados abaixo para eliminar esforço de busca na correção.*

| ID OWASP | Módulo (6.2) | Componente | Tópico do Checklist | Localização Exata (Arquivo(s) e Linha(s)) + Evidência | Risco (STRIDE / CWE) | Recomendação de Correção |
| :--- | :---: | :---: | :--- | :--- | :--- | :--- |
| `<Ex.: EMB-APPSEC-01>` | `Módulo 1` | `EMB-APPSEC` | Buffer and Stack Overflow Protection | `[src/main.c:L42-L48](file:///caminho#L42-L48)` (`parse_uart_cmd`: `strcpy` sem limite); `[src/net.c:L115](file:///caminho#L115)` (`sprintf` em buffer fixo) | Elevation of Privilege / `CWE-120` | Substituir `strcpy`/`sprintf` por `snprintf` nas linhas indicadas. |
| `<Ex.: ISTG-FW-SCRT-003>` | `Módulo 2` | `FW` | Uso de Segredos Hardcoded | `[include/config.h:L12-L18](file:///caminho#L12-L18)` (Senha Wi-Fi e chave MQTT em texto claro) | Information Disclosure / `CWE-798` | Mover credenciais para partição NVS criptografada e remover do código-fonte. |

---

## ⚠️ 2. Tópicos PARCIALMENTE DE ACORDO com as Normas (`PARTIAL`)

> *Estes tópicos possuem implementação parcial do controle, mas apresentam brechas ou configurações incompletas nos arquivos e linhas abaixo.*

| ID OWASP | Módulo (6.2) | Componente | Tópico do Checklist | Localização Exata (Arquivo(s) e Linha(s)) + O que Falta | Recomendação Direta de Ajuste |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `<Ex.: ISTG-FW[UPDT]-LOGIC-001>` | `Módulo 4` | `FW[UPDT]` | Proteção contra Rollback de Firmware | Verifica versão em `[src/ota.c:L40-L52](file:///caminho#L40-L52)`, mas `[sdkconfig:L112](file:///caminho#L112)` não ativa contador anti-rollback em eFuse. | Ativar `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y` na linha 112 do `sdkconfig`. |

---

## ✅ 3. Tópicos DE ACORDO com as Normas (`PASS`)

> *Estes tópicos passaram integralmente nos testes e atendem às normas OWASP.*

| ID OWASP | Módulo (6.2) | Componente | Tópico do Checklist | Evidência Verificada (Arquivo / Linha) |
| :--- | :---: | :---: | :--- | :--- |
| `<Ex.: ISTG-DES-CRYPT-001>` | `Módulo 2` | `DES` | Uso de criptografia forte em trânsito (TLS 1.2/1.3) | `[arquivo.c](file:///caminho#L10-L25)` |

---

## ⚪ 4. Tópicos Não Aplicáveis (`N/A`)

> *Componentes e casos de teste fora do escopo arquitetural deste projeto.*

| ID / Grupo OWASP | Componente | Justificativa de Não Aplicabilidade |
| :--- | :---: | :--- |
| `<Ex.: ISTG-INT[I2C]-*>` | `INT[I2C]` | Nenhum periférico ou barramento I2C presente no projeto. |

---

## 🔍 5. Sondagem Geral e Classificação do Projeto (Seção 6.1)

### 5.1. Artefatos e Tecnologias Identificadas
- **Arquitetura / MCU / SoC:** `<Ex.: ESP32 (Xtensa LX6) / STM32 (ARM Cortex-M4) / Linux ARM>`
- **Sistema Operacional / SDK / Build:** `<Ex.: FreeRTOS + ESP-IDF / PlatformIO / CMakeLists.txt>`
- **Protocolos e Interfaces Detectadas:** `<Ex.: MQTT sobre TLS, HTTP REST, Wi-Fi, UART, I2C, SPI>`
- **Bibliotecas Criptográficas e Armazenamento:** `<Ex.: mbedTLS, NVS, LittleFS>`

### 5.2. Classificação de Escopo (Seção 6.1)
| Categoria (Seção 6.1) | Presente? | Módulos e Componentes OWASP Ativados |
| :--- | :---: | :--- |
| **1. Firmware / Código Embarcado** | `<Sim/Não>` | `ISTG-FW`, `ISTG-MEM`, `ISTG-PROC`, `ISTG-INT[UART/I2C]`, `Embedded AppSec` |
| **2. Sistema de Build / Imagem de Firmware** | `<Sim/Não>` | `ISTG-FW-INFO-004`, `ISTG-FW-CONF-002`, `ISTG-FW[INST]-CRYPT-001`, `ISTG-FW-CONF-001` |
| **3. Backend / Broker / Serviços de Dados** | `<Sim/Não>` | `ISTG-DES` |
| **4. Aplicação Web / Painel / Mobile / Interfaces** | `<Sim/Não>` | `ISTG-UI`, `ISTG-WRLS`, `ISTG-PHY` |
