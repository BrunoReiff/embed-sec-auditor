# Checklist Guia de Auditoria OWASP IoT & Embarcados (Rastreamento de Estado do Agente)

> **Propósito deste arquivo:** Servir como guia persistente de onde o agente parou e para onde ele deve ir durante a auditoria, unificando o checklist oficial do repositório `IOT_OWASP/owasp-istg/checklists/checklist.md` com os controles do `IOT_OWASP/embeddedappsec`. A **Parte C (`IOT_OWASP/owasp-fstm`)** é **opcional** e só deve ser executada caso o usuário solicite explicitamente.

---

## 🧭 Estado Atual da Auditoria (Guia de Navegação do Agente)

- **Projeto Auditado:** `<NOME_OU_CAMINHO_DO_PROJETO>`
- **Data da Última Atualização:** `<YYYY-MM-DD HH:MM>`
- **Fase Atual do Fluxo:** `[ ] Etapa 1: Sondagem | [ ] Etapa 2: Classificação 6.1 | [ ] Etapa 3: Checklist | [ ] Etapa 4: Execução 6.2 | [ ] Etapa 5: Relatório Final`
- **Onde o Agente Parou (Último Módulo / Test ID Concluído):** `<Ex.: Módulo 2 concluído até ISTG-FW-CRYPT-001>`
- **Para Onde o Agente Deve Ir (Próximo Módulo / Test ID Pendente):** `<Ex.: Iniciar Módulo 3 — Hardening de Build, Bootloader e Binários (ISTG-FW-INFO-004)>`

### Progresso da Execução por Módulo (Ordem Estrita da Seção 6.2 — Partes A e B Obrigatórias)

| Ordem | Módulo da Seção 6.2 | Status do Módulo | Itens Totais | Concluídos | Pendentes |
| :---: | :--- | :---: | :---: | :---: | :---: |
| **1º** | **Módulo 1 — SAST Embarcado & Qualidade de Memória** | `PENDENTE` | 15 | 0 | 15 |
| **2º** | **Módulo 2 — Segredos, Identidade e Criptografia (`SCRT`, `CRYPT`, `AUTHZ`)** | `PENDENTE` | 29 | 0 | 29 |
| **3º** | **Módulo 3 — Hardening de Build, Bootloader e Binários (`INFO-004`, `CONF-002`)** | `PENDENTE` | 34 | 0 | 34 |
| **4º** | **Módulo 4 — Ciclo de Vida de Atualização de Firmware (`ISTG-FW[UPDT]`)** | `PENDENTE` | 7 | 0 | 7 |
| **5º** | **Módulo 5 — Serviços de Troca de Dados e Lógica de Negócio (`ISTG-DES`)** | `PENDENTE` | 11 | 0 | 11 |
| **6º** | **Módulo 6 — SBOM e Dependências de Terceiros (`CONF-001`)** | `PENDENTE` | 7 | 0 | 7 |

### Mapeamento de Escopo do Projeto (Seção 6.1)

| Categoria da Seção 6.1 | Detectado no Projeto? | Artefatos / Tecnologias Encontradas | Componentes Ativados |
| :--- | :---: | :--- | :--- |
| **1. Firmware / Código Embarcado** | `[ ] Sim / [ ] Não` | | `ISTG-FW`, `ISTG-MEM`, `ISTG-PROC`, `ISTG-INT[UART/I2C]`, `Embedded AppSec` |
| **2. Sistema de Build / Imagem de Firmware** | `[ ] Sim / [ ] Não` | | `ISTG-FW-INFO-004`, `ISTG-FW-CONF-002`, `ISTG-FW[INST]-CRYPT-001`, `ISTG-FW-CONF-001` |
| **3. Backend / Broker / Serviços de Dados** | `[ ] Sim / [ ] Não` | | `ISTG-DES` |
| **4. Aplicação Web / Painel / Mobile / Interfaces** | `[ ] Sim / [ ] Não` | | `ISTG-UI`, `ISTG-WRLS`, `ISTG-PHY` |

> **Legenda de Status dos Itens:**
> - `PASS` (**De Acordo com as Normas**)
> - `PARTIAL` (**Parcialmente de Acordo**)
> - `FAIL` (**Totalmente em Desacordo**)
> - `N/A` (**Não Aplicável ao Escopo**)
> - `PENDENTE` (**Aguardando Verificação Obrigatória**)
> - `OPCIONAL` (**Desativado por padrão — Executar somente se solicitado pelo usuário**)
>
> **📍 Regra de Preenchimento de Evidências (Foco Especial no Módulo 1):** Na coluna `Notes / Evidências`, registre **obrigatoriamente** em qual(is) **arquivo(s)** e **linha(s) exata(s)** (`[arquivo:LX-LY](file:///caminho#LX-LY)`) mais o nome da função/variável afetada a vulnerabilidade se encontra, minimizando o esforço do agente que fará a resolução.

---

## Parte A: Checklist Oficial OWASP ISTG (86 Casos de Teste — `IOT_OWASP/owasp-istg/checklists/checklist.md`)

### 1. Processing Units (`ISTG-PROC`)
| Test ID | Test Name | Módulo 6.2 | Status | Notes / Evidências (Arquivo(s) e Linha(s)) |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-PROC-AUTHZ** | **Authorization** | | | |
| `ISTG-PROC-AUTHZ-001` | Unauthorized Access to the Processing Unit | Módulo 3 | `PENDENTE` | |
| `ISTG-PROC-AUTHZ-002` | Privilege Escalation | Módulo 3 | `PENDENTE` | |
| **ISTG-PROC-LOGIC** | **Business Logic** | | | |
| `ISTG-PROC-LOGIC-001` | Insecure Implementation of Instructions | Módulo 1 | `PENDENTE` | |
| **ISTG-PROC-SIDEC** | **Side-Channel Attacks** | | | |
| `ISTG-PROC-SIDEC-001` | Insufficient Protection Against Side-Channel Attacks | Módulo 2 | `PENDENTE` | |

### 2. Memory (`ISTG-MEM`)
| Test ID | Test Name | Módulo 6.2 | Status | Notes / Evidências |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-MEM-INFO** | **Information Gathering** | | | |
| `ISTG-MEM-INFO-001` | Disclosure of Source Code and Binaries | Módulo 3 | `PENDENTE` | |
| `ISTG-MEM-INFO-002` | Disclosure of Implementation Details | Módulo 3 | `PENDENTE` | |
| `ISTG-MEM-INFO-003` | Disclosure of Ecosystem Details | Módulo 3 | `PENDENTE` | |
| `ISTG-MEM-INFO-004` | Disclosure of User Data | Módulo 2 | `PENDENTE` | |
| `ISTG-MEM-INFO-005` | Insecure Binary Compilation Options | Módulo 3 | `PENDENTE` | |
| **ISTG-MEM-SCRT** | **Secrets** | | | |
| `ISTG-MEM-SCRT-001` | Unencrypted Storage of Secrets | Módulo 2 | `PENDENTE` | |
| **ISTG-MEM-CRYPT** | **Cryptography** | | | |
| `ISTG-MEM-CRYPT-001` | Usage of Weak Cryptographic Algorithms | Módulo 2 | `PENDENTE` | |

### 3. Firmware (`ISTG-FW`)
| Test ID | Test Name | Módulo 6.2 | Status | Notes / Evidências |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-FW-INFO** | **Information Gathering** | | | |
| `ISTG-FW-INFO-001` | Disclosure of Source Code and Binaries | Módulo 3 | `PENDENTE` | |
| `ISTG-FW-INFO-002` | Disclosure of Implementation Details | Módulo 3 | `PENDENTE` | |
| `ISTG-FW-INFO-003` | Disclosure of Ecosystem Details | Módulo 3 | `PENDENTE` | |
| `ISTG-FW-INFO-004` | Insecure Binary Compilation Options | Módulo 3 | `PENDENTE` | |
| **ISTG-FW-CONF** | **Configuration and Patch Management** | | | |
| `ISTG-FW-CONF-001` | Usage of Outdated Software | Módulo 6 | `PENDENTE` | |
| `ISTG-FW-CONF-002` | Presence of Unnecessary Software and Functionalities | Módulo 3 | `PENDENTE` | |
| **ISTG-FW-SCRT** | **Secrets** | | | |
| `ISTG-FW-SCRT-001` | Secrets Stored in Public Storage | Módulo 2 | `PENDENTE` | |
| `ISTG-FW-SCRT-002` | Unencrypted Storage of Secrets | Módulo 2 | `PENDENTE` | |
| `ISTG-FW-SCRT-003` | Usage of Hardcoded Secrets | Módulo 2 | `PENDENTE` | |
| **ISTG-FW-CRYPT** | **Cryptography** | | | |
| `ISTG-FW-CRYPT-001` | Usage of Weak Cryptographic Algorithms | Módulo 2 | `PENDENTE` | |

#### 3.1. Installed Firmware (`ISTG-FW[INST]`)
| Test ID | Test Name | Módulo 6.2 | Status | Notes / Evidências |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-FW[INST]-AUTHZ** | **Authorization** | | | |
| `ISTG-FW[INST]-AUTHZ-001` | Unauthorized Access to the Firmware | Módulo 2 | `PENDENTE` | |
| `ISTG-FW[INST]-AUTHZ-002` | Privilege Escalation | Módulo 2 | `PENDENTE` | |
| **ISTG-FW[INST]-INFO** | **Information Gathering** | | | |
| `ISTG-FW[INST]-INFO-001` | Disclosure of User Data | Módulo 2 | `PENDENTE` | |
| **ISTG-FW[INST]-CRYPT** | **Cryptography** | | | |
| `ISTG-FW[INST]-CRYPT-001` | Insufficient Verification of the Bootloader Signature | Módulo 3 | `PENDENTE` | |

#### 3.2. Firmware Update Mechanism (`ISTG-FW[UPDT]`)
| Test ID | Test Name | Módulo 6.2 | Status | Notes / Evidências |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-FW[UPDT]-AUTHZ** | **Authorization** | | | |
| `ISTG-FW[UPDT]-AUTHZ-001` | Unauthorized Firmware Update | Módulo 4 | `PENDENTE` | |
| **ISTG-FW[UPDT]-CRYPT** | **Cryptography** | | | |
| `ISTG-FW[UPDT]-CRYPT-001` | Insufficient Firmware Update Signature | Módulo 4 | `PENDENTE` | |
| `ISTG-FW[UPDT]-CRYPT-002` | Insufficient Firmware Update Encryption | Módulo 4 | `PENDENTE` | |
| `ISTG-FW[UPDT]-CRYPT-003` | Insecure Transmission of the Firmware Update | Módulo 4 | `PENDENTE` | |
| `ISTG-FW[UPDT]-CRYPT-004` | Insufficient Verification of the Firmware Update Signature | Módulo 4 | `PENDENTE` | |
| **ISTG-FW[UPDT]-LOGIC** | **Business Logic** | | | |
| `ISTG-FW[UPDT]-LOGIC-001` | Insufficient Rollback Protection | Módulo 4 | `PENDENTE` | |

### 4. Data Exchange Services (`ISTG-DES`)
| Test ID | Test Name | Módulo 6.2 | Status | Notes / Evidências |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-DES-AUTHZ** | **Authorization** | | | |
| `ISTG-DES-AUTHZ-001` | Unauthorized Access to the Data Exchange Service | Módulo 5 | `PENDENTE` | |
| `ISTG-DES-AUTHZ-002` | Privilege Escalation | Módulo 5 | `PENDENTE` | |
| **ISTG-DES-INFO** | **Information Gathering** | | | |
| `ISTG-DES-INFO-001` | Disclosure of Implementation Details | Módulo 5 | `PENDENTE` | |
| `ISTG-DES-INFO-002` | Disclosure of Ecosystem Details | Módulo 5 | `PENDENTE` | |
| `ISTG-DES-INFO-003` | Disclosure of User Data | Módulo 5 | `PENDENTE` | |
| **ISTG-DES-CONF** | **Configuration and Patch Management** | | | |
| `ISTG-DES-CONF-001` | Usage of Outdated Software | Módulo 6 | `PENDENTE` | |
| `ISTG-DES-CONF-002` | Presence of Unnecessary Software and Functionalities | Módulo 5 | `PENDENTE` | |
| **ISTG-DES-SCRT** | **Secrets** | | | |
| `ISTG-DES-SCRT-001` | Access to Confidential Data | Módulo 2 | `PENDENTE` | |
| **ISTG-DES-CRYPT** | **Cryptography** | | | |
| `ISTG-DES-CRYPT-001` | Usage of Weak Cryptographic Algorithms | Módulo 2 | `PENDENTE` | |
| **ISTG-DES-LOGIC** | **Business Logic** | | | |
| `ISTG-DES-LOGIC-001` | Circumvention of the Intended Business Logic | Módulo 5 | `PENDENTE` | |
| **ISTG-DES-INPV** | **Input Validation** | | | |
| `ISTG-DES-INPV-001` | Insufficient Input Validation | Módulo 1 | `PENDENTE` | |
| `ISTG-DES-INPV-002` | Code or Command Injection | Módulo 1 | `PENDENTE` | |

### 5. Internal Interfaces (`ISTG-INT`)
| Test ID | Test Name | Módulo 6.2 | Status | Notes / Evidências |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-INT-AUTHZ** | **Authorization** | | | |
| `ISTG-INT-AUTHZ-001` | Unauthorized Access to the Interface | Módulo 2 | `PENDENTE` | |
| `ISTG-INT-AUTHZ-002` | Privilege Escalation | Módulo 2 | `PENDENTE` | |
| **ISTG-INT-INFO** | **Information Gathering** | | | |
| `ISTG-INT-INFO-001` | Disclosure of Implementation Details | Módulo 3 | `PENDENTE` | |
| `ISTG-INT-INFO-002` | Disclosure of Ecosystem Details | Módulo 3 | `PENDENTE` | |
| `ISTG-INT-INFO-003` | Disclosure of User Data | Módulo 3 | `PENDENTE` | |
| **ISTG-INT-CONF** | **Configuration and Patch Management** | | | |
| `ISTG-INT-CONF-001` | Usage of Outdated Software | Módulo 6 | `PENDENTE` | |
| `ISTG-INT-CONF-002` | Presence of Unnecessary Software and Functionalities | Módulo 3 | `PENDENTE` | |
| **ISTG-INT-SCRT** | **Secrets** | | | |
| `ISTG-INT-SCRT-001` | Access to Confidential Data | Módulo 2 | `PENDENTE` | |
| **ISTG-INT-CRYPT** | **Cryptography** | | | |
| `ISTG-INT-CRYPT-001` | Usage of Weak Cryptographic Algorithms | Módulo 2 | `PENDENTE` | |
| **ISTG-INT-LOGIC** | **Business Logic** | | | |
| `ISTG-INT-LOGIC-001` | Circumvention of the Intended Business Logic | Módulo 5 | `PENDENTE` | |
| **ISTG-INT-INPV** | **Input Validation** | | | |
| `ISTG-INT-INPV-001` | Insufficient Input Validation | Módulo 1 | `PENDENTE` | |
| `ISTG-INT-INPV-002` | Code or Command Injection | Módulo 1 | `PENDENTE` | |

#### 5.1. Inter-Integrated Circuit (`ISTG-INT[I2C]`)
| Test ID | Test Name | Módulo 6.2 | Status | Notes / Evidências |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-INT[I2C]-AUTHZ** | **Authorization** | | | |
| `ISTG-INT[I2C]-AUTHZ-001` | Bus Interaction with Unauthorized Devices | Módulo 3 | `PENDENTE` | |
| **ISTG-INT[I2C]-INFO** | **Information Gathering** | | | |
| `ISTG-INT[I2C]-INFO-001` | Slave Enumeration | Módulo 3 | `PENDENTE` | |
| `ISTG-INT[I2C]-INFO-002` | Communication Sniffing | Módulo 3 | `PENDENTE` | |
| `ISTG-INT[I2C]-INFO-003` | EEPROM/Memory Extraction | Módulo 3 | `PENDENTE` | |
| **ISTG-INT[I2C]-INPV** | **Input Validation** | | | |
| `ISTG-INT[I2C]-INPV-001` | Insufficient Handling of Invalid Data | Módulo 1 | `PENDENTE` | |

#### 5.2. Universal Asynchronous Receiver-Transmitter (`ISTG-INT[UART]`)
| Test ID | Test Name | Módulo 6.2 | Status | Notes / Evidências |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-INT[UART]-AUTHZ** | **Authorization** | | | |
| `ISTG-INT[UART]-AUTHZ-001` | Unauthenticated Access to Serial Console | Módulo 3 | `PENDENTE` | |
| `ISTG-INT[UART]-AUTHZ-002` | Bootloader Interrupt via Serial Console | Módulo 3 | `PENDENTE` | |
| **ISTG-INT[UART]-INFO** | **Information Gathering** | | | |
| `ISTG-INT[UART]-INFO-001` | UART Interface and Baud Rate Identification | Módulo 3 | `PENDENTE` | |
| `ISTG-INT[UART]-INFO-002` | Disclosure of Sensitive Data in Serial Output | Módulo 3 | `PENDENTE` | |
| **ISTG-INT[UART]-INPV** | **Input Validation** | | | |
| `ISTG-INT[UART]-INPV-001` | Command Injection via Serial Interface | Módulo 1 | `PENDENTE` | |

### 6. Physical Interfaces (`ISTG-PHY`)
| Test ID | Test Name | Módulo 6.2 | Status | Notes / Evidências |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-PHY-AUTHZ** | **Authorization** | | | |
| `ISTG-PHY-AUTHZ-001` | Unauthorized Access to the Interface | Módulo 2 | `PENDENTE` | |
| `ISTG-PHY-AUTHZ-002` | Privilege Escalation | Módulo 2 | `PENDENTE` | |
| **ISTG-PHY-INFO** | **Information Gathering** | | | |
| `ISTG-PHY-INFO-001` | Disclosure of Implementation Details | Módulo 3 | `PENDENTE` | |
| `ISTG-PHY-INFO-002` | Disclosure of Ecosystem Details | Módulo 3 | `PENDENTE` | |
| `ISTG-PHY-INFO-003` | Disclosure of User Data | Módulo 3 | `PENDENTE` | |
| **ISTG-PHY-CONF** | **Configuration and Patch Management** | | | |
| `ISTG-PHY-CONF-001` | Usage of Outdated Software | Módulo 6 | `PENDENTE` | |
| `ISTG-PHY-CONF-002` | Presence of Unnecessary Software and Functionalities | Módulo 3 | `PENDENTE` | |
| **ISTG-PHY-SCRT** | **Secrets** | | | |
| `ISTG-PHY-SCRT-001` | Access to Confidential Data | Módulo 2 | `PENDENTE` | |
| **ISTG-PHY-CRYPT** | **Cryptography** | | | |
| `ISTG-PHY-CRYPT-001` | Usage of Weak Cryptographic Algorithms | Módulo 2 | `PENDENTE` | |
| **ISTG-PHY-LOGIC** | **Business Logic** | | | |
| `ISTG-PHY-LOGIC-001` | Circumvention of the Intended Business Logic | Módulo 5 | `PENDENTE` | |
| **ISTG-PHY-INPV** | **Input Validation** | | | |
| `ISTG-PHY-INPV-001` | Insufficient Input Validation | Módulo 1 | `PENDENTE` | |
| `ISTG-PHY-INPV-002` | Code or Command Injection | Módulo 1 | `PENDENTE` | |

### 7. Wireless Interfaces (`ISTG-WRLS`)
| Test ID | Test Name | Módulo 6.2 | Status | Notes / Evidências |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-WRLS-AUTHZ** | **Authorization** | | | |
| `ISTG-WRLS-AUTHZ-001` | Unauthorized Access to the Interface | Módulo 2 | `PENDENTE` | |
| `ISTG-WRLS-AUTHZ-002` | Privilege Escalation | Módulo 2 | `PENDENTE` | |
| **ISTG-WRLS-INFO** | **Information Gathering** | | | |
| `ISTG-WRLS-INFO-001` | Disclosure of Implementation Details | Módulo 3 | `PENDENTE` | |
| `ISTG-WRLS-INFO-002` | Disclosure of Ecosystem Details | Módulo 3 | `PENDENTE` | |
| `ISTG-WRLS-INFO-003` | Disclosure of User Data | Módulo 3 | `PENDENTE` | |
| **ISTG-WRLS-CONF** | **Configuration and Patch Management** | | | |
| `ISTG-WRLS-CONF-001` | Usage of Outdated Software | Módulo 6 | `PENDENTE` | |
| `ISTG-WRLS-CONF-002` | Presence of Unnecessary Software and Functionalities | Módulo 3 | `PENDENTE` | |
| **ISTG-WRLS-SCRT** | **Secrets** | | | |
| `ISTG-WRLS-SCRT-001` | Access to Confidential Data | Módulo 2 | `PENDENTE` | |
| **ISTG-WRLS-CRYPT** | **Cryptography** | | | |
| `ISTG-WRLS-CRYPT-001` | Usage of Weak Cryptographic Algorithms | Módulo 2 | `PENDENTE` | |
| **ISTG-WRLS-LOGIC** | **Business Logic** | | | |
| `ISTG-WRLS-LOGIC-001` | Circumvention of the Intended Business Logic | Módulo 5 | `PENDENTE` | |
| **ISTG-WRLS-INPV** | **Input Validation** | | | |
| `ISTG-WRLS-INPV-001` | Insufficient Input Validation | Módulo 1 | `PENDENTE` | |
| `ISTG-WRLS-INPV-002` | Code or Command Injection | Módulo 1 | `PENDENTE` | |

### 8. User Interfaces (`ISTG-UI`)
| Test ID | Test Name | Módulo 6.2 | Status | Notes / Evidências |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-UI-AUTHZ** | **Authorization** | | | |
| `ISTG-UI-AUTHZ-001` | Unauthorized Access to the Interface | Módulo 2 | `PENDENTE` | |
| `ISTG-UI-AUTHZ-002` | Privilege Escalation | Módulo 2 | `PENDENTE` | |
| **ISTG-UI-INFO** | **Information Gathering** | | | |
| `ISTG-UI-INFO-001` | Disclosure of Implementation Details | Módulo 3 | `PENDENTE` | |
| `ISTG-UI-INFO-002` | Disclosure of Ecosystem Details | Módulo 3 | `PENDENTE` | |
| `ISTG-UI-INFO-003` | Disclosure of User Data | Módulo 3 | `PENDENTE` | |
| **ISTG-UI-CONF** | **Configuration and Patch Management** | | | |
| `ISTG-UI-CONF-001` | Usage of Outdated Software | Módulo 6 | `PENDENTE` | |
| `ISTG-UI-CONF-002` | Presence of Unnecessary Software and Functionalities | Módulo 3 | `PENDENTE` | |
| **ISTG-UI-SCRT** | **Secrets** | | | |
| `ISTG-UI-SCRT-001` | Access to Confidential Data | Módulo 2 | `PENDENTE` | |
| **ISTG-UI-CRYPT** | **Cryptography** | | | |
| `ISTG-UI-CRYPT-001` | Usage of Weak Cryptographic Algorithms | Módulo 2 | `PENDENTE` | |
| **ISTG-UI-LOGIC** | **Business Logic** | | | |
| `ISTG-UI-LOGIC-001` | Circumvention of the Intended Business Logic | Módulo 5 | `PENDENTE` | |
| **ISTG-UI-INPV** | **Input Validation** | | | |
| `ISTG-UI-INPV-001` | Insufficient Input Validation | Módulo 1 | `PENDENTE` | |
| `ISTG-UI-INPV-002` | Code or Command Injection | Módulo 1 | `PENDENTE` | |

---

## Parte B: Domínios do OWASP Embedded Application Security (`IOT_OWASP/embeddedappsec`)

| ID Domínio | Tópico da Norma (`embeddedappsec`) | Módulo 6.2 | Status | Notes / Evidências |
| :--- | :--- | :---: | :---: | :--- |
| `EMB-APPSEC-01` | Buffer and Stack Overflow Protection (`1_buffer_and_stack_overflow_protection.md`) | Módulo 1 | `PENDENTE` | |
| `EMB-APPSEC-02` | Injection Prevention (`2_injection_prevention.md`) | Módulo 1 | `PENDENTE` | |
| `EMB-APPSEC-03` | Firmware Updates and Cryptographic Signatures (`3_firmware_updates...md`) | Módulo 4 | `PENDENTE` | |
| `EMB-APPSEC-04` | Securing Sensitive Information (`4_securing_sensitive_information.md`) | Módulo 2 | `PENDENTE` | |
| `EMB-APPSEC-05` | Identity Management (`5identity_management.md`) | Módulo 2 | `PENDENTE` | |
| `EMB-APPSEC-06` | Embedded Framework & C-Based Toolchain Hardening (`6_embedded_framework...md`) | Módulo 3 | `PENDENTE` | |
| `EMB-APPSEC-07` | Usage of Debugging Code and Interfaces (`7_usage_of_debugging_code...md`) | Módulo 3 | `PENDENTE` | |
| `EMB-APPSEC-08` | Transport Layer Security (`8_transport_layer_security.md`) | Módulo 2 | `PENDENTE` | |
| `EMB-APPSEC-09` | Usage of Data Collection and Storage - Privacy (`9_usage_of_data_collection...md`) | Módulo 2 | `PENDENTE` | |
| `EMB-APPSEC-10` | Third Party Code and Components / SBOM (`10_third_party_code_and_components.md`) | Módulo 6 | `PENDENTE` | |
| `EMB-APPSEC-11` | Threat Modeling — DFD, STRIDE & DREAD (`threat-model.md`) | Módulo 5 | `PENDENTE` | |

---

## Parte C (OPCIONAL — Somente se Solicitado pelo Usuário): Estágios do OWASP FSTM (`IOT_OWASP/owasp-fstm`)

> **Atenção para o Agente:** Esta seção (`FSTM-STAGE-01` a `09`) envolve extração profunda de binários, emulação QEMU/Firmadyne e exploração em runtime. **NÃO a execute no fluxo padrão obrigatório** — mantenha os itens abaixo como `OPCIONAL` e só os altere/execute se o usuário pedir explicitamente os estágios do FSTM.

| ID Estágio | Estágio FSTM (`owasp-fstm/README.md`) | Módulo 6.2 | Nível ISVS | Status | Notes / Evidências |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `FSTM-STAGE-01` | Stage 1: Information Gathering and Reconnaissance | Módulo 3 | L1 | `OPCIONAL` | Executar apenas sob demanda do usuário |
| `FSTM-STAGE-02` | Stage 2: Obtaining Firmware | Módulo 3 | L1 | `OPCIONAL` | Executar apenas sob demanda do usuário |
| `FSTM-STAGE-03` | Stage 3: Analyzing Firmware (Headers, Partition, Entropy) | Módulo 3 | L1 | `OPCIONAL` | Executar apenas sob demanda do usuário |
| `FSTM-STAGE-04` | Stage 4: Extracting the Filesystem | Módulo 3 | L1 | `OPCIONAL` | Executar apenas sob demanda do usuário |
| `FSTM-STAGE-05` | Stage 5: Analyzing Filesystem Contents, SAST, Checksec & SBOM | Módulos 1, 2, 3, 6 | L1 | `OPCIONAL` | Executar apenas sob demanda do usuário |
| `FSTM-STAGE-06` | Stage 6: Emulating Firmware (User-mode / Full-system) | Módulo 5 | L2 | `OPCIONAL` | Executar apenas sob demanda do usuário |
| `FSTM-STAGE-07` | Stage 7: Dynamic Analysis (Web UI, APIs, Bootloader, OTA) | Módulos 4, 5 | L2 | `OPCIONAL` | Executar apenas sob demanda do usuário |
| `FSTM-STAGE-08` | Stage 8: Runtime Analysis (Debugging, Instrumentation) | Módulo 5 | L3 | `OPCIONAL` | Executar apenas sob demanda do usuário |
| `FSTM-STAGE-09` | Stage 9: Binary Exploitation & ISVS Verification | Módulo 5 | L3 | `OPCIONAL` | Executar apenas sob demanda do usuário |


