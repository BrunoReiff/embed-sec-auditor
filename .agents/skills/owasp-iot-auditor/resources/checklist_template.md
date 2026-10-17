# OWASP IoT & Embedded Security Audit Checklist (Agent State Tracker)

> **Purpose of this file:** Serves as a persistent state-tracking guide showing where the agent stopped and where it must go next during an audit, unifying the official checklist from `IOT_OWASP/owasp-istg/checklists/checklist.md` with the controls of `IOT_OWASP/embeddedappsec`. **Part C (`IOT_OWASP/owasp-fstm`)** is **optional** and must only be executed if explicitly requested by the user.

---

## 🧭 Current Audit State (Agent Navigation Guide)

- **Audited Project:** `<PROJECT_NAME_OR_PATH>`
- **Last Updated:** `<YYYY-MM-DD HH:MM>`
- **Current Workflow Phase:** `[ ] Step 1: Discovery | [ ] Step 2: Classification 6.1 | [ ] Step 3: Checklist | [ ] Step 4: Execution 6.2 | [ ] Step 5: Final Report`
- **Where the Agent Stopped (Last Completed Module / Test ID):** `<Ex.: Module 2 completed up to ISTG-FW-CRYPT-001>`
- **Where the Agent Must Go Next (Next Pending Module / Test ID):** `<Ex.: Start Module 3 — Build, Bootloader & Binary Hardening (ISTG-FW-INFO-004)>`

### Execution Progress by Module (Strict Section 6.2 Order — Parts A & B Mandatory)

| Order | Section 6.2 Module | Module Status | Total Items | Completed | Pending |
| :---: | :--- | :---: | :---: | :---: | :---: |
| **1st** | **Module 1 — Embedded SAST & Memory Quality** | `PENDING` | 15 | 0 | 15 |
| **2nd** | **Module 2 — Secrets, Identity & Cryptography (`SCRT`, `CRYPT`, `AUTHZ`)** | `PENDING` | 29 | 0 | 29 |
| **3rd** | **Module 3 — Build, Bootloader & Binary Hardening (`INFO-004`, `CONF-002`)** | `PENDING` | 34 | 0 | 34 |
| **4th** | **Module 4 — Firmware Update Lifecycle (`ISTG-FW[UPDT]`)** | `PENDING` | 7 | 0 | 7 |
| **5th** | **Module 5 — Data Exchange Services & Business Logic (`ISTG-DES`)** | `PENDING` | 11 | 0 | 11 |
| **6th** | **Module 6 — SBOM & Third-Party Dependencies (`CONF-001`)** | `PENDING` | 7 | 0 | 7 |

### Project Scope Mapping (Section 6.1)

| Section 6.1 Category | Detected in Project? | Found Artifacts / Technologies | Activated Components |
| :--- | :---: | :--- | :--- |
| **1. Firmware / Embedded Code** | `[ ] Yes / [ ] No` | | `ISTG-FW`, `ISTG-MEM`, `ISTG-PROC`, `ISTG-INT[UART/I2C]`, `Embedded AppSec` |
| **2. Build System / Firmware Image** | `[ ] Yes / [ ] No` | | `ISTG-FW-INFO-004`, `ISTG-FW-CONF-002`, `ISTG-FW[INST]-CRYPT-001`, `ISTG-FW-CONF-001` |
| **3. Backend / Broker / Data Services** | `[ ] Yes / [ ] No` | | `ISTG-DES` |
| **4. Web App / Dashboard / Mobile / Interfaces** | `[ ] Yes / [ ] No` | | `ISTG-UI`, `ISTG-WRLS`, `ISTG-PHY` |

> **Item Status Legend:**
> - `PASS` (**Fully Compliant with Standards**)
> - `PARTIAL` (**Partially Compliant**)
> - `FAIL` (**Fully Non-Compliant**)
> - `N/A` (**Not Applicable to Scope**)
> - `PENDING` (**Awaiting Mandatory Verification**)
> - `OPTIONAL` (**Disabled by default — Execute only if explicitly requested by the user**)
>
> **📍 Evidence Recording Rule (Special Focus on Module 1):** In the `Notes / Evidence` column, **mandatorily** record the exact **file(s)** and **line number(s)** (`[file:LX-LY](file:///path#LX-LY)`) plus the affected function/variable name where the vulnerability resides, minimizing the effort required by the remediating agent.

---

## Part A: Official OWASP ISTG Checklist (86 Test Cases — `IOT_OWASP/owasp-istg/checklists/checklist.md`)

### 1. Processing Units (`ISTG-PROC`)
| Test ID | Test Name | Module 6.2 | Status | Notes / Evidence (File(s) & Line(s)) |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-PROC-AUTHZ** | **Authorization** | | | |
| `ISTG-PROC-AUTHZ-001` | Unauthorized Access to the Processing Unit | Module 3 | `PENDING` | |
| `ISTG-PROC-AUTHZ-002` | Privilege Escalation | Module 3 | `PENDING` | |
| **ISTG-PROC-LOGIC** | **Business Logic** | | | |
| `ISTG-PROC-LOGIC-001` | Insecure Implementation of Instructions | Module 1 | `PENDING` | |
| **ISTG-PROC-SIDEC** | **Side-Channel Attacks** | | | |
| `ISTG-PROC-SIDEC-001` | Insufficient Protection Against Side-Channel Attacks | Module 2 | `PENDING` | |

### 2. Memory (`ISTG-MEM`)
| Test ID | Test Name | Module 6.2 | Status | Notes / Evidence |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-MEM-INFO** | **Information Gathering** | | | |
| `ISTG-MEM-INFO-001` | Disclosure of Source Code and Binaries | Module 3 | `PENDING` | |
| `ISTG-MEM-INFO-002` | Disclosure of Implementation Details | Module 3 | `PENDING` | |
| `ISTG-MEM-INFO-003` | Disclosure of Ecosystem Details | Module 3 | `PENDING` | |
| `ISTG-MEM-INFO-004` | Disclosure of User Data | Module 2 | `PENDING` | |
| `ISTG-MEM-INFO-005` | Insecure Binary Compilation Options | Module 3 | `PENDING` | |
| **ISTG-MEM-SCRT** | **Secrets** | | | |
| `ISTG-MEM-SCRT-001` | Unencrypted Storage of Secrets | Module 2 | `PENDING` | |
| **ISTG-MEM-CRYPT** | **Cryptography** | | | |
| `ISTG-MEM-CRYPT-001` | Usage of Weak Cryptographic Algorithms | Module 2 | `PENDING` | |

### 3. Firmware (`ISTG-FW`)
| Test ID | Test Name | Module 6.2 | Status | Notes / Evidence |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-FW-INFO** | **Information Gathering** | | | |
| `ISTG-FW-INFO-001` | Disclosure of Source Code and Binaries | Module 3 | `PENDING` | |
| `ISTG-FW-INFO-002` | Disclosure of Implementation Details | Module 3 | `PENDING` | |
| `ISTG-FW-INFO-003` | Disclosure of Ecosystem Details | Module 3 | `PENDING` | |
| `ISTG-FW-INFO-004` | Insecure Binary Compilation Options | Module 3 | `PENDING` | |
| **ISTG-FW-CONF** | **Configuration and Patch Management** | | | |
| `ISTG-FW-CONF-001` | Usage of Outdated Software | Module 6 | `PENDING` | |
| `ISTG-FW-CONF-002` | Presence of Unnecessary Software and Functionalities | Module 3 | `PENDING` | |
| **ISTG-FW-SCRT** | **Secrets** | | | |
| `ISTG-FW-SCRT-001` | Secrets Stored in Public Storage | Module 2 | `PENDING` | |
| `ISTG-FW-SCRT-002` | Unencrypted Storage of Secrets | Module 2 | `PENDING` | |
| `ISTG-FW-SCRT-003` | Usage of Hardcoded Secrets | Module 2 | `PENDING` | |
| **ISTG-FW-CRYPT** | **Cryptography** | | | |
| `ISTG-FW-CRYPT-001` | Usage of Weak Cryptographic Algorithms | Module 2 | `PENDING` | |

#### 3.1. Installed Firmware (`ISTG-FW[INST]`)
| Test ID | Test Name | Module 6.2 | Status | Notes / Evidence |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-FW[INST]-AUTHZ** | **Authorization** | | | |
| `ISTG-FW[INST]-AUTHZ-001` | Unauthorized Access to the Firmware | Module 2 | `PENDING` | |
| `ISTG-FW[INST]-AUTHZ-002` | Privilege Escalation | Module 2 | `PENDING` | |
| **ISTG-FW[INST]-INFO** | **Information Gathering** | | | |
| `ISTG-FW[INST]-INFO-001` | Disclosure of User Data | Module 2 | `PENDING` | |
| **ISTG-FW[INST]-CRYPT** | **Cryptography** | | | |
| `ISTG-FW[INST]-CRYPT-001` | Insufficient Verification of the Bootloader Signature | Module 3 | `PENDING` | |

#### 3.2. Firmware Update Mechanism (`ISTG-FW[UPDT]`)
| Test ID | Test Name | Module 6.2 | Status | Notes / Evidence |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-FW[UPDT]-AUTHZ** | **Authorization** | | | |
| `ISTG-FW[UPDT]-AUTHZ-001` | Unauthorized Firmware Update | Module 4 | `PENDING` | |
| **ISTG-FW[UPDT]-CRYPT** | **Cryptography** | | | |
| `ISTG-FW[UPDT]-CRYPT-001` | Insufficient Firmware Update Signature | Module 4 | `PENDING` | |
| `ISTG-FW[UPDT]-CRYPT-002` | Insufficient Firmware Update Encryption | Module 4 | `PENDING` | |
| `ISTG-FW[UPDT]-CRYPT-003` | Insecure Transmission of the Firmware Update | Module 4 | `PENDING` | |
| `ISTG-FW[UPDT]-CRYPT-004` | Insufficient Verification of the Firmware Update Signature | Module 4 | `PENDING` | |
| **ISTG-FW[UPDT]-LOGIC** | **Business Logic** | | | |
| `ISTG-FW[UPDT]-LOGIC-001` | Insufficient Rollback Protection | Module 4 | `PENDING` | |

### 4. Data Exchange Services (`ISTG-DES`)
| Test ID | Test Name | Module 6.2 | Status | Notes / Evidence |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-DES-AUTHZ** | **Authorization** | | | |
| `ISTG-DES-AUTHZ-001` | Unauthorized Access to the Data Exchange Service | Module 5 | `PENDING` | |
| `ISTG-DES-AUTHZ-002` | Privilege Escalation | Module 5 | `PENDING` | |
| **ISTG-DES-INFO** | **Information Gathering** | | | |
| `ISTG-DES-INFO-001` | Disclosure of Implementation Details | Module 5 | `PENDING` | |
| `ISTG-DES-INFO-002` | Disclosure of Ecosystem Details | Module 5 | `PENDING` | |
| `ISTG-DES-INFO-003` | Disclosure of User Data | Module 5 | `PENDING` | |
| **ISTG-DES-CONF** | **Configuration and Patch Management** | | | |
| `ISTG-DES-CONF-001` | Usage of Outdated Software | Module 6 | `PENDING` | |
| `ISTG-DES-CONF-002` | Presence of Unnecessary Software and Functionalities | Module 5 | `PENDING` | |
| **ISTG-DES-SCRT** | **Secrets** | | | |
| `ISTG-DES-SCRT-001` | Access to Confidential Data | Module 2 | `PENDING` | |
| **ISTG-DES-CRYPT** | **Cryptography** | | | |
| `ISTG-DES-CRYPT-001` | Usage of Weak Cryptographic Algorithms | Module 2 | `PENDING` | |
| **ISTG-DES-LOGIC** | **Business Logic** | | | |
| `ISTG-DES-LOGIC-001` | Circumvention of the Intended Business Logic | Module 5 | `PENDING` | |
| **ISTG-DES-INPV** | **Input Validation** | | | |
| `ISTG-DES-INPV-001` | Insufficient Input Validation | Module 1 | `PENDING` | |
| `ISTG-DES-INPV-002` | Code or Command Injection | Module 1 | `PENDING` | |

### 5. Internal Interfaces (`ISTG-INT`)
| Test ID | Test Name | Module 6.2 | Status | Notes / Evidence |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-INT-AUTHZ** | **Authorization** | | | |
| `ISTG-INT-AUTHZ-001` | Unauthorized Access to the Interface | Module 2 | `PENDING` | |
| `ISTG-INT-AUTHZ-002` | Privilege Escalation | Module 2 | `PENDING` | |
| **ISTG-INT-INFO** | **Information Gathering** | | | |
| `ISTG-INT-INFO-001` | Disclosure of Implementation Details | Module 3 | `PENDING` | |
| `ISTG-INT-INFO-002` | Disclosure of Ecosystem Details | Module 3 | `PENDING` | |
| `ISTG-INT-INFO-003` | Disclosure of User Data | Module 3 | `PENDING` | |
| **ISTG-INT-CONF** | **Configuration and Patch Management** | | | |
| `ISTG-INT-CONF-001` | Usage of Outdated Software | Module 6 | `PENDING` | |
| `ISTG-INT-CONF-002` | Presence of Unnecessary Software and Functionalities | Module 3 | `PENDING` | |
| **ISTG-INT-SCRT** | **Secrets** | | | |
| `ISTG-INT-SCRT-001` | Access to Confidential Data | Module 2 | `PENDING` | |
| **ISTG-INT-CRYPT** | **Cryptography** | | | |
| `ISTG-INT-CRYPT-001` | Usage of Weak Cryptographic Algorithms | Module 2 | `PENDING` | |
| **ISTG-INT-LOGIC** | **Business Logic** | | | |
| `ISTG-INT-LOGIC-001` | Circumvention of the Intended Business Logic | Module 5 | `PENDING` | |
| **ISTG-INT-INPV** | **Input Validation** | | | |
| `ISTG-INT-INPV-001` | Insufficient Input Validation | Module 1 | `PENDING` | |
| `ISTG-INT-INPV-002` | Code or Command Injection | Module 1 | `PENDING` | |

#### 5.1. Inter-Integrated Circuit (`ISTG-INT[I2C]`)
| Test ID | Test Name | Module 6.2 | Status | Notes / Evidence |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-INT[I2C]-AUTHZ** | **Authorization** | | | |
| `ISTG-INT[I2C]-AUTHZ-001` | Bus Interaction with Unauthorized Devices | Module 3 | `PENDING` | |
| **ISTG-INT[I2C]-INFO** | **Information Gathering** | | | |
| `ISTG-INT[I2C]-INFO-001` | Slave Enumeration | Module 3 | `PENDING` | |
| `ISTG-INT[I2C]-INFO-002` | Communication Sniffing | Module 3 | `PENDING` | |
| `ISTG-INT[I2C]-INFO-003` | EEPROM/Memory Extraction | Module 3 | `PENDING` | |
| **ISTG-INT[I2C]-INPV** | **Input Validation** | | | |
| `ISTG-INT[I2C]-INPV-001` | Insufficient Handling of Invalid Data | Module 1 | `PENDING` | |

#### 5.2. Universal Asynchronous Receiver-Transmitter (`ISTG-INT[UART]`)
| Test ID | Test Name | Module 6.2 | Status | Notes / Evidence |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-INT[UART]-AUTHZ** | **Authorization** | | | |
| `ISTG-INT[UART]-AUTHZ-001` | Unauthenticated Access to Serial Console | Module 3 | `PENDING` | |
| `ISTG-INT[UART]-AUTHZ-002` | Bootloader Interrupt via Serial Console | Module 3 | `PENDING` | |
| **ISTG-INT[UART]-INFO** | **Information Gathering** | | | |
| `ISTG-INT[UART]-INFO-001` | UART Interface and Baud Rate Identification | Module 3 | `PENDING` | |
| `ISTG-INT[UART]-INFO-002` | Disclosure of Sensitive Data in Serial Output | Module 3 | `PENDING` | |
| **ISTG-INT[UART]-INPV** | **Input Validation** | | | |
| `ISTG-INT[UART]-INPV-001` | Command Injection via Serial Interface | Module 1 | `PENDING` | |

### 6. Physical Interfaces (`ISTG-PHY`)
| Test ID | Test Name | Module 6.2 | Status | Notes / Evidence |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-PHY-AUTHZ** | **Authorization** | | | |
| `ISTG-PHY-AUTHZ-001` | Unauthorized Access to the Interface | Module 2 | `PENDING` | |
| `ISTG-PHY-AUTHZ-002` | Privilege Escalation | Module 2 | `PENDING` | |
| **ISTG-PHY-INFO** | **Information Gathering** | | | |
| `ISTG-PHY-INFO-001` | Disclosure of Implementation Details | Module 3 | `PENDING` | |
| `ISTG-PHY-INFO-002` | Disclosure of Ecosystem Details | Module 3 | `PENDING` | |
| `ISTG-PHY-INFO-003` | Disclosure of User Data | Module 3 | `PENDING` | |
| **ISTG-PHY-CONF** | **Configuration and Patch Management** | | | |
| `ISTG-PHY-CONF-001` | Usage of Outdated Software | Module 6 | `PENDING` | |
| `ISTG-PHY-CONF-002` | Presence of Unnecessary Software and Functionalities | Module 3 | `PENDING` | |
| **ISTG-PHY-SCRT** | **Secrets** | | | |
| `ISTG-PHY-SCRT-001` | Access to Confidential Data | Module 2 | `PENDING` | |
| **ISTG-PHY-CRYPT** | **Cryptography** | | | |
| `ISTG-PHY-CRYPT-001` | Usage of Weak Cryptographic Algorithms | Module 2 | `PENDING` | |
| **ISTG-PHY-LOGIC** | **Business Logic** | | | |
| `ISTG-PHY-LOGIC-001` | Circumvention of the Intended Business Logic | Module 5 | `PENDING` | |
| **ISTG-PHY-INPV** | **Input Validation** | | | |
| `ISTG-PHY-INPV-001` | Insufficient Input Validation | Module 1 | `PENDING` | |
| `ISTG-PHY-INPV-002` | Code or Command Injection | Module 1 | `PENDING` | |

### 7. Wireless Interfaces (`ISTG-WRLS`)
| Test ID | Test Name | Module 6.2 | Status | Notes / Evidence |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-WRLS-AUTHZ** | **Authorization** | | | |
| `ISTG-WRLS-AUTHZ-001` | Unauthorized Access to the Interface | Module 2 | `PENDING` | |
| `ISTG-WRLS-AUTHZ-002` | Privilege Escalation | Module 2 | `PENDING` | |
| **ISTG-WRLS-INFO** | **Information Gathering** | | | |
| `ISTG-WRLS-INFO-001` | Disclosure of Implementation Details | Module 3 | `PENDING` | |
| `ISTG-WRLS-INFO-002` | Disclosure of Ecosystem Details | Module 3 | `PENDING` | |
| `ISTG-WRLS-INFO-003` | Disclosure of User Data | Module 3 | `PENDING` | |
| **ISTG-WRLS-CONF** | **Configuration and Patch Management** | | | |
| `ISTG-WRLS-CONF-001` | Usage of Outdated Software | Module 6 | `PENDING` | |
| `ISTG-WRLS-CONF-002` | Presence of Unnecessary Software and Functionalities | Module 3 | `PENDING` | |
| **ISTG-WRLS-SCRT** | **Secrets** | | | |
| `ISTG-WRLS-SCRT-001` | Access to Confidential Data | Module 2 | `PENDING` | |
| **ISTG-WRLS-CRYPT** | **Cryptography** | | | |
| `ISTG-WRLS-CRYPT-001` | Usage of Weak Cryptographic Algorithms | Module 2 | `PENDING` | |
| **ISTG-WRLS-LOGIC** | **Business Logic** | | | |
| `ISTG-WRLS-LOGIC-001` | Circumvention of the Intended Business Logic | Module 5 | `PENDING` | |
| **ISTG-WRLS-INPV** | **Input Validation** | | | |
| `ISTG-WRLS-INPV-001` | Insufficient Input Validation | Module 1 | `PENDING` | |
| `ISTG-WRLS-INPV-002` | Code or Command Injection | Module 1 | `PENDING` | |

### 8. User Interfaces (`ISTG-UI`)
| Test ID | Test Name | Module 6.2 | Status | Notes / Evidence |
| :--- | :--- | :---: | :---: | :--- |
| **ISTG-UI-AUTHZ** | **Authorization** | | | |
| `ISTG-UI-AUTHZ-001` | Unauthorized Access to the Interface | Module 2 | `PENDING` | |
| `ISTG-UI-AUTHZ-002` | Privilege Escalation | Module 2 | `PENDING` | |
| **ISTG-UI-INFO** | **Information Gathering** | | | |
| `ISTG-UI-INFO-001` | Disclosure of Implementation Details | Module 3 | `PENDING` | |
| `ISTG-UI-INFO-002` | Disclosure of Ecosystem Details | Module 3 | `PENDING` | |
| `ISTG-UI-INFO-003` | Disclosure of User Data | Module 3 | `PENDING` | |
| **ISTG-UI-CONF** | **Configuration and Patch Management** | | | |
| `ISTG-UI-CONF-001` | Usage of Outdated Software | Module 6 | `PENDING` | |
| `ISTG-UI-CONF-002` | Presence of Unnecessary Software and Functionalities | Module 3 | `PENDING` | |
| **ISTG-UI-SCRT** | **Secrets** | | | |
| `ISTG-UI-SCRT-001` | Access to Confidential Data | Module 2 | `PENDING` | |
| **ISTG-UI-CRYPT** | **Cryptography** | | | |
| `ISTG-UI-CRYPT-001` | Usage of Weak Cryptographic Algorithms | Module 2 | `PENDING` | |
| **ISTG-UI-LOGIC** | **Business Logic** | | | |
| `ISTG-UI-LOGIC-001` | Circumvention of the Intended Business Logic | Module 5 | `PENDING` | |
| **ISTG-UI-INPV** | **Input Validation** | | | |
| `ISTG-UI-INPV-001` | Insufficient Input Validation | Module 1 | `PENDING` | |
| `ISTG-UI-INPV-002` | Code or Command Injection | Module 1 | `PENDING` | |

---

## Part B: OWASP Embedded Application Security Domains (`IOT_OWASP/embeddedappsec`)

| Domain ID | Standard Topic (`embeddedappsec`) | Module 6.2 | Status | Notes / Evidence |
| :--- | :--- | :---: | :---: | :--- |
| `EMB-APPSEC-01` | Buffer and Stack Overflow Protection (`1_buffer_and_stack_overflow_protection.md`) | Module 1 | `PENDING` | |
| `EMB-APPSEC-02` | Injection Prevention (`2_injection_prevention.md`) | Module 1 | `PENDING` | |
| `EMB-APPSEC-03` | Firmware Updates and Cryptographic Signatures (`3_firmware_updates...md`) | Module 4 | `PENDING` | |
| `EMB-APPSEC-04` | Securing Sensitive Information (`4_securing_sensitive_information.md`) | Module 2 | `PENDING` | |
| `EMB-APPSEC-05` | Identity Management (`5identity_management.md`) | Module 2 | `PENDING` | |
| `EMB-APPSEC-06` | Embedded Framework & C-Based Toolchain Hardening (`6_embedded_framework...md`) | Module 3 | `PENDING` | |
| `EMB-APPSEC-07` | Usage of Debugging Code and Interfaces (`7_usage_of_debugging_code...md`) | Module 3 | `PENDING` | |
| `EMB-APPSEC-08` | Transport Layer Security (`8_transport_layer_security.md`) | Module 2 | `PENDING` | |
| `EMB-APPSEC-09` | Usage of Data Collection and Storage - Privacy (`9_usage_of_data_collection...md`) | Module 2 | `PENDING` | |
| `EMB-APPSEC-10` | Third Party Code and Components / SBOM (`10_third_party_code_and_components.md`) | Module 6 | `PENDING` | |
| `EMB-APPSEC-11` | Threat Modeling — DFD, STRIDE & DREAD (`threat-model.md`) | Module 5 | `PENDING` | |

---

## Part C (OPTIONAL — Only if Requested by User): OWASP FSTM Stages (`IOT_OWASP/owasp-fstm`)

> **Note for the Agent:** This section (`FSTM-STAGE-01` to `09`) involves deep binary extraction, QEMU/Firmadyne emulation, and runtime exploitation. **DO NOT execute it in the default mandatory workflow** — keep the items below as `OPTIONAL` and only modify/execute them if the user explicitly asks for the FSTM stages.

| Stage ID | FSTM Stage (`owasp-fstm/README.md`) | Module 6.2 | ISVS Level | Status | Notes / Evidence |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `FSTM-STAGE-01` | Stage 1: Information Gathering and Reconnaissance | Module 3 | L1 | `OPTIONAL` | Execute only upon explicit user request |
| `FSTM-STAGE-02` | Stage 2: Obtaining Firmware | Module 3 | L1 | `OPTIONAL` | Execute only upon explicit user request |
| `FSTM-STAGE-03` | Stage 3: Analyzing Firmware (Headers, Partition, Entropy) | Module 3 | L1 | `OPTIONAL` | Execute only upon explicit user request |
| `FSTM-STAGE-04` | Stage 4: Extracting the Filesystem | Module 3 | L1 | `OPTIONAL` | Execute only upon explicit user request |
| `FSTM-STAGE-05` | Stage 5: Analyzing Filesystem Contents, SAST, Checksec & SBOM | Modules 1, 2, 3, 6 | L1 | `OPTIONAL` | Execute only upon explicit user request |
| `FSTM-STAGE-06` | Stage 6: Emulating Firmware (User-mode / Full-system) | Module 5 | L2 | `OPTIONAL` | Execute only upon explicit user request |
| `FSTM-STAGE-07` | Stage 7: Dynamic Analysis (Web UI, APIs, Bootloader, OTA) | Modules 4, 5 | L2 | `OPTIONAL` | Execute only upon explicit user request |
| `FSTM-STAGE-08` | Stage 8: Runtime Analysis (Debugging, Instrumentation) | Module 5 | L3 | `OPTIONAL` | Execute only upon explicit user request |
| `FSTM-STAGE-09` | Stage 9: Binary Exploitation & ISVS Verification | Module 5 | L3 | `OPTIONAL` | Execute only upon explicit user request |
