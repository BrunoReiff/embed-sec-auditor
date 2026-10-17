# OWASP IoT & Embedded Security Audit Report

**Analyzed Project:** `<PROJECT_NAME>`  
**Audit Date:** `<YYYY-MM-DD>`  
**Applied Standards:** OWASP Embedded AppSec Best Practices, OWASP ISTG (86 Test Cases), and OWASP ISVS.  
**Remediation & Re-verification Plan by ID:** `[owasp_iot_remediation_plan.md](./owasp_iot_remediation_plan.md)`

---

## ⚡ Quick Navigation by Result Category (Click to jump directly to section)

| Compliance Category | Count | Jump Directly to Section |
| :--- | :---: | :--- |
| ❌ **Fully Non-Compliant (`FAIL` — Failed Tests)** | `<N>` | [👉 Jump to Fully Non-Compliant (`FAIL`)](#-1-topics-fully-non-compliant-with-standards-fail) |
| ⚠️ **Partially Compliant (`PARTIAL` — Incomplete)** | `<N>` | [👉 Jump to Partially Compliant (`PARTIAL`)](#️-2-topics-partially-compliant-with-standards-partial) |
| ✅ **Fully Compliant (`PASS` — Approved)** | `<N>` | [👉 Jump to Fully Compliant (`PASS`)](#-3-topics-fully-compliant-with-standards-pass) |
| ⚪ **Not Applicable to Project (`N/A`)** | `<N>` | [👉 Jump to Not Applicable (`N/A`)](#-4-not-applicable-topics-na) |
| 🛠️ **Remediation & Re-verification Plan by OWASP ID** | `<N>` | [👉 Open `owasp_iot_remediation_plan.md`](./owasp_iot_remediation_plan.md) |
| 🔍 **General Discovery & Scope (Section 6.1)** | — | [👉 Jump to Discovery & Classification](#-5-general-project-discovery--scope-classification-section-61) |

> [!TIP]
> **How to remediate or re-test by OWASP ID (Closed Loop `Mode 3` $\leftrightarrow$ `Mode 2`):**
> - **To have this agent fix + verify in a closed loop (Mode 3):** Say `"Remediate OWASP IDs <ID_1>, <ID_2>"` (e.g., `"Remediate OWASP IDs ISTG-FW-SCRT-003, EMB-APPSEC-01"`). Mode 3 applies the fix and invokes Mode 2; if `PARTIAL`, Mode 2 returns the exact missing items to Mode 3 in a loop until Mode 2 guarantees `PASS`!
> - **To verify after another agent or developer fixes an issue (Mode 2):** Say `"Verify ID <OWASP_ID>"`. If Mode 2 identifies that the fix is `PARTIAL`, it will record what is missing and invoke Mode 3 in a loop until `PASS` is guaranteed.

---

## ❌ 1. Topics FULLY NON-COMPLIANT with Standards (`FAIL`)

> *These topics **failed the test** (missing control or confirmed vulnerability) and require priority remediation. All exact affected files and line numbers are mapped below to eliminate search effort during remediation.*

| OWASP ID | Module (6.2) | Component | Checklist Topic | Exact Location (File(s) & Line(s)) + Evidence | Risk (STRIDE / CWE) | Remediation Recommendation |
| :--- | :---: | :---: | :--- | :--- | :--- | :--- |
| `<Ex.: EMB-APPSEC-01>` | `Module 1` | `EMB-APPSEC` | Buffer and Stack Overflow Protection | `[src/main.c:L42-L48](file:///path#L42-L48)` (`parse_uart_cmd`: unbounded `strcpy`); `[src/net.c:L115](file:///path#L115)` (`sprintf` into fixed buffer) | Elevation of Privilege / `CWE-120` | Replace `strcpy`/`sprintf` with `snprintf` at the indicated lines. |
| `<Ex.: ISTG-FW-SCRT-003>` | `Module 2` | `FW` | Usage of Hardcoded Secrets | `[include/config.h:L12-L18](file:///path#L12-L18)` (Cleartext Wi-Fi password and MQTT key) | Information Disclosure / `CWE-798` | Move credentials to an encrypted NVS partition and remove from source code. |

---

## ⚠️ 2. Topics PARTIALLY COMPLIANT with Standards (`PARTIAL`)

> *These topics have a partial control implementation, but exhibit gaps or incomplete configurations at the files and lines listed below.*

| OWASP ID | Module (6.2) | Component | Checklist Topic | Exact Location (File(s) & Line(s)) + What is Missing | Direct Adjustment Recommendation |
| :--- | :---: | :---: | :--- | :--- | :--- |
| `<Ex.: ISTG-FW[UPDT]-LOGIC-001>` | `Module 4` | `FW[UPDT]` | Insufficient Rollback Protection | Checks version in `[src/ota.c:L40-L52](file:///path#L40-L52)`, but `[sdkconfig:L112](file:///path#L112)` does not enable the eFuse anti-rollback counter. | Enable `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y` at line 112 of `sdkconfig`. |

---

## ✅ 3. Topics FULLY COMPLIANT with Standards (`PASS`)

> *These topics passed testing in full and comply with OWASP standards.*

| OWASP ID | Module (6.2) | Component | Checklist Topic | Verified Evidence (File / Line) |
| :--- | :---: | :---: | :--- | :--- |
| `<Ex.: ISTG-DES-CRYPT-001>` | `Module 2` | `DES` | Strong cryptography in transit (TLS 1.2/1.3) | `[file.c](file:///path#L10-L25)` |

---

## ⚪ 4. Not Applicable Topics (`N/A`)

> *Components and test cases outside the architectural scope of this project.*

| OWASP ID / Group | Component | Justification for Non-Applicability |
| :--- | :---: | :--- |
| `<Ex.: ISTG-INT[I2C]-*>` | `INT[I2C]` | No I2C bus or peripheral present in the project. |

---

## 🔍 5. General Project Discovery & Scope Classification (Section 6.1)

### 5.1. Identified Artifacts & Technologies
- **Architecture / MCU / SoC:** `<Ex.: ESP32 (Xtensa LX6) / STM32 (ARM Cortex-M4) / Embedded Linux ARM>`
- **Operating System / SDK / Build:** `<Ex.: FreeRTOS + ESP-IDF / PlatformIO / CMakeLists.txt>`
- **Detected Protocols & Interfaces:** `<Ex.: MQTT over TLS, HTTP REST, Wi-Fi, UART, I2C, SPI>`
- **Cryptographic Libraries & Storage:** `<Ex.: mbedTLS, NVS, LittleFS>`

### 5.2. Scope Classification (Section 6.1)
| Category (Section 6.1) | Present? | Activated OWASP Modules & Components |
| :--- | :---: | :--- |
| **1. Firmware / Embedded Code** | `<Yes/No>` | `ISTG-FW`, `ISTG-MEM`, `ISTG-PROC`, `ISTG-INT[UART/I2C]`, `Embedded AppSec` |
| **2. Build System / Firmware Image** | `<Yes/No>` | `ISTG-FW-INFO-004`, `ISTG-FW-CONF-002`, `ISTG-FW[INST]-CRYPT-001`, `ISTG-FW-CONF-001` |
| **3. Backend / Broker / Data Services** | `<Yes/No>` | `ISTG-DES` |
| **4. Web App / Dashboard / Mobile / Interfaces** | `<Yes/No>` | `ISTG-UI`, `ISTG-WRLS`, `ISTG-PHY` |
