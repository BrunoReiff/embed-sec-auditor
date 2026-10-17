# 🛡️ EmbedSec Auditor — OWASP IoT & Embedded Security Agent

An AI Agent (Skill + Rule) that **audits, re-verifies, and remediates** vulnerabilities in embedded systems and IoT ecosystems using a unified OWASP methodology:

- **OWASP ISTG** — IoT Security Testing Guide (86 test cases)
- **OWASP Embedded Application Security** — embedded code best practices (10 domains + threat modeling)
- **OWASP FSTM** — Firmware Security Testing Methodology *(optional, on-demand)*
- **OWASP ISVS** — IoT Security Verification Standard

Supports ESP-IDF, Arduino, PlatformIO, FreeRTOS, Zephyr, Embedded Linux (Yocto/Buildroot/OpenWrt), bare-metal firmware, as well as data exchange backends/brokers (MQTT, REST, CoAP, WebSockets) and web/mobile interfaces.

> **🌐 Output Defaults:**
> - **Language:** All generated reports, plans, and checklists are written in **English by default** (another language is used only if explicitly requested by the user).
> - **Format:** All outputs are generated as **standalone static HTML pages (`.html`) by default** with a unified top navigation bar and direct anchor links between the **Final Report (`owasp_iot_final_report.html`)**, the **Remediation Plan (`owasp_iot_remediation_plan.html`)**, and the **Progress Checklist (`owasp_iot_progress_checklist.html`)**, so you can open and navigate everything inside **a single browser tab**.

---

## 📦 Repository Structure

```text
.agents/                              ← Agent core
├── rules/
│   └── owasp-iot-agent-rule.md       ← "always_on" rule (Default English + Static HTML + 3 Modes)
└── skills/owasp-iot-auditor/
    ├── SKILL.md                      ← Complete agent operational instructions
    ├── references/
    │   └── verification_rules.md     ← Technical inspection criteria & regexes per module
    ├── resources/
    │   ├── checklist_template.html   ← Static HTML state-tracking checklist (ISTG + EmbeddedAppSec + FSTM)
    │   ├── report_template.html      ← Static HTML "zero-scroll" compliance report template
    │   └── remediation_tracker_template.html ← Static HTML remediation & re-test plan by OWASP ID
    └── scripts/
        └── owasp_iot_scanner.py      ← Discovery & triage helper script (Cross-platform Python 3)
IOT_OWASP/                            ← Upstream reference sources (git submodules of official OWASP repos)
├── embeddedappsec/
├── owasp-fstm/
└── owasp-istg/
```

> [!NOTE]
> The `IOT_OWASP/` folder serves strictly as upstream reference material from which the checklists and rules were consolidated. The agent operates standalone—everything required at runtime is inside `.agents/`.

---

## 🚀 Installation

```bash
git clone --recurse-submodules https://github.com/BrunoReiff/embed-sec-auditor.git
```

Choose how to install the agent:

| Scope | Installation Steps |
| :--- | :--- |
| **Per-Project (Workspace)** | Copy the `.agents/` folder into the root directory of the embedded/IoT project you want to audit. |
| **Global (All Projects)** | Copy `.agents/skills/owasp-iot-auditor` → `~/.gemini/config/skills/` and `.agents/rules/owasp-iot-agent-rule.md` → `~/.gemini/config/rules/`. |

Compatible with AI coding assistants that support the `.agents/` customization standard (Skills + Rules), such as Google Antigravity.

---

## 🧭 Usage — The 3 Operational Modes

| Mode | Purpose | Example Prompt |
| :--- | :--- | :--- |
| **Mode 1 — Full / Incremental Audit** | Map the entire project, run the 6 test modules, and generate the Static HTML Final Report + Linked Remediation Plan | *"Audit this project with the owasp-iot-auditor skill"* |
| **Mode 2 — Targeted ID Verification** | Re-test specific OWASP IDs as a strict compliance judge | *"Verify ID `ISTG-FW-SCRT-003`"* or *"Re-test `EMB-APPSEC-01`"* |
| **Mode 3 — Targeted ID Remediation** | Fix specific OWASP IDs with automated closed-loop verification | *"Remediate OWASP IDs `EMB-APPSEC-01` and `ISTG-DES-CRYPT-001`"* |

> To include the 9 stages of **OWASP FSTM** (binary extraction, emulation, and runtime analysis), explicitly ask: *"...including Part C (FSTM)"*.

---

## ⚙️ How the Agent Operates

### Mode 1 — Full / Incremental Audit (5 Steps)

1. **General Project Discovery** — Inventories programming languages, RTOS/OS/SDKs, hardware interfaces, build systems, cryptographic libraries, and network/wireless protocols (assisted by `owasp_iot_scanner.py`).
2. **Scope Classification (Section 6.1)** — Classifies the project across 4 functional categories (*Firmware/Embedded Code*, *Build System/Firmware Image*, *Backend/Broker/Data Services*, *Web/Mobile/User & Physical Interfaces*) and marks out-of-scope components as `N/A`.
3. **State-Tracking HTML Checklist** — Initializes or resumes `owasp_iot_progress_checklist.html`, tracking **where the agent stopped and where it must go next** so large audits can be paused and resumed seamlessly.
4. **Sequential Testing (Section 6.2)** — Executes 6 test modules in strict order, always recording the **exact file(s) and line number(s)** (`file:///path#L10-L20`) of every finding:
   1. **Module 1:** Embedded SAST & Memory Quality (banned C/C++ functions, command/code injection, RAM hygiene, stack overflow)
   2. **Module 2:** Secrets, Identity & Cryptography (hardcoded secrets, `.gitignore` rules, TLS/mTLS validation, secure storage, sessions & privacy)
   3. **Module 3:** Build, Bootloader & Binary Hardening (compiler flags, Secure Boot, Flash Encryption, JTAG/UART lockdown, surface reduction)
   4. **Module 4:** Firmware Update Lifecycle / OTA (`ISTG-FW[UPDT]` — authentication, asymmetric signatures, encrypted distribution, anti-rollback)
   5. **Module 5:** Data Exchange Services & Business Logic (`ISTG-DES` — per-device auth, MQTT ACLs, anti-replay, rate limiting, LWT)
   6. **Module 6:** SBOM & Third-Party Dependencies (pinned versions, CISA/ISVS minimum elements, CVE checks)
5. **Single-Tab Static HTML Output (Report + Linked Remediation Plan)** — Generates cross-linked static HTML files in the audited project:
   - `owasp_iot_final_report.html` — **Zero-scroll** compliance report strictly grouped by status (**`FAIL` first**, then `PARTIAL`, `PASS`, and `N/A`), with a clickable quick-navigation dashboard at the top and a direct **🛠️ Open in Remediation Plan** link on every `FAIL`/`PARTIAL` row.
   - `owasp_iot_remediation_plan.html` — Linked directly from the report in the same browser tab; contains actionable task cards for every `FAIL` and `PARTIAL` item with exact file/line locations and one-click **Copy** buttons for Mode 3 commands, external developer prompts, and Mode 2 re-verification commands.

### Mode 2 ⇄ Mode 3 — Closed-Loop Remediation & Verification

```mermaid
flowchart LR
    U["User: Remediate ID X"] --> M3["Mode 3: Applies fix at exact mapped files and lines"]
    M3 --> M2{"Mode 2: Strict compliance judge"}
    M2 -->|PARTIAL or FAIL: missing items| M3
    M2 -->|100% PASS guaranteed| OK["Promotes to PASS across HTML Report, Plan, and Checklist"]
```

- **Mode 3 never self-approves (`PASS`)** — After applying a fix, it immediately invokes Mode 2 to audit the change.
- **Mode 2 never assumes `PASS` automatically** — If a fix is incomplete (`PARTIAL` or `FAIL`), Mode 2 records **exact missing items (files & lines)** and invokes Mode 3 back.
- The **closed loop (`Mode 3` ⇄ `Mode 2`)** repeats until Mode 2 guarantees 100% compliance (`PASS`) and synchronizes all three HTML files.

---

## 🔧 Helper Script (Optional Manual Execution)

```bash
# Cross-platform (Linux / macOS / Windows with Python 3)
python3 .agents/skills/owasp-iot-auditor/scripts/owasp_iot_scanner.py --target <project_path> --init-checklist
```

Use `--verify-id <OWASP_ID>` to quickly locate all occurrences of a specific ID across the tracking files during Mode 2 re-verification.

---

## ⚠️ Disclaimer

This agent primarily performs static and configuration analysis (source code, build configs, manifests, and firmware artifacts). It complements—but does not replace—physical hardware penetration testing (e.g., live fault injection or side-channel oscilloscopes). Use only on projects and devices you are authorized to test.

## 📚 Credits

Methodology built upon official OWASP projects: [OWASP ISTG](https://github.com/OWASP/owasp-istg), [OWASP Embedded Application Security](https://github.com/scriptingxss/embeddedappsec), and [OWASP FSTM](https://github.com/scriptingxss/owasp-fstm). See each submodule for its respective license.
