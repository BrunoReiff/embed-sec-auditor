# 🛡️ EmbedSec Auditor — OWASP IoT & Embedded Security Agent

An AI Agent (Skill + Rule) that **audits, verifies, and remediates** security vulnerabilities in embedded systems, firmware, and IoT ecosystems using official OWASP standards (ISTG, Embedded Application Security, FSTM, and ISVS).

All audit deliverables are generated as **standalone static HTML pages** (`.html`) linked together so you can review findings, track remediation, and navigate everything in a **single browser tab**.

---

## 🚀 Quick Installation

Clone this repository and choose your installation scope:

```bash
git clone --recurse-submodules https://github.com/BrunoReiff/embed-sec-auditor.git
```

- **Per Project:** Copy the `.agents/` directory into the root of your target IoT/embedded project.
- **Global (All Projects):** Copy `.agents/skills/owasp-iot-auditor` to `~/.gemini/config/skills/` and `.agents/rules/owasp-iot-agent-rule.md` to `~/.gemini/config/rules/`.

Compatible with coding assistants that support the `.agents/` standard (such as Google Antigravity).

---

## 🧭 How to Use

Simply chat with your AI assistant using one of the three operational modes:

| Mode | What It Does | Example Prompt |
| :--- | :--- | :--- |
| **Mode 1 — Full Audit** | Maps the project, runs sequential OWASP checks (memory safety, secrets, bootloader, OTA, MQTT/REST, SBOM), and generates the HTML report + plan. | *"Audit this project with the owasp-iot-auditor skill"* |
| **Mode 1.2 — Deep SAST Audit** | Runs the full audit with external SAST tools (Cppcheck, Gitleaks, Semgrep, Flawfinder, Checksec, Trivy, Binwalk). Automatically checks and offers to install missing tools. | *"Run Mode 1 Deep Audit on this project"* |
| **Mode 2 — Verify Specific ID** | Acts as an impartial compliance judge to re-test an OWASP ID and verify if the patch meets 100% of the criteria. | *"Verify ID ISTG-FW-SCRT-003"* |
| **Mode 3 — Remediate & Fix** | Applies surgical, non-breaking patches to the vulnerable lines and automatically triggers Mode 2 in a closed loop until approved (`PASS`). | *"Remediate OWASP ID EMB-APPSEC-01"* |

---

## 📊 Output Deliverables

When an audit runs, three static HTML files are created in your project:

1. **`owasp_iot_final_report.html`** — Zero-scroll compliance report showing findings grouped by status (`FAIL`, `PARTIAL`, `PASS`, `N/A`), with direct links to the remediation plan.
2. **`owasp_iot_remediation_plan.html`** — Interactive task cards with exact file paths, line ranges, and one-click copy buttons to trigger fixes.
3. **`owasp_iot_progress_checklist.html`** — State tracker monitoring the exact progress across all 86 OWASP ISTG test cases.

---

## 📚 Credits & Academic References

Built upon and inspired by:
- **OWASP Foundations:** [OWASP ISTG](https://github.com/OWASP/owasp-istg), [OWASP Embedded AppSec](https://github.com/scriptingxss/embeddedappsec), [OWASP FSTM](https://github.com/scriptingxss/owasp-fstm), and [OWASP ISVS](https://github.com/OWASP/IoT-Security-Verification-Standard-ISVS).
- **[FirmAgent (NDSS Symposium)](https://www.ndss-symposium.org/ndss-paper/firmagent-leveraging-fuzzing-to-assist-llm-agents-with-iot-firmware-vulnerability-discovery/):** Inspired our intraprocedural Source-to-Sink IoT Taint Correlation engine (`taint_analyzer.py`).
- **[IoTwizz (Kushal Mistry)](https://github.com/khushalmistry/IoTwizz):** Inspired our firmware binary Shannon entropy/signature inspector (`firmware_inspector.py`) and physical interface lockdown audit.
