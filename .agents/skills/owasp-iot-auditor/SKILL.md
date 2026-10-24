---
name: owasp-iot-auditor
description: >-
  Audits, verifies, and remediates embedded systems and IoT projects using the
  unified OWASP methodology (Embedded AppSec Best Practices, FSTM, ISTG, and
  ISVS). Generates standalone static HTML reports, remediation plans, and
  checklists in English by default (linked for single-tab browser navigation).
  Supports three specialized modular modes: (1) Full/Incremental Project Audit
  with two profiles (Mode 1.1 Standard Fast Native Audit and Mode 1.2 Deep
  Hybrid SAST Audit orchestrating Cppcheck, Gitleaks, Semgrep, Flawfinder,
  Checksec, and Trivy), (2) Targeted Single-ID Verification Mode (Strict Judge),
  and (3) Targeted ID Remediation Mode (Surgical Patch Engineer with closed-loop
  verification).
---

# OWASP IoT & Embedded Security Auditor Skill (Master Router)

> [!IMPORTANT]
> **Universal Defaults & Immutable HTML Skeleton:**
> 1. **Default Language — English:** All generated reports, remediation plans, and checklists **MUST be written in English by default**.
> 2. **Default Output Format — Static HTML (`.html`) for Single-Tab Navigation:** Outputs are standalone static HTML files (`owasp_iot_final_report.html`, `owasp_iot_remediation_plan.html`, and `owasp_iot_progress_checklist.html`) sharing a unified top navigation bar.
> 3. **🔒 Immutable HTML Skeleton & Anchor Preservation:** The HTML structure (`<head>`, `<style>`, `<nav>`, `<section>`, `<thead>`, CSS classes, `<script>`) is **100% FROZEN**. When inserting findings at declared anchors (`<!-- ANCHOR: ... -->`), **ALWAYS preserve the anchor comment** in `ReplacementContent` (or use `owasp_iot_scanner.py --inject-anchor`) so subsequent findings and re-tests never lose the insertion anchor. Never rewrite 400+ lines of HTML from scratch.
> 4. **⚡ Zero Code-Reading Rule for Scanner CLI:** Never read `.py` source files inside `scripts/` to learn CLI flags. Consult [`references/scanner_cli_reference.md`](./references/scanner_cli_reference.md) or the quick table in [`modes/mode_1_full_audit.md`](./modes/mode_1_full_audit.md).

---

## 1. Modular 3-Mode Architecture

To minimize reading latency and maximize token efficiency, this Skill routes requests to **three dedicated, specialized mode documents**:

| Mode | Agent Persona / Role | When to Use | Execution Guide |
| :--- | :--- | :--- | :--- |
| **Mode 1.1** *(Standard)* | **Lead Security Auditor** | Fast native single-pass project discovery, Section 6.1 classification, sequential Module 1–6 OWASP audit, and Fast-Path HTML report generation (`--init-all`). | 👉 [modes/mode_1_full_audit.md](./modes/mode_1_full_audit.md) |
| **Mode 1.2** *(Deep SAST)* | **Lead Security Auditor (Full-Power)** | **Everything in Mode 1.1 PLUS 6 External SAST/SCA/Binary Tools** (*Cppcheck*, *Gitleaks*, *Semgrep*, *Flawfinder*, *Checksec*, *Trivy*). Checks tools first (`--check-tools`), prompts user to install missing tools (**Option A: `--install-tools all`**), and runs `--deep-scan`. | 👉 [modes/mode_1_full_audit.md](./modes/mode_1_full_audit.md) |
| **Mode 2** | **Strict Compliance Judge** | Surgical re-test of specific OWASP IDs. Impartially verifies against acceptance criteria, enforces closed loop with Mode 3 if gaps remain, and holds exclusive authority to promote items to `PASS`. | 👉 [modes/mode_2_targeted_verification.md](./modes/mode_2_targeted_verification.md) |
| **Mode 3** | **Surgical Remediator & Patch Engineer** | Applies clean, non-breaking security patches to specific OWASP IDs. Never marks `PASS` on its own; immediately triggers Mode 2 and loops until 100% compliance is certified. | 👉 [modes/mode_3_targeted_remediation.md](./modes/mode_3_targeted_remediation.md) |

---

## 2. Master Operational Architecture & Routing Flowchart

```mermaid
flowchart TD
    USER["User Request"] --> ROUTER{"Which Mode is Requested?"}

    %% MODE 1
    ROUTER -->|Mode 1.1 Standard /Mode 1.2 Deep SAST| M1_ROUTER["Read modes/mode_1_full_audit.md<br><b>Role: Lead Security Auditor</b>"]
    M1_ROUTER --> M1_CHECK{"Mode 1.2 Requested?"}
    M1_CHECK -->|Yes| M1_TOOLS["0. Run --check-tools<br>Ask user if missing tools should be installed (Option A: --install-tools all)"]
    M1_TOOLS --> M1_EXEC["1. Discovery & 6.1 Classification (--init-all [--deep-scan])<br>2. Progress Checklist Initialization<br>3. Modules 1 to 6 Sequential Audit (Exact File/Line)<br>4. Fast-Path Template Injection (< 30s)"]
    M1_CHECK -->|No (Mode 1.1)| M1_EXEC

    %% MODE 2
    ROUTER -->|Verify / Re-test OWASP ID| M2_ROUTER["Read modes/mode_2_targeted_verification.md<br><b>Role: Strict Compliance Judge</b>"]
    M2_ROUTER --> M2_EXEC["1. Locate ID in Plan/Report<br>2. Inspect referenced files/lines vs criteria<br>3. Issue Verdict (PASS / PARTIAL / FAIL)"]

    %% MODE 3
    ROUTER -->|Remediate / Fix OWASP ID| M3_ROUTER["Read modes/mode_3_targeted_remediation.md<br><b>Role: Surgical Remediator</b>"]
    M3_ROUTER --> M3_EXEC["1. Locate vulnerability & criteria<br>2. Apply minimal non-breaking patch<br>3. Mandatory Trigger of Mode 2"]

    %% CLOSED LOOP
    M3_EXEC -->|Calls Mode 2 to Audit| M2_EXEC
    M2_EXEC -->|PARTIAL / FAIL: Gaps remain| M2_LOOP["Mode 2 sends delta missing items back to Mode 3"]
    M2_LOOP --> M3_EXEC
    M2_EXEC -->|PASS Guaranteed: 100% Compliant| M2_PASS["Mode 2 updates HTML Report, Plan & Checklist to PASS"]
```

---

## 3. On-Demand Heavy Knowledge & Tooling Index (Level 3 Assets)

When operating within any of the modes, consult these specialized assets strictly as needed:

- **Ultra-Short Scanner CLI Cheat Sheet (Read Instead of `.py` Code):** [`references/scanner_cli_reference.md`](./references/scanner_cli_reference.md)
- **External SAST Suite Catalog & Mapping:** [`references/static_analysis_tools.md`](./references/static_analysis_tools.md)
- **Surgical Regex & Acceptance Criteria:** [`references/verification_rules.md`](./references/verification_rules.md) (contains regular expressions and technical criteria for all 86 ISTG test cases and Embedded AppSec domains).
- **Base CLI Router & Modular Scripts (`scripts/`):**
  - Base Router Entrypoint: [`scripts/owasp_iot_scanner.py`](./scripts/owasp_iot_scanner.py)
  - Specialized Backend Modules: `scripts/modules/` (`html_manager.py`, `native_scanner.py`, `sast_orchestrator.py`, `tool_installer.py`, `taint_analyzer.py`, `firmware_inspector.py`)
- **Offline Semgrep IoT Ruleset & Static HTML Templates (`resources/`):**
  - Semgrep AST Ruleset: [`resources/semgrep_iot_rules.yaml`](./resources/semgrep_iot_rules.yaml)
  - Final Audit Report: [`resources/report_template.html`](./resources/report_template.html)
  - Remediation Action Plan: [`resources/remediation_tracker_template.html`](./resources/remediation_tracker_template.html)
  - State-Tracking Checklist: [`resources/checklist_template.html`](./resources/checklist_template.html)
