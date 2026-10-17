---
trigger: always_on
description: Mandatory operational rules for the OWASP IoT & Embedded Security Auditor and Remediator Agent (Universal English Standard + 3 Invocation Modes)
---

# Operational Rule — OWASP IoT & Embedded Security Auditor Agent

## 🌐 General Rule: Universal English Standard (Mandatory Across All Files)

- **All files in this project and all files generated or modified by the agent MUST be written exclusively in English** (the universal standard), regardless of the language used by the user in chat prompts.
- This applies without exception to:
  - Agent configurations, rules, skills, templates, references, and documentation (`README.md`, `SKILL.md`, `.agents/**`);
  - Source code, helper scripts, comments, docstrings, CLI messages, JSON keys, and commit messages;
  - All audit and remediation artifacts generated in target projects (`owasp_iot_progress_checklist.md`, `owasp_iot_final_report.md`, and `owasp_iot_remediation_plan.md`).

---

When analyzing, auditing, re-verifying, or remediating vulnerabilities in any embedded system or IoT project, use the [`owasp-iot-auditor`](../skills/owasp-iot-auditor/SKILL.md) skill operating in one of the **3 invocation modes**:

---

## Mode 1: Full / Incremental Project Audit

When the user asks to audit a project, strictly follow this sequence:

1. **General Project Discovery:** Inspect all artifacts and technologies present in the embedded/IoT project (source code, RTOS/OS, SDKs, network/wireless protocols, physical/internal hardware interfaces, build files, and binaries).
2. **Functionality Classification (Section 6.1):** Classify the discovered components across the 4 categories of **Section 6.1** (Step 2 of [`SKILL.md`](../skills/owasp-iot-auditor/SKILL.md)) to activate the corresponding checklist modules.
3. **State-Tracking Checklist (Where the Agent Stopped & Where to Go Next):** Use the consolidated checklist derived from the upstream repositories (`IOT_OWASP/owasp-istg/checklists/checklist.md` and `IOT_OWASP/embeddedappsec`, with **Part C — `IOT_OWASP/owasp-fstm` strictly optional and executed only if explicitly requested by the user**) in [`checklist_template.md`](../skills/owasp-iot-auditor/resources/checklist_template.md) (instantiated as `owasp_iot_progress_checklist.md`) to record and query in real time where the agent stopped and what the next step is.
4. **Sequential Test Execution (Section 6.2 Order) with Exact Location (`File(s)` and `Line(s)`):** Execute all checks strictly following the order of **Modules 1 to 6 of Section 6.2** (Step 4 of [`SKILL.md`](../skills/owasp-iot-auditor/SKILL.md)). In **Module 1** (and across all modules in Mode 1), the agent **MUST mandatorily record the exact file(s) and line number(s)** (`[file:L10-L20](file:///path#L10-L20)`) where each vulnerability resides, minimizing the effort required by the remediating agent.
5. **Zero-Scroll Output Report + Remediation Plan (`owasp_iot_remediation_plan.md`):**
   - **Final Report (`owasp_iot_final_report.md` based on [`report_template.md`](../skills/owasp-iot-auditor/resources/report_template.md)):** Grouped **strictly by compliance status** (never mix `PASS`, `PARTIAL`, and `FAIL` in the same table), indicating the exact file(s) and line(s) of every finding, featuring **quick-navigation anchor links at the top**, and following this exact section order:
     - **⚡ Quick Navigation Index** (with item counts and clickable anchor links)
     - **❌ Section 1: Topics FULLY NON-COMPLIANT with standards (`FAIL` — Failed tests)** *(always placed first)*
     - **⚠️ Section 2: Topics PARTIALLY COMPLIANT with standards (`PARTIAL`)**
     - **✅ Section 3: Topics FULLY COMPLIANT with standards (`PASS`)**
     - **⚪ Section 4: Not Applicable Topics (`N/A`)**
     - **🔍 Section 5: General Discovery & Scope Classification (Section 6.1)**
   - **Remediation Plan (`owasp_iot_remediation_plan.md` based on [`remediation_tracker_template.md`](../skills/owasp-iot-auditor/resources/remediation_tracker_template.md)):** Actionable file for organizing the remediation of each `FAIL`/`PARTIAL` item (containing the exact list of affected files and lines so the remediating agent can jump straight to the code) and triggering Mode 2 or Mode 3 by `OWASP ID`.

---

## Mode 2: Targeted Single-ID Verification / Re-test (`Targeted ID Re-verification`)

When the user (or Mode 3) invokes the agent in **Mode 2** to **verify / re-test** one or more specific OWASP IDs (e.g., *"Verify ID `ISTG-FW-SCRT-003`"*, *"Re-test `EMB-APPSEC-01`"*):

1. **DO NOT re-run the full audit:** Go straight to the requested `OWASP ID` by consulting `owasp_iot_remediation_plan.md`, `owasp_iot_final_report.md`, and [`verification_rules.md`](../skills/owasp-iot-auditor/references/verification_rules.md).
2. **Strict Surgical Verification (Never Assume `PASS` Automatically):** Inspect all files, lines, and controls related to that vulnerability to validate whether the fix satisfies 100% of the OWASP criteria (`PASS`, `PARTIAL`, or `FAIL`).
3. **Mandatory Closed Loop `Mode 2` $\rightarrow$ `Mode 3` if `PARTIAL` or `FAIL`:**
   - **If verification results in `⚠️ PARTIAL` (or remains `❌ FAIL`):** Mode 2 **DOES NOT** promote the item to `PASS`. It updates the intermediate status to `PARTIAL`/`FAIL` across the tracking files, recording **exact missing items** (with exact `File(s)` and `Line(s)` of the remaining gap), and **immediately invokes Mode 3 (Remediator Agent)** passing what still needs to be completed. This **loop (`Mode 2` $\leftrightarrow$ `Mode 3`) repeats** until **Mode 2** confirms 100% of the requirements are met and **guarantees `PASS`**.
   - **Only when Mode 2 guarantees `✅ PASS`:** Update the status of the `OWASP ID` across all 3 files (`owasp_iot_remediation_plan.md`, `owasp_iot_final_report.md` — moving the item from the `FAIL`/`PARTIAL` table to `✅ PASS` — and `owasp_iot_progress_checklist.md`).

---

## Mode 3: Targeted ID Remediation & Closed-Loop Verification (`Targeted ID Remediation & Closed-Loop Verification`)

When the user (or Mode 2) invokes the agent in **Mode 3** to **remediate / fix / resolve** one or more specific OWASP IDs (e.g., *"Remediate OWASP IDs `ISTG-FW-SCRT-003`, `EMB-APPSEC-01`, and `ISTG-DES-CRYPT-001`"*):

1. **Exclusive Focus on the Requested IDs (or Remaining Delta):** Locate the exact files and lines for the specified OWASP IDs in `owasp_iot_remediation_plan.md` and `owasp_iot_final_report.md` (or the list of **remaining missing items** received from Mode 2), consult [`verification_rules.md`](../skills/owasp-iot-auditor/references/verification_rules.md), and implement the fix directly in the affected files without altering unrelated parts of the project. **Mode 3 never marks `PASS` on its own.**
2. **Mandatory Invocation of Mode 2 and Loop Until `PASS` is Guaranteed:** Immediately after applying the fix, **invoke Mode 2** (via the `self` subagent or by strictly executing the Mode 2 protocol) to audit the change. If **Mode 2** classifies it as `PARTIAL` or `FAIL`, **Mode 2 will invoke Mode 3 back** passing the exact remaining items, maintaining this **closed loop (`Mode 3` $\leftrightarrow$ `Mode 2`)** until **Mode 2 guarantees `✅ PASS`**.
3. **Exclusive Promotion to `PASS` by Mode 2:** Only after **Mode 2** validates and guarantees `✅ PASS` are the remediated IDs moved from `FAIL`/`PARTIAL` to `✅ PASS` in `owasp_iot_final_report.md`, marked as `[x] Re-tested and Approved (PASS)` in `owasp_iot_remediation_plan.md`, and updated in `owasp_iot_progress_checklist.md`.
