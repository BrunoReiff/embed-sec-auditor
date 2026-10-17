# 🛠️ Remediation & Targeted Re-verification Plan by OWASP ID

**Project:** `<PROJECT_NAME>`  
**Last Updated:** `<YYYY-MM-DD HH:MM>`  
**Linked Report:** `[owasp_iot_final_report.md](./owasp_iot_final_report.md)`  
**Linked Checklist:** `[owasp_iot_progress_checklist.md](./owasp_iot_progress_checklist.md)`

---

## 💡 How to Use This File to Remediate Issues (2 Options)

You can resolve the items below using their **OWASP IDs** in two ways:

### Option A — Ask THIS Agent to Remediate + Verify in a Closed Loop (Mode 3 $\leftrightarrow$ Mode 2 — Recommended)
Simply specify which OWASP IDs you want to resolve at once:
> `"Remediate OWASP IDs <ID_1>, <ID_2>, and <ID_3>"` *(e.g., `"Remediate OWASP IDs ISTG-FW-SCRT-003, EMB-APPSEC-01"`)*
- The agent in **Mode 3** applies the initial fix and invokes **Mode 2 (Verifier)** (never assuming `PASS` automatically).
- If **Mode 2** detects that the fix is `PARTIAL` (or `FAIL`), **Mode 2 invokes Mode 3 back passing the exact missing items**, maintaining this **closed loop** until **Mode 2 guarantees `PASS`** and updates the report!

### Option B — Fix with Another Agent (or Manually) and Invoke THIS Agent in Mode 2
1. Copy the **"Ready-to-Copy Prompt for External Developer Agent"** from the card below and send it to another agent to implement.
2. Afterwards, invoke this Verifier Agent passing just the OWASP ID:
   > `"Verify ID <OWASP_ID>"` *(e.g., `"Verify ID ISTG-FW-SCRT-003"`)*
   *(If the external fix turns out to be `PARTIAL`, Mode 2 will pinpoint the exact missing items and invoke Mode 3 in a loop until `PASS` is guaranteed!)*

---

## 📊 Remediation Progress Dashboard

| Remediation Status | Count |
| :--- | :---: |
| 🔴 **Pending Remediation (`FAIL`)** | `<N>` |
| 🟡 **Pending Adjustment (`PARTIAL`)** | `<N>` |
| 🔵 **Fixed by Dev (Awaiting Verifier Re-test)** | `<N>` |
| 🟢 **Re-tested and Approved (`PASS`)** | `<N>` |

---

## 🔴 1. Remediation Queue — High Priority (`FAIL` / Fully Non-Compliant Items)

### [ ] `<OWASP_ID>` — `<Topic Name>`
- **Current Status:** `❌ FAIL (Awaiting Remediation)`
- **Module (6.2) / Component:** `<Ex.: Module 1 / EMB-APPSEC-01 or ISTG-DES-INPV-001>`
- **📍 Exact Location (File(s) & Line(s)):**
  - `[src/main.c:L42-L48](file:///abs/path/src/main.c#L42-L48)` — Function `parse_uart_cmd()`: unbounded `strcpy(buf, rx_data)` into `buf[64]`.
  - `[src/network.c:L115](file:///abs/path/src/network.c#L115)` — Function `handle_mqtt_msg()`: unbounded `sprintf(topic_buf, ...)`.
- **Issue Description:** `<Objective explanation of the vulnerability found>`
- **What Needs to Be Done (OWASP Acceptance Criteria):** `<Exact description of the replacement/fix required at each file and line listed above>`
- ⚡ **Direct Command (Mode 3 — This Agent Remediates + Self-Verifies + Marks `PASS`):**
  > `"Remediate OWASP ID <OWASP_ID>"`
- 📋 **Ready-to-Copy Prompt for External Developer Agent (Option B — Zero Search Effort):**
  > `"Fix vulnerability <OWASP_ID> (<Topic Name>) at the following exact files and lines: (1) <file_path_1> lines <X-Y> in function <func_1>, (2) <file_path_2> line <Z> in function <func_2>. Apply the following secure fix: <secure_fix_description>."`
- 🔍 **Standalone Re-test Command (Mode 2 — If fixed externally):**
  > `"Verify ID <OWASP_ID>"`

---

## 🟡 2. Remediation Queue — Medium Priority (`PARTIAL` / Partially Compliant Items)

### [ ] `<OWASP_ID>` — `<Topic Name>`
- **Current Status:** `⚠️ PARTIAL (Incomplete Mitigation)`
- **Module (6.2) / Component:** `<Ex.: Module 4 / FW[UPDT]>`
- **📍 Exact Location (File(s) & Line(s)):**
  - `[src/ota.c:L40-L60](file:///abs/path/src/ota.c#L40-L60)` — Function `verify_ota_header()`
  - `[sdkconfig:L112](file:///abs/path/sdkconfig#L112)` — Flag `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK` disabled
- **What Already Exists vs. What is Missing:** `<Summary of what is already implemented and what is missing to achieve 100% compliance>`
- ⚡ **Direct Command (Mode 3 — This Agent Remediates + Self-Verifies + Marks `PASS`):**
  > `"Remediate OWASP ID <OWASP_ID>"`
- 📋 **Ready-to-Copy Prompt for External Developer Agent (Option B — Zero Search Effort):**
  > `"Complete the implementation of control <OWASP_ID> (<Topic Name>) at exact file <file_path> (lines <X-Y>, function <func_name>): <required_adjustment>."`
- 🔍 **Standalone Re-test Command (Mode 2 — If fixed externally):**
  > `"Verify ID <OWASP_ID>"`

---

## 🟢 3. History of Resolved & Approved Issues (`PASS`)

| Re-test Timestamp | OWASP ID | Topic | Mode Used | Previous Status | New Status | Validated Fix Evidence |
| :---: | :--- | :--- | :---: | :---: | :---: | :--- |
| `<YYYY-MM-DD HH:MM>` | `<Ex.: ISTG-FW-SCRT-003>` | Usage of Hardcoded Secrets | `Mode 3 (Closed-Loop Verified)` | `❌ FAIL` | `✅ PASS` | Secrets removed from `[config.h](file:///path)` and migrated to encrypted NVS. |
