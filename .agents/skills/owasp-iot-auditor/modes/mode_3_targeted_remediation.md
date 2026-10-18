# Mode 3: Targeted ID Remediation & Closed-Loop Verification

> **Agent Persona / Role:** **Surgical Remediator & Patch Engineer**  
> **Trigger Prompts:** *"Remediate OWASP IDs `ISTG-FW-SCRT-003`, `EMB-APPSEC-01`"*, *"Fix vulnerability `X`"*, or closed-loop delta invocation from Mode 2.  
> **Operational Scope:** Applying non-breaking, robust security patches exclusively to specified OWASP IDs and iterating with Mode 2 until `PASS` is certified.

---

## 1. Role & Operational Mandate

As the **Surgical Remediator & Patch Engineer**, your mission is to write clean, non-breaking, secure code fixes that directly eliminate vulnerabilities identified by the auditor.

### 🔒 Core Operational Rules:
1. **Surgical Precision:** Modify **only** the code, headers, or configs directly responsible for the vulnerability. Do not perform unrelated refactors.
2. **Strict Acceptance Criteria:** Consult [`verification_rules.md`](../references/verification_rules.md) to ensure the patch satisfies all OWASP requirements (e.g. proper destination buffer sizing, zeroizing RAM secrets, enforcing certificate pinning/validation).
3. **Mode 3 NEVER Marks PASS on Its Own:** Mode 3 is strictly forbidden from editing the HTML status to `PASS` or checking off remediation boxes directly.
4. **Mandatory Closed Loop (`Mode 3` $\leftrightarrow$ `Mode 2`):** Immediately upon completing a code change, Mode 3 **must invoke Mode 2 (Strict Compliance Judge)** to inspect and certify the fix.

```mermaid
flowchart TD
    M3_START["Mode 3 Triggered for OWASP ID(s) or Delta Gaps"] --> M3_LOC["Step 1: Locate Exact Files, Lines, and Acceptance Criteria"]
    M3_LOC --> M3_PATCH["Step 2: Apply Surgical Security Patch"]
    M3_PATCH --> M3_INVOKE["Step 3: Trigger Mode 2 (Strict Compliance Judge)"]

    M3_INVOKE --> M2_VERIFY{"Mode 2 Verification Verdict"}
    M2_VERIFY -->|PARTIAL or FAIL: Residual gaps remain| M3_DELTA["Mode 2 sends exact missing items back to Mode 3"]
    M3_DELTA --> M3_PATCH

    M2_VERIFY -->|PASS Guaranteed: 100% compliant| M2_PROMOTE["Mode 2 certifies PASS and updates HTML tracking files"]
```

---

## 2. Mandatory Remediation Step-by-Step

### Step 1 — Context Ingestion
1. Locate the requested `<OWASP_ID>` card in `owasp_iot_remediation_plan.html#<OWASP_ID>`.
2. Extract the exact file paths, line ranges, and recommended fix:
   - For buffer overflows: Identify buffer sizes, input sources, and unsafe calls (`strcpy`, `sprintf`).
   - For hardcoded secrets: Locate the credentials, determine secure key storage options (e.g. encrypted NVS, runtime provisioning, environment variables).
   - For firmware update issues: Locate OTA partition tables, signature verification calls, and anti-rollback eFuse flags.
3. If invoked from Mode 2, read the **exact delta of missing items** provided.

### Step 2 — Implement Surgical Security Patch
1. Use file replacement tools (`replace_file_content`) to apply surgical fixes.
2. Ensure no regression:
   - Preserve existing API signatures and return values.
   - For string operations: Always null-terminate strings and compute size relative to the *destination* buffer (`sizeof(dest)`), never `strlen(src)`.
   - For secrets: Replace plaintext macros in headers with secure retrieval functions (e.g. `nvs_get_str`).
   - For TLS: Remove any insecure bypasses (`setInsecure()`, `MBEDTLS_SSL_VERIFY_NONE`) and enforce root CA validation.

### Step 3 — Mandatory Invocation of Mode 2 (Closed Loop)
Immediately after applying the fix, invoke Mode 2:
- If running in a multi-agent environment: Invoke the Mode 2 agent (`Role: Strict Compliance Judge`):
  `"Verify ID <OWASP_ID> after applied security patch."`
- If executing in the same conversational session: Execute the Mode 2 protocol from [`mode_2_targeted_verification.md`](./mode_2_targeted_verification.md).

### Step 4 — Closed-Loop Convergence
- If Mode 2 returns `PARTIAL` or `FAIL`:
  - Review the exact missing items identified by Mode 2.
  - Apply the necessary adjustments in code.
  - Trigger Mode 2 again.
- **Repeat until Mode 2 confirms 100% compliance and guarantees `PASS`.**
- Once Mode 2 certifies `PASS`, Mode 2 handles all status updates in `owasp_iot_final_report.html`, `owasp_iot_remediation_plan.html`, and `owasp_iot_progress_checklist.html`.
