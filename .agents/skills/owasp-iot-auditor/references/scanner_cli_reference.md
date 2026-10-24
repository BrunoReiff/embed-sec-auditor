# CLI Quick Reference — `owasp_iot_scanner.py` (Zero Code-Reading Guide)

> [!IMPORTANT]
> **Agent Fast-Path Rule:** NEVER read `.py` files inside `scripts/` or `scripts/modules/` to learn how to call the scanner. Use the exact flags below directly.

Base command path:
```bash
python3 .agents/skills/owasp-iot-auditor/scripts/owasp_iot_scanner.py [FLAGS]
```

---

## 1. Mode 1.1 — Standard Fast Native Audit (Default)
Initializes the 3 HTML files (`report`, `remediation`, `checklist`) and runs the single-pass native discovery + Section 6.1 classification + native regex triage:
```bash
python3 .agents/skills/owasp-iot-auditor/scripts/owasp_iot_scanner.py --target . --init-all
```

---

## 2. Mode 1.2 — Deep Hybrid Audit (`Full-Power SAST + OWASP`)

### Step 0: Check Installed External SAST Tools (Mandatory Pre-Flight)
Checks if *Cppcheck*, *Gitleaks*, *Semgrep*, *Flawfinder*, *Checksec*, *Trivy*, and *Binwalk* are installed on the host machine:
```bash
python3 .agents/skills/owasp-iot-auditor/scripts/owasp_iot_scanner.py --check-tools
```

### Step 0b: Install Missing Tools (When User Selects Option A)
If `--check-tools` reports missing tools, ask the user if they want to install them. When confirmed (**Option A**), run:
```bash
# Install all missing SAST tools automatically:
python3 .agents/skills/owasp-iot-auditor/scripts/owasp_iot_scanner.py --install-tools all

# Or install specific tools only:
python3 .agents/skills/owasp-iot-auditor/scripts/owasp_iot_scanner.py --install-tools flawfinder,semgrep,gitleaks,binwalk
```

### Step 1: Run Full-Power Deep Hybrid Scan
Executes 100% of the native OWASP scanner (including FirmAgent Source-to-Sink Taint Chains and IoTwizz Hardware Lockdown) **PLUS** external SAST tools and the IoTwizz Firmware Binary Inspector (.bin/.img entropy, magic signatures, cleartext secrets):
```bash
python3 .agents/skills/owasp-iot-auditor/scripts/owasp_iot_scanner.py --target . --init-all --deep-scan
```
*(Alias: `--full-power`)*

---

## 3. Safe HTML Anchor Injection (Preserves Immutable Anchors)
Injects `<tr>` rows or `<article>` cards without ever deleting the `<!-- ANCHOR: ... -->` comment:
```bash
python3 .agents/skills/owasp-iot-auditor/scripts/owasp_iot_scanner.py \
  --target . \
  --inject-target report \
  --inject-anchor INSERT_FAIL_ROWS_HERE \
  --inject-content-file path/to/snippet.html
```
- `--inject-target`: `report` | `remediation` | `checklist`
- `--inject-anchor`: `INSERT_FAIL_ROWS_HERE` | `INSERT_PARTIAL_ROWS_HERE` | `INSERT_PASS_ROWS_HERE` | `INSERT_NA_ROWS_HERE` | `INSERT_DISCOVERY_DETAILS_HERE` | `INSERT_FAIL_CARDS_HERE` | `INSERT_PARTIAL_CARDS_HERE` | `AUDIT_STATE_LIST`

---

## 4. Mode 2 — Targeted Single-ID Locator
Quickly locates all lines referencing a specific `<OWASP_ID>` across the 3 HTML files:
```bash
python3 .agents/skills/owasp-iot-auditor/scripts/owasp_iot_scanner.py --target . --verify-id <OWASP_ID>
```

