# Technical Verification Rules by Module (Section 6.2)

This reference guide consolidates the technical inspection criteria for each of the **6 Modules of Section 6.2** defined in [SKILL.md](../SKILL.md) (Step 4), aligned with the upstream `embeddedappsec`, `owasp-fstm`, and `owasp-istg` repositories.

---

## Module 1 — Embedded SAST & Memory Quality

### 1.1. Banned C/C++ Functions & Memory Corruption (`EMB-APPSEC-01`, `ISTG-*-INPV-001`)
- **Banned (Status `FAIL` if used with external input or without strict bounds validation):**
  - `gets()` $\rightarrow$ Replace with `fgets(buf, sizeof(buf), stdin)`
  - `strcpy()` $\rightarrow$ Replace with `snprintf()`, `strlcpy()`, or `strncpy()` with explicit null termination `buf[sizeof(buf)-1] = '\0'`
  - `strcat()` $\rightarrow$ Replace with `strlcat()` or `strncat(dest, src, sizeof(dest) - strlen(dest) - 1)`
  - `sprintf()` / `vsprintf()` $\rightarrow$ Replace with `snprintf()` / `vsnprintf()`
  - `scanf("%s", ...)` / `sscanf(..., "%s", ...)` without a maximum field width specifier
- **Partial Usage Pitfall (Status `FAIL` or `PARTIAL`):**
  - `strncpy(dst, src, strlen(src))` or `strncat(dst, src, strlen(src))` — the bound is derived from the source rather than the destination buffer size!
- **Scanning Regular Expression:**
  ```regex
  \b(gets|strcpy|strcat|sprintf|vsprintf|scanf|sscanf|fscanf|strncpy|strncat|memcpy|memmove)\s*\(
  ```

### 1.2. Command & Code Injection Prevention (`EMB-APPSEC-02`, `ISTG-*-INPV-002`)
- **Dangerous Calls Invoking Shells or Interpreters:**
  - **C/C++:** `system()`, `popen()`, `execlp()`, `execvp()`, `execvP()`, `ShellExecute()`
  - **Lua:** `os.execute()`, `io.popen()`
  - **Python:** `os.system()`, `subprocess.*(..., shell=True)`, `eval()`, `exec()`
  - **JS/Node.js:** `child_process.exec()`, `child_process.execSync()`, `eval()`
  - **PHP:** `system()`, `exec()`, `passthru()`, `shell_exec()`
- **Evaluation Criteria:**
  - `FAIL`: Concatenation of input strings (`snprintf`, `+`, f-strings) passed to `system()`/`popen()`/`exec()`, or SQL queries built without *prepared statements*.
  - `PASS`: Exclusive use of native APIs or `fork()` + `execve("/absolute/path", argv, envp)` with a static *allowlist* / *lookup map*.

### 1.3. RAM Memory Hygiene & Stack Overflow (`EMB-APPSEC-01`, `EMB-APPSEC-04`)
- **Criteria:**
  - Zeroization of secrets in RAM using `memset_s()`, `explicit_bzero()`, or `mbedtls_platform_zeroize()` (using standard `memset()` before `free()` = `PARTIAL` due to compiler *dead store elimination*).
  - On Embedded Linux: `setrlimit(RLIMIT_CORE, ...)` set to `0` to disable *core dumps*, and `mlock()` for secret memory pages.
  - On FreeRTOS: `configCHECK_FOR_STACK_OVERFLOW` set to `1` or `2` + `vApplicationStackOverflowHook`.

---

## Module 2 — Secrets, Identity & Cryptography (`SCRT`, `CRYPT`, `AUTHZ`)

### 2.1. Hardcoded Secrets & Version Control (`ISTG-FW-SCRT-001/002/003`, `ISTG-MEM-SCRT-001`)
- **What to look for:**
  - `WIFI_PASS`, `MQTT_PASS`, `API_KEY`, `SECRET`, `PRIVATE_KEY`, `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN PRIVATE KEY-----`, JWT/Bearer tokens hardcoded in `.c`, `.cpp`, `.h`, `.py`, `.js`, `.json`, `.ini`, `sdkconfig`.
  - `.gitignore`: Must block `*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.csr`, `.env`, `secrets.h`.
- **Evaluation Criteria:**
  - `FAIL`: Any real password, private key, or token committed in source files or base firmware images.
  - `PARTIAL`: Secrets moved out of source code, but stored in Flash/NVRAM/LittleFS without partition encryption (`Flash Encryption` / `NVS Encryption`).
  - `PASS`: Stored in a Secure Element (ATECC608, TPM, TrustZone/TEE, PSA ITS) or hardware-encrypted NVS/Flash.

### 2.2. Cryptography at Rest & in Transit (`ISTG-*-CRYPT-001`, `EMB-APPSEC-08`)
- **Weak / Prohibited Algorithms (`FAIL`):**
  - Symmetric/Modes: `DES`, `3DES`, `RC4`, `AES-ECB`.
  - Hashes for integrity/passwords: `MD5`, `SHA-1` (or plain SHA-256 without salt/KDF for passwords).
  - Transport Protocols: `HTTP`, `MQTT` (port 1883 without TLS), `Telnet`, `FTP`, `SSLv2`, `SSLv3`, `TLS 1.0`, `TLS 1.1`.
- **TLS/mTLS Validation in Code:**
  - `FAIL`: `setInsecure()`, `MBEDTLS_SSL_VERIFY_NONE`, `rejectUnauthorized: false`, `verify=False`, `CURLOPT_SSL_VERIFYPEER, 0`.
  - `PARTIAL`: TLS 1.2+ enabled with configured CA, but missing mTLS (for critical M2M communication) or missing certificate expiration checks (lack of NTP/RTC time synchronization).
  - `PASS`: TLS 1.2/1.3 with strict X.509 chain validation (`MBEDTLS_SSL_VERIFY_REQUIRED` / `X509_verify_cert`), CN/SAN verification, AEAD ciphers (AES-GCM / ChaCha20-Poly1305), and mTLS.

### 2.3. Identity Management, Sessions & Privacy (`EMB-APPSEC-05`, `EMB-APPSEC-09`)
- Prohibition of universal default credentials (`admin:admin`, `root:root`, `123456`).
- Brute-force protection (*rate limiting* / *account lockout*).
- Web Sessions: Cookies with `HttpOnly`, `Secure`, `SameSite`, high entropy, no Session ID in URLs, server-side invalidation on logout.
- Privacy: PII/UID minimization (salted hashing for RFID cards/local credentials) and a **Factory Reset** routine that securely wipes user data.

---

## Module 3 — Build, Bootloader & Binary Hardening (`INFO-004`, `CONF-002`)

### 3.1. Compiler Flags & Binary Mitigations (`ISTG-FW-INFO-004`, `ISTG-MEM-INFO-005`)
- **Required flags in `CMakeLists.txt`, `Makefile`, `platformio.ini`:**
  - `-fPIE -pie` (ASLR)
  - `-fstack-protector-strong` or `-fstack-protector-all` (Stack Canaries)
  - `-Wl,-z,noexecstack` (NX)
  - `-Wl,-z,relro,-z,now` (Full RELRO)
  - `-D_FORTIFY_SOURCE=2`
- **In compiled binaries (`.elf` / Linux ELF):** Verify via `readelf` / `checksec`.

### 3.2. Bootloader & Platform Hardening (`ISTG-FW[INST]-CRYPT-001`, `ISTG-PROC-AUTHZ-001`)
- **Das U-Boot:**
  - `CONFIG_ENABLE_VBOOT=y`, `CONFIG_FIT_SIGNATURE=y`, `CONFIG_RSA=y`, `CONFIG_BOOTDELAY=-2`, `CONFIG_SILENT_CONSOLE`, disabling `CONFIG_CMD_USB` and writable environment.
- **ESP-IDF (`sdkconfig`):**
  - `CONFIG_SECURE_BOOT=y` / `CONFIG_SECURE_BOOT_V2_ENABLED=y`
  - `CONFIG_SECURE_FLASH_ENC_ENABLED=y` (`Release` mode)
  - `CONFIG_SECURE_DISABLE_ROM_DL_MODE=y` and JTAG disabled (`CONFIG_SECURE_BOOT_ALLOW_JTAG` absent/disabled).

### 3.3. Attack Surface Reduction & Internal Interfaces (`ISTG-FW-CONF-002`, `ISTG-INT[UART]`, `ISTG-INT[I2C]`)
- **Removal of Unnecessary Binaries & Services (AGL Table):**
  - Absence of `telnetd`, `ftpd`, `tftp`, `rshd`, `gdbserver`, `strace`, `tcpdump`, multiple shells, and debug code/routes (`CWE-489`).
- **UART Security (`ISTG-INT[UART]-INFO-002`, `AUTHZ-001/002`):**
  - `Serial.print*`, `printf`, `ESP_LOG*` **must not** output keys, passwords, JWT tokens, hashes, raw UIDs, or internal memory addresses in production builds.
  - Serial console must not drop into an unauthenticated shell automatically or allow boot interruption.

---

## Module 4 — Firmware Update Lifecycle (`ISTG-FW[UPDT]`)

| ISTG ID | ISVS Req. | Criteria for `PASS` (Compliant) | Criteria for `PARTIAL` | Criteria for `FAIL` |
| :--- | :--- | :--- | :--- | :--- |
| `ISTG-FW[UPDT]-AUTHZ-001` | V3.4.10 | Trigger/upload requires strong authentication and administrative privilege verification. | Simple authentication without privilege checks or static token. | Any network client can initiate/upload OTA without authentication. |
| `ISTG-FW[UPDT]-CRYPT-001` | V2.4.2 / V3.4.13 | Firmware package signed with strong asymmetric key (RSA-2048/3072 or ECDSA P-256+). | Uses only a hash (SHA-256/MD5) or HMAC with a shared symmetric key on the device. | Update package lacks a cryptographic signature. |
| `ISTG-FW[UPDT]-CRYPT-002` | — | Update image distributed encrypted (e.g., Flash Encryption / encrypted image). | Image obfuscated or encrypted with a weak/hardcoded key. | `.bin` image distributed in cleartext (easy code/string extraction). |
| `ISTG-FW[UPDT]-CRYPT-003` | V3.4.12 | OTA download over HTTPS/MQTTS (TLS 1.2/1.3) with strict X.509 certificate validation. | Uses HTTPS but bypasses certificate validation (`setInsecure`). | Download over HTTP, TFTP, or unencrypted MQTT. |
| `ISTG-FW[UPDT]-CRYPT-004` | V3.4.3 | Device verifies the digital signature of the image in the OTA partition before activating it. | Verifies only checksum/CRC or binary size. | Applies firmware directly without signature validation. |
| `ISTG-FW[UPDT]-LOGIC-001` | V3.4.6 | Anti-Rollback protection active (rejects version lower than current + A/B partition boot confirmation). | Compares version only via software string (bypassable) or lacks automatic failure rollback. | Accepts downgrade to any previous version. |

---

## Module 5 — Data Exchange Services & Business Logic (`ISTG-DES`)

- **`ISTG-DES-AUTHZ-001` & `002`:**
  - MQTT brokers and REST APIs must enforce per-device/per-user authentication (prohibit `allow_anonymous true`).
  - MQTT topic ACLs must restrict publish/subscribe permissions to the exact device scope (bound to the X.509 certificate CN or authenticated ClientID), preventing lateral movement across rooms/devices.
- **`ISTG-DES-INFO-001/002/003` & `CONF-002`:**
  - Disable verbose headers (`X-Powered-By`, broker/server version banners), unnecessary HTTP methods, and wildcard debug topics (`#`).
- **`ISTG-DES-LOGIC-001` (Resilience & Business Logic):**
  - Protection against **Replay Attacks** (`timestamp` validation within an acceptable window + `nonce`/sequence number).
  - Protection against **Flooding / DoS** (*cooldown* / *rate-limiting* at the edge and on the backend/broker).
  - Use of **Last Will and Testament (LWT)** in MQTT for reliable disconnect detection and state reconciliation.

---

## Module 6 — SBOM & Third-Party Dependencies (`CONF-001`)

- **Criteria (`ISTG-*-CONF-001`, `EMB-APPSEC-10`, `ISVS V1.1.1`):**
  - `PASS`: Dependency manifest with exact *pinned* versions, generated SBOM (CycloneDX / SPDX) containing the 7 CISA 2025 minimum elements (*Supplier, Component Name, Version, Unique ID/CPE/PURL, Dependency Relationship, Author, Timestamp*), and no known critical CVEs.
  - `PARTIAL`: Dependencies declared in configuration files (`package.json`, `platformio.ini`, `CMakeLists.txt`), but using loose version ranges (`^`, `*`, `latest`) or lacking a formal SBOM file.
  - `FAIL`: Libraries manually copied without version traceability, or usage of components with unmitigated critical CVEs.
