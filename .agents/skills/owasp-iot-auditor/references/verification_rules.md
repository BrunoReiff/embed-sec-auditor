# Regras Técnicas de Verificação por Módulo (Seção 6.2)

Este guia de referência consolida os critérios técnicos de inspeção para cada um dos **6 Módulos da Seção 6.2** definidos em [SKILL.md](../SKILL.md) (Etapa 4), alinhados aos repositórios `embeddedappsec`, `owasp-fstm` e `owasp-istg`.

---

## Módulo 1 — SAST Embarcado & Qualidade de Memória

### 1.1. Funções C/C++ Banidas e Corrupção de Memória (`EMB-APPSEC-01`, `ISTG-*-INPV-001`)
- **Banidas (Status `FAIL` se usadas com entrada externa ou sem validação estrita de tamanho):**
  - `gets()` $\rightarrow$ Substituir por `fgets(buf, sizeof(buf), stdin)`
  - `strcpy()` $\rightarrow$ Substituir por `snprintf()`, `strlcpy()` ou `strncpy()` com terminação explícita `buf[sizeof(buf)-1] = '\0'`
  - `strcat()` $\rightarrow$ Substituir por `strlcat()` ou `strncat(dest, src, sizeof(dest) - strlen(dest) - 1)`
  - `sprintf()` / `vsprintf()` $\rightarrow$ Substituir por `snprintf()` / `vsnprintf()`
  - `scanf("%s", ...)` / `sscanf(..., "%s", ...)` sem especificador de largura máxima
- **Armadilha de Uso Parcial (Status `FAIL` ou `PARTIAL`):**
  - `strncpy(dst, src, strlen(src))` ou `strncat(dst, src, strlen(src))` — o limite é dado pela origem e não pelo destino!
- **Expressão Regular de Varredura:**
  ```regex
  \b(gets|strcpy|strcat|sprintf|vsprintf|scanf|sscanf|fscanf|strncpy|strncat|memcpy|memmove)\s*\(
  ```

### 1.2. Prevenção de Injeção de Comandos e Código (`EMB-APPSEC-02`, `ISTG-*-INPV-002`)
- **Chamadas Perigosas que Invocam Shell ou Interpretadores:**
  - **C/C++:** `system()`, `popen()`, `execlp()`, `execvp()`, `execvP()`, `ShellExecute()`
  - **Lua:** `os.execute()`, `io.popen()`
  - **Python:** `os.system()`, `subprocess.*(..., shell=True)`, `eval()`, `exec()`
  - **JS/Node.js:** `child_process.exec()`, `child_process.execSync()`, `eval()`
  - **PHP:** `system()`, `exec()`, `passthru()`, `shell_exec()`
- **Critério de Avaliação:**
  - `FAIL`: Concatenação de strings de entrada (`snprintf`, `+`, f-strings) passada a `system()`/`popen()`/`exec()` ou queries SQL sem *prepared statements*.
  - `PASS`: Uso exclusivo de APIs nativas ou `fork()` + `execve("/caminho/absoluto", argv, envp)` com *allowlist* / *lookup map* estático.

### 1.3. Higiene de Memória RAM e Stack Overflow (`EMB-APPSEC-01`, `EMB-APPSEC-04`)
- **Critérios:**
  - Limpeza de segredos em RAM com `memset_s()`, `explicit_bzero()` ou `mbedtls_platform_zeroize()` (uso de `memset()` comum antes de `free()` = `PARTIAL` devido a *dead store elimination* pelo compilador).
  - Em Linux embarcado: `setrlimit(RLIMIT_CORE, ...)` com `0` para desativar *core dumps* e `mlock()` para páginas de segredos.
  - Em FreeRTOS: `configCHECK_FOR_STACK_OVERFLOW` definido como `1` ou `2` + `vApplicationStackOverflowHook`.

---

## Módulo 2 — Segredos, Identidade e Criptografia (`SCRT`, `CRYPT`, `AUTHZ`)

### 2.1. Segredos Hardcoded e Controle de Versão (`ISTG-FW-SCRT-001/002/003`, `ISTG-MEM-SCRT-001`)
- **O que procurar:**
  - `WIFI_PASS`, `MQTT_PASS`, `API_KEY`, `SECRET`, `PRIVATE_KEY`, `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN PRIVATE KEY-----`, tokens JWT/Bearer chumbados em `.c`, `.cpp`, `.h`, `.py`, `.js`, `.json`, `.ini`, `sdkconfig`.
  - `.gitignore`: Deve bloquear `*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.csr`, `.env`, `secrets.h`.
- **Critério de Avaliação:**
  - `FAIL`: Qualquer senha, chave privada ou token real em arquivos de código ou imagem base.
  - `PARTIAL`: Segredos fora do código, mas armazenados em Flash/NVRAM/LittleFS sem criptografia de partição (`Flash Encryption` / `NVS Encryption`).
  - `PASS`: Armazenamento em Secure Element (ATECC608, TPM, TrustZone/TEE, PSA ITS) ou NVS/Flash criptografada por hardware.

### 2.2. Criptografia em Repouso e em Trânsito (`ISTG-*-CRYPT-001`, `EMB-APPSEC-08`)
- **Algoritmos Fracos / Proibidos (`FAIL`):**
  - Simétricos/Modos: `DES`, `3DES`, `RC4`, `AES-ECB`.
  - Hashes para integridade/senhas: `MD5`, `SHA-1` (ou SHA-256 simples sem salt/KDF para senhas).
  - Protocolos de Transporte: `HTTP`, `MQTT` (porta 1883 sem TLS), `Telnet`, `FTP`, `SSLv2`, `SSLv3`, `TLS 1.0`, `TLS 1.1`.
- **Validação TLS/mTLS no Código:**
  - `FAIL`: `setInsecure()`, `MBEDTLS_SSL_VERIFY_NONE`, `rejectUnauthorized: false`, `verify=False`, `CURLOPT_SSL_VERIFYPEER, 0`.
  - `PARTIAL`: TLS 1.2+ ativado com CA configurada, mas sem mTLS (em comunicação M2M crítica) ou sem verificação de expiração temporal (ausência de sincronização NTP/RTC).
  - `PASS`: TLS 1.2/1.3 com validação estrita de cadeia X.509 (`MBEDTLS_SSL_VERIFY_REQUIRED` / `X509_verify_cert`), verificação de CN/SAN, cifras AEAD (AES-GCM / ChaCha20-Poly1305) e mTLS.

### 2.3. Gestão de Identidade, Sessões e Privacidade (`EMB-APPSEC-05`, `EMB-APPSEC-09`)
- Proibição de credenciais padrão universais (`admin:admin`, `root:root`, `123456`).
- Bloqueio de força bruta (*rate limiting* / *account lockout*).
- Sessões Web: Cookies com `HttpOnly`, `Secure`, `SameSite`, alta entropia, sem Session ID na URL, invalidação no logout.
- Privacidade: Minimização de PII/UIDs (hashing com salt para cartões RFID/credenciais locais) e rotina de **Factory Reset** que apaga dados de forma segura.

---

## Módulo 3 — Hardening de Build, Bootloader e Binários (`INFO-004`, `CONF-002`)

### 3.1. Flags de Compilação e Mitigações de Binários (`ISTG-FW-INFO-004`, `ISTG-MEM-INFO-005`)
- **Flags exigidas em `CMakeLists.txt`, `Makefile`, `platformio.ini`:**
  - `-fPIE -pie` (ASLR)
  - `-fstack-protector-strong` ou `-fstack-protector-all` (Stack Canaries)
  - `-Wl,-z,noexecstack` (NX)
  - `-Wl,-z,relro,-z,now` (Full RELRO)
  - `-D_FORTIFY_SOURCE=2`
- **Em binários compilados (`.elf` / Linux ELF):** Verificar via `readelf` / `checksec`.

### 3.2. Hardening de Bootloader e Plataforma (`ISTG-FW[INST]-CRYPT-001`, `ISTG-PROC-AUTHZ-001`)
- **Das U-Boot:**
  - `CONFIG_ENABLE_VBOOT=y`, `CONFIG_FIT_SIGNATURE=y`, `CONFIG_RSA=y`, `CONFIG_BOOTDELAY=-2`, `CONFIG_SILENT_CONSOLE`, desativação de `CONFIG_CMD_USB` e ambiente gravável.
- **ESP-IDF (`sdkconfig`):**
  - `CONFIG_SECURE_BOOT=y` / `CONFIG_SECURE_BOOT_V2_ENABLED=y`
  - `CONFIG_SECURE_FLASH_ENC_ENABLED=y` (modo `Release`)
  - `CONFIG_SECURE_DISABLE_ROM_DL_MODE=y` e desativação de JTAG (`CONFIG_SECURE_BOOT_ALLOW_JTAG` ausente/desativado).

### 3.3. Redução de Superfície e Interfaces Internas (`ISTG-FW-CONF-002`, `ISTG-INT[UART]`, `ISTG-INT[I2C]`)
- **Remoção de Binários e Serviços Desnecessários (Tabela AGL):**
  - Ausência de `telnetd`, `ftpd`, `tftp`, `rshd`, `gdbserver`, `strace`, `tcpdump`, múltiplos shells, e código/rotas de debug (`CWE-489`).
- **Segurança da UART (`ISTG-INT[UART]-INFO-002`, `AUTHZ-001/002`):**
  - `Serial.print*`, `printf`, `ESP_LOG*` **não** podem imprimir chaves, senhas, tokens JWT, hashes, UIDs brutos ou endereços de memória internos em builds de produção.
  - Console serial não deve fornecer shell autenticado automaticamente nem permitir interrupção do boot.

---

## Módulo 4 — Ciclo de Vida de Atualização de Firmware (`ISTG-FW[UPDT]`)

| ID ISTG | Requisito ISVS | Critério para `PASS` (De Acordo) | Critério para `PARTIAL` | Critério para `FAIL` |
| :--- | :--- | :--- | :--- | :--- |
| `ISTG-FW[UPDT]-AUTHZ-001` | V3.4.10 | Disparo/upload exige autenticação forte e verificação de permissão administrativa. | Autenticação simples sem controle de privilégio ou token estático. | Qualquer cliente na rede pode iniciar/enviar OTA sem autenticação. |
| `ISTG-FW[UPDT]-CRYPT-001` | V2.4.2 / V3.4.13 | Pacote de firmware assinado com chave assimétrica forte (RSA-2048/3072 ou ECDSA P-256+). | Usa apenas hash (SHA-256/MD5) ou HMAC com chave simétrica compartilhada no dispositivo. | Pacote de atualização sem assinatura criptográfica. |
| `ISTG-FW[UPDT]-CRYPT-002` | — | Imagem de atualização distribuída criptografada (ex.: Flash Encryption / imagem cifrada). | Imagem ofuscada ou cifrada com chave fraca/hardcoded. | Imagem `.bin` distribuída em texto claro (fácil extração de código/strings). |
| `ISTG-FW[UPDT]-CRYPT-003` | V3.4.12 | Download do OTA via HTTPS/MQTTS (TLS 1.2/1.3) com validação estrita do certificado X.509. | Usa HTTPS mas ignora validação do certificado (`setInsecure`). | Download via HTTP, TFTP ou MQTT sem TLS. |
| `ISTG-FW[UPDT]-CRYPT-004` | V3.4.3 | Dispositivo verifica a assinatura digital da imagem na partição OTA antes de ativá-la. | Verifica apenas checksum/CRC ou tamanho do binário. | Aplica o firmware diretamente sem validar assinatura. |
| `ISTG-FW[UPDT]-LOGIC-001` | V3.4.6 | Proteção Anti-Rollback ativa (rejeita versão inferior à atual + confirmação de boot da partição A/B). | Compara versão apenas via string em software (contornável) ou sem auto-rollback de falha. | Aceita downgrade para qualquer versão anterior. |

---

## Módulo 5 — Serviços de Troca de Dados e Lógica de Negócio (`ISTG-DES`)

- **`ISTG-DES-AUTHZ-001` & `002`:**
  - Brokers MQTT e APIs REST devem exigir autenticação individual por dispositivo/usuário (proibir `allow_anonymous true`).
  - ACLs de tópicos MQTT devem restringir publicação/assinatura ao escopo exato do dispositivo (amarrado ao CN do certificado X.509 ou ClientID autenticado), impedindo movimentação lateral entre salas/dispositivos.
- **`ISTG-DES-INFO-001/002/003` & `CONF-002`:**
  - Desabilitar cabeçalhos verbosos (`X-Powered-By`, banners de versão do broker/servidor), métodos HTTP desnecessários e tópicos wildcard de debug (`#`).
- **`ISTG-DES-LOGIC-001` (Resiliência e Lógica de Negócio):**
  - Proteção contra **Replay Attacks** (validação de `timestamp` dentro de janela aceitável + `nonce`/sequência).
  - Proteção contra **Flooding / DoS** (*cooldown* / *rate-limiting* na borda e no backend/broker).
  - Uso de **Last Will and Testament (LWT)** no MQTT para detecção confiável de desconexão e reconciliação de estado.

---

## Módulo 6 — SBOM e Dependências de Terceiros (`CONF-001`)

- **Critérios (`ISTG-*-CONF-001`, `EMB-APPSEC-10`, `ISVS V1.1.1`):**
  - `PASS`: Existência de manifesto de dependências com versões exatas fixadas (*pinned*), SBOM gerado (CycloneDX / SPDX) contendo os 7 elementos mínimos da CISA 2025 (*Supplier, Component Name, Version, Unique ID/CPE/PURL, Dependency Relationship, Author, Timestamp*) e ausência de CVEs críticas conhecidas.
  - `PARTIAL`: Dependências declaradas em arquivos de configuração (`package.json`, `platformio.ini`, `CMakeLists.txt`), mas usando faixas abertas (`^`, `*`, `latest`) ou sem arquivo SBOM formalizado.
  - `FAIL`: Bibliotecas copiadas manualmente sem rastreabilidade de versão ou uso de componentes com CVEs críticas conhecidas sem mitigação.

