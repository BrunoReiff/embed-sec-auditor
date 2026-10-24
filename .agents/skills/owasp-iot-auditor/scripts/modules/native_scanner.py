# -*- coding: utf-8 -*-
"""
Native Scanner Module — OWASP IoT & Embedded Security Auditor
Executes:
1. High-Performance Single-Pass Recursive Tree Search via os.scandir (Step 1 Discovery)
2. Functionality Classification per Section 6.1 (Step 2)
3. Native Regex Static Triage across Modules 1 to 6 (Step 4 Baseline)
"""

import os
import re
from pathlib import Path

IGNORE_DIRS = {
    ".git",
    "node_modules",
    ".pio",
    ".vscode",
    ".idea",
    "__pycache__",
    "dist",
    "build",
    "IOT_OWASP",
    ".agents",
    ".agent",
}

SOURCE_EXTS = {
    ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".ino", ".s", ".S",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".lua", ".sh", ".php", ".html",
    ".json", ".yaml", ".yml", ".ini", ".conf", ".cfg", ".cmake", ".mk"
}

MAX_FILE_SIZE_BYTES = 500 * 1024  # 500 KB limit to avoid blocking I/O on large dumps


def scan_project_tree(target_dir: Path):
    """
    Single-Pass Tree Search Algorithm using os.scandir:
    - Prunes ignored directories at branch level immediately.
    - Executes technology inventory AND native regex triage concurrently in ONE traversal.
    """
    inventory = {
        "files_by_ext": {},
        "total_files_scanned": 0,
        "embedded_code_files": [],
        "build_and_firmware_files": [],
        "backend_service_files": [],
        "ui_frontend_files": [],
        "detected_technologies": {
            "rtos_os_sdk": set(),
            "build_systems": set(),
            "crypto_libs": set(),
            "protocols_services": set(),
            "hardware_interfaces": set(),
            "storage_filesystems": set(),
        },
        "has_gitignore": False,
        "gitignore_content": "",
    }

    findings = {
        "Module_1_SAST_and_Memory": [],
        "Module_2_Secrets_Identity_Cryptography": [],
        "Module_3_Hardening_Build_Bootloader_Binaries": [],
        "Module_4_Firmware_Update_OTA": [],
        "Module_5_Data_Exchange_Services_Logic": [],
        "Module_6_SBOM_and_Dependencies": [],
    }

    rules = [
        # Module 1
        ("Module_1_SAST_and_Memory", "ISTG-*-INPV-001 / EMB-APPSEC-01", "Unsafe C/C++ buffer manipulation function", re.compile(r"\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\("), {".c", ".cpp", ".cc", ".h", ".hpp", ".ino"}),
        ("Module_1_SAST_and_Memory", "EMB-APPSEC-01", "Potential misuse of strncpy/strncat bounded by strlen", re.compile(r"\b(strncpy|strncat)\s*\([^;]*strlen\s*\("), {".c", ".cpp", ".cc", ".h", ".hpp", ".ino"}),
        ("Module_1_SAST_and_Memory", "ISTG-*-INPV-002 / EMB-APPSEC-02", "External command/process execution (Command Injection risk)", re.compile(r"\b(system|popen|execlp|execvp|os\.system|child_process\.exec|eval)\s*\("), {".c", ".cpp", ".py", ".js", ".ts", ".lua", ".php"}),
        # Module 2
        ("Module_2_Secrets_Identity_Cryptography", "ISTG-FW-SCRT-003 / EMB-APPSEC-04", "Potential hardcoded secret/credential", re.compile(r"(?:WIFI_PASS|MQTT_PASS|PASSWORD|SECRET|API_KEY|PRIVATE_KEY)\s*[:=]\s*[\"'][^\"']{3,}[\"']|-----BEGIN (?:RSA )?PRIVATE KEY-----", re.I), SOURCE_EXTS),
        ("Module_2_Secrets_Identity_Cryptography", "ISTG-*-CRYPT-001 / EMB-APPSEC-08", "TLS certificate validation disabled", re.compile(r"\b(setInsecure\s*\(\)|MBEDTLS_SSL_VERIFY_NONE|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*0)\b"), SOURCE_EXTS),
        ("Module_2_Secrets_Identity_Cryptography", "ISTG-*-CRYPT-001", "Weak cryptographic algorithm or hash usage (MD5/SHA1/DES/RC4/ECB)", re.compile(r"\b(MD5|SHA1|DES|3DES|RC4|AES_ECB|ECB_MODE)\b"), SOURCE_EXTS),
        # Module 3
        ("Module_3_Hardening_Build_Bootloader_Binaries", "ISTG-INT[UART]-INFO-002", "Serial log detected (verify if it leaks secrets/UIDs/tokens over UART)", re.compile(r"\b(Serial\.print|Serial\.println|Serial\.printf|ESP_LOG[IWDVE])\s*\([^)]*(?:pass|key|token|secret|uid|hash|pin)", re.I), {".c", ".cpp", ".h", ".hpp", ".ino"}),
        ("Module_3_Hardening_Build_Bootloader_Binaries", "ISTG-FW-INFO-004 / EMB-APPSEC-06", "Compiler hardening or Secure Boot/Flash Encryption flag present", re.compile(r"(-fstack-protector|-fPIE|-D_FORTIFY_SOURCE|CONFIG_SECURE_BOOT|CONFIG_SECURE_FLASH_ENC|CONFIG_ENABLE_VBOOT|CONFIG_FIT_SIGNATURE)"), {".txt", ".ini", ".mk", ".cmake", ""}),
        # Module 4
        ("Module_4_Firmware_Update_OTA", "ISTG-FW[UPDT]-*", "Firmware update (OTA) routine or configuration detected", re.compile(r"\b(esp_https_ota|esp_ota_begin|ArduinoOTA|HTTPUpdate|Update\.begin|CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK)\b"), SOURCE_EXTS),
        # Module 5
        ("Module_5_Data_Exchange_Services_Logic", "ISTG-DES-AUTHZ-001", "Anonymous broker access or wildcard MQTT topic subscription", re.compile(r"\b(allow_anonymous\s+true)\b|subscribe\s*\(\s*[\"']#[\"']"), SOURCE_EXTS),
    ]

    def _traverse(current_dir: Path):
        try:
            with os.scandir(current_dir) as entries:
                for entry in entries:
                    name = entry.name
                    if entry.is_dir(follow_symlinks=False):
                        if name in IGNORE_DIRS or name.startswith("."):
                            continue
                        _traverse(Path(entry.path))
                        continue

                    if name.startswith("owasp_iot_") or name == "metodologia_owasp_iot_agente.md":
                        continue

                    rel_path = str(Path(entry.path).relative_to(target_dir))
                    ext = Path(entry.path).suffix.lower()
                    lower_name = name.lower()

                    inventory["total_files_scanned"] += 1
                    inventory["files_by_ext"][ext] = inventory["files_by_ext"].get(ext, 0) + 1

                    if name == ".gitignore":
                        inventory["has_gitignore"] = True
                        try:
                            inventory["gitignore_content"] = Path(entry.path).read_text(encoding="utf-8", errors="ignore")
                        except Exception:
                            pass

                    if (
                        lower_name in {"cmakelists.txt", "makefile", "platformio.ini", "sdkconfig", "sdkconfig.defaults", "kconfig", "dockerfile", "docker-compose.yml", "idf_component.yml"}
                        or ext in {".bin", ".elf", ".hex", ".uf2", ".img", ".squashfs", ".jffs2", ".ubifs", ".ld"}
                        or lower_name.endswith((".bb", ".bbappend"))
                    ):
                        inventory["build_and_firmware_files"].append(rel_path)
                        if "platformio.ini" in lower_name:
                            inventory["detected_technologies"]["build_systems"].add("PlatformIO")
                        if "sdkconfig" in lower_name or "idf_component" in lower_name:
                            inventory["detected_technologies"]["rtos_os_sdk"].add("ESP-IDF")
                        if "cmakelists.txt" in lower_name:
                            inventory["detected_technologies"]["build_systems"].add("CMake")
                        if "makefile" in lower_name:
                            inventory["detected_technologies"]["build_systems"].add("Make")
                        if "dockerfile" in lower_name or "docker-compose" in lower_name:
                            inventory["detected_technologies"]["build_systems"].add("Docker")
                        if lower_name.endswith((".bb", ".bbappend")):
                            inventory["detected_technologies"]["rtos_os_sdk"].add("Yocto / OpenEmbedded")

                    if ext in {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".ino", ".s", ".S"}:
                        inventory["embedded_code_files"].append(rel_path)
                        if ext == ".ino":
                            inventory["detected_technologies"]["rtos_os_sdk"].add("Arduino")

                    if lower_name in {"package.json", "requirements.txt", "pyproject.toml", "mosquitto.conf"} or ext in {".py", ".js", ".ts", ".go", ".rs"}:
                        if not any(p in rel_path.lower() for p in ["frontend", "public", "www", "htdocs", "ui", "web"]):
                            inventory["backend_service_files"].append(rel_path)

                    if ext in {".html", ".htm", ".css", ".vue", ".jsx", ".tsx"} or any(p in rel_path.lower() for p in ["frontend", "www", "htdocs", "webui", "dashboard"]):
                        inventory["ui_frontend_files"].append(rel_path)

                    if lower_name in {"package.json", "requirements.txt", "platformio.ini", "idf_component.yml"}:
                        findings["Module_6_SBOM_and_Dependencies"].append({
                            "id": "ISTG-*-CONF-001 / EMB-APPSEC-10",
                            "file": rel_path,
                            "line": 1,
                            "source_tool": "native",
                            "description": f"Dependency manifest detected ({name}) for SBOM generation and CVE audit.",
                        })

                    if ext not in SOURCE_EXTS and lower_name not in {"sdkconfig", "cmakelists.txt", "makefile", "platformio.ini"}:
                        continue

                    try:
                        st = entry.stat()
                        if st.st_size > MAX_FILE_SIZE_BYTES or st.st_size == 0:
                            continue
                    except Exception:
                        continue

                    try:
                        content = Path(entry.path).read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue

                    if re.search(r"\b(freertos|xTaskCreate|vTaskDelay|configCHECK_FOR_STACK_OVERFLOW)\b", content, re.I):
                        inventory["detected_technologies"]["rtos_os_sdk"].add("FreeRTOS")
                    if re.search(r"\b(esp_system\.h|esp_wifi\.h|esp_log\.h|nvs_flash\.h|esp_ota_ops\.h)\b", content, re.I):
                        inventory["detected_technologies"]["rtos_os_sdk"].add("ESP-IDF")
                    if re.search(r"\b(Arduino\.h|Serial\.begin|digitalWrite|WiFi\.begin)\b", content):
                        inventory["detected_technologies"]["rtos_os_sdk"].add("Arduino Framework")
                    if re.search(r"\b(zephyr/kernel\.h|CONFIG_ZEPHYR)\b", content, re.I):
                        inventory["detected_technologies"]["rtos_os_sdk"].add("Zephyr RTOS")
                    if re.search(r"\b(CONFIG_ENABLE_VBOOT|CONFIG_FIT_SIGNATURE|CONFIG_BOOTDELAY|u-boot)\b", content, re.I):
                        inventory["detected_technologies"]["rtos_os_sdk"].add("Das U-Boot")

                    if re.search(r"\b(mbedtls_|mbedtls/)\b", content, re.I):
                        inventory["detected_technologies"]["crypto_libs"].add("mbedTLS")
                    if re.search(r"\b(openssl/|SSL_CTX_|EVP_PKEY|X509_verify_cert)\b", content):
                        inventory["detected_technologies"]["crypto_libs"].add("OpenSSL")
                    if re.search(r"\b(wolfssl|wc_InitRsaKey)\b", content, re.I):
                        inventory["detected_technologies"]["crypto_libs"].add("wolfSSL")
                    if re.search(r"\b(bcrypt|argon2|pbkdf2)\b", content, re.I):
                        inventory["detected_technologies"]["crypto_libs"].add("Password Hashing (bcrypt/PBKDF2/Argon2)")

                    if re.search(r"\b(mqtt|mosquitto|aedes|PubSubClient|esp_mqtt_client)\b", content, re.I):
                        inventory["detected_technologies"]["protocols_services"].add("MQTT")
                    if re.search(r"\b(coap)\b", content, re.I):
                        inventory["detected_technologies"]["protocols_services"].add("CoAP")
                    if re.search(r"\b(http|https|express|fastapi|flask|esp_http_client|WebServer)\b", content, re.I):
                        inventory["detected_technologies"]["protocols_services"].add("HTTP/REST")
                    if re.search(r"\b(websocket|ws://|wss://|socket\.io)\b", content, re.I):
                        inventory["detected_technologies"]["protocols_services"].add("WebSockets")

                    if re.search(r"\b(Serial\.print|uart_driver_install|ttyS|ttyAMA|UART_NUM_)\b", content):
                        inventory["detected_technologies"]["hardware_interfaces"].add("UART")
                    if re.search(r"\b(Wire\.begin|i2c_master_|i2c_param_config|/dev/i2c)\b", content):
                        inventory["detected_technologies"]["hardware_interfaces"].add("I2C")
                    if re.search(r"\b(SPI\.begin|spi_bus_initialize|MFRC522|RC522)\b", content):
                        inventory["detected_technologies"]["hardware_interfaces"].add("SPI")
                    if re.search(r"\b(MFRC522|RC522|PN532|rfid|nfc)\b", content, re.I):
                        inventory["detected_technologies"]["hardware_interfaces"].add("RFID/NFC (WRLS)")
                    if re.search(r"\b(WiFi\.|esp_wifi|wpa_supplicant)\b", content):
                        inventory["detected_technologies"]["hardware_interfaces"].add("Wi-Fi (WRLS)")
                    if re.search(r"\b(BLEDevice|esp_ble_|NimBLE|bluetooth)\b", content, re.I):
                        inventory["detected_technologies"]["hardware_interfaces"].add("BLE/Bluetooth (WRLS)")
                    if re.search(r"\b(jtag|swd|openocd)\b", content, re.I):
                        inventory["detected_technologies"]["hardware_interfaces"].add("JTAG/SWD")

                    if re.search(r"\b(LittleFS|SPIFFS|nvs_flash|EEPROM|squashfs|ubifs|jffs2|sqlite)\b", content, re.I):
                        for m in set(re.findall(r"\b(LittleFS|SPIFFS|nvs_flash|EEPROM|squashfs|ubifs|jffs2|sqlite)\b", content, re.I)):
                            inventory["detected_technologies"]["storage_filesystems"].add(m)

                    lines = content.splitlines()
                    for idx, line in enumerate(lines, start=1):
                        for mod_key, ref_id, desc, pattern, allowed_exts in rules:
                            if ext in allowed_exts or lower_name in {"sdkconfig", "cmakelists.txt", "makefile", "platformio.ini"}:
                                if pattern.search(line):
                                    findings[mod_key].append({
                                        "id": ref_id,
                                        "file": rel_path,
                                        "line": idx,
                                        "source_tool": "native",
                                        "description": desc,
                                        "snippet": line.strip()[:140],
                                    })
        except PermissionError:
            pass

    _traverse(target_dir)

    for k in inventory["detected_technologies"]:
        inventory["detected_technologies"][k] = sorted(list(inventory["detected_technologies"][k]))

    return inventory, findings


def classify_section_6_1(inventory: dict) -> dict:
    """Step 2: Classifies software functionalities per Section 6.1."""
    has_fw = len(inventory["embedded_code_files"]) > 0 or len(inventory["detected_technologies"]["rtos_os_sdk"]) > 0
    has_build = len(inventory["build_and_firmware_files"]) > 0
    has_des = (
        len(inventory["backend_service_files"]) > 0
        or any(p in inventory["detected_technologies"]["protocols_services"] for p in ["MQTT", "CoAP", "HTTP/REST", "WebSockets"])
    )
    has_ui = len(inventory["ui_frontend_files"]) > 0
    has_wrls = any("WRLS" in h for h in inventory["detected_technologies"]["hardware_interfaces"])
    has_uart = "UART" in inventory["detected_technologies"]["hardware_interfaces"]
    has_i2c = "I2C" in inventory["detected_technologies"]["hardware_interfaces"]

    return {
        "6.1.1_firmware_embedded_code": {
            "active": has_fw,
            "artifact_count": len(inventory["embedded_code_files"]),
            "examples": inventory["embedded_code_files"][:10],
            "activated_modules": (
                ["ISTG-FW", "ISTG-FW[INST]", "ISTG-FW[UPDT]", "ISTG-MEM", "ISTG-PROC", "Embedded AppSec (10 domains)"]
                + (["ISTG-INT[UART]"] if has_uart else [])
                + (["ISTG-INT[I2C]"] if has_i2c else [])
            ) if has_fw else [],
        },
        "6.1.2_build_system_firmware_image": {
            "active": has_build,
            "artifact_count": len(inventory["build_and_firmware_files"]),
            "examples": inventory["build_and_firmware_files"][:10],
            "activated_modules": [
                "ISTG-FW-INFO-004 (Compiler Hardening)",
                "ISTG-FW-CONF-002 (Minimal Surface)",
                "ISTG-FW[INST]-CRYPT-001 (Bootloader)",
                "ISTG-FW-CONF-001 (SBOM)",
            ] if has_build else [],
        },
        "6.1.3_backend_broker_data_services": {
            "active": has_des,
            "artifact_count": len(inventory["backend_service_files"]),
            "examples": inventory["backend_service_files"][:10],
            "activated_modules": ["ISTG-DES (Data Exchange Services)"] if has_des else [],
        },
        "6.1.4_web_app_dashboard_mobile_interfaces": {
            "active": has_ui or has_wrls,
            "artifact_count": len(inventory["ui_frontend_files"]),
            "examples": inventory["ui_frontend_files"][:10],
            "activated_modules": (
                (["ISTG-UI"] if has_ui else [])
                + (["ISTG-WRLS"] if has_wrls else [])
            ),
        },
    }

