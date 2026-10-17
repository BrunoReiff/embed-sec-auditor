#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OWASP IoT & Embedded Security Auditor — Helper Scanner Script
Executa:
1. Sondagem Geral de Artefatos e Tecnologias do Projeto Embarcado/IoT
2. Classificação das Funcionalidades conforme a Seção 6.1 (Etapa 2 do SKILL.md)
3. Verificação/Inicialização do Checklist de Estado (onde o agente parou e para onde deve ir)
4. Triagem automatizada seguindo a ordem estrita da Seção 6.2 (Módulos 1 a 6)
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
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


def scan_project_artifacts(target_dir: Path):
    """Etapa 1: Sondagem geral do projeto e detecção de artefatos e tecnologias."""
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

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        rel_root = Path(root).relative_to(target_dir)

        for fname in files:
            fpath = Path(root) / fname
            rel_path = str(rel_root / fname) if str(rel_root) != "." else fname
            ext = fpath.suffix.lower()

            if fname == "metodologia_owasp_iot_agente.md" or fname.startswith("owasp_iot_"):
                continue

            inventory["total_files_scanned"] += 1
            inventory["files_by_ext"][ext] = inventory["files_by_ext"].get(ext, 0) + 1

            if fname == ".gitignore":
                inventory["has_gitignore"] = True
                try:
                    inventory["gitignore_content"] = fpath.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    pass

            lower_name = fname.lower()
            # Build & Firmware images
            if (
                lower_name in {"cmakelists.txt", "makefile", "platformio.ini", "sdkconfig", "sdkconfig.defaults", "kconfig", "dockerfile", "docker-compose.yml", "idf_component.yml"}
                or ext in {".bin", ".elf", ".hex", ".uf2", ".img", ".squashfs", ".jffs2", ".ubifs", ".ld"}
                or lower_name.endswith(".bb") or lower_name.endswith(".bbappend")
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

            # Embedded code files
            if ext in {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".ino", ".s", ".S"}:
                inventory["embedded_code_files"].append(rel_path)
                if ext == ".ino":
                    inventory["detected_technologies"]["rtos_os_sdk"].add("Arduino")

            # Backend / Services
            if lower_name in {"package.json", "requirements.txt", "pyproject.toml", "mosquitto.conf"} or ext in {".py", ".js", ".ts", ".go", ".rs"}:
                if not any(p in rel_path.lower() for p in ["frontend", "public", "www", "htdocs", "ui", "web"]):
                    inventory["backend_service_files"].append(rel_path)

            # UI / Frontend
            if ext in {".html", ".htm", ".css", ".vue", ".jsx", ".tsx"} or any(p in rel_path.lower() for p in ["frontend", "www", "htdocs", "webui", "dashboard"]):
                inventory["ui_frontend_files"].append(rel_path)

            # Content inspection for tech stack detection
            if ext in SOURCE_EXTS or lower_name in {"sdkconfig", "platformio.ini", "cmakelists.txt", "package.json"}:
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                # RTOS / OS
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

                # Crypto libraries
                if re.search(r"\b(mbedtls_|mbedtls/)\b", content, re.I):
                    inventory["detected_technologies"]["crypto_libs"].add("mbedTLS")
                if re.search(r"\b(openssl/|SSL_CTX_|EVP_PKEY|X509_verify_cert)\b", content):
                    inventory["detected_technologies"]["crypto_libs"].add("OpenSSL")
                if re.search(r"\b(wolfssl|wc_InitRsaKey)\b", content, re.I):
                    inventory["detected_technologies"]["crypto_libs"].add("wolfSSL")
                if re.search(r"\b(bcrypt|argon2|pbkdf2)\b", content, re.I):
                    inventory["detected_technologies"]["crypto_libs"].add("Password Hashing (bcrypt/PBKDF2/Argon2)")

                # Protocols & Data Exchange Services
                if re.search(r"\b(mqtt|mosquitto|aedes|PubSubClient|esp_mqtt_client)\b", content, re.I):
                    inventory["detected_technologies"]["protocols_services"].add("MQTT")
                if re.search(r"\b(coap)\b", content, re.I):
                    inventory["detected_technologies"]["protocols_services"].add("CoAP")
                if re.search(r"\b(http|https|express|fastapi|flask|esp_http_client|WebServer)\b", content, re.I):
                    inventory["detected_technologies"]["protocols_services"].add("HTTP/REST")
                if re.search(r"\b(websocket|ws://|wss://|socket\.io)\b", content, re.I):
                    inventory["detected_technologies"]["protocols_services"].add("WebSockets")

                # Hardware & Wireless Interfaces
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

                # Storage / Filesystems
                if re.search(r"\b(LittleFS|SPIFFS|nvs_flash|EEPROM|squashfs|ubifs|jffs2|sqlite)\b", content, re.I):
                    for m in set(re.findall(r"\b(LittleFS|SPIFFS|nvs_flash|EEPROM|squashfs|ubifs|jffs2|sqlite)\b", content, re.I)):
                        inventory["detected_technologies"]["storage_filesystems"].add(m)

    # Convert sets to sorted lists for JSON serialization
    for k in inventory["detected_technologies"]:
        inventory["detected_technologies"][k] = sorted(list(inventory["detected_technologies"][k]))

    return inventory


def classify_section_6_1(inventory):
    """Etapa 2: Classifica as funcionalidades do software com a Seção 6.1 do metodologia_owasp_iot_agente.md."""
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

    classification = {
        "6.1.1_firmware_codigo_embarcado": {
            "ativo": has_fw,
            "artefatos_contagem": len(inventory["embedded_code_files"]),
            "exemplos": inventory["embedded_code_files"][:10],
            "modulos_ativados": (
                ["ISTG-FW", "ISTG-FW[INST]", "ISTG-FW[UPDT]", "ISTG-MEM", "ISTG-PROC", "Embedded AppSec (10 domínios)"]
                + (["ISTG-INT[UART]"] if has_uart else [])
                + (["ISTG-INT[I2C]"] if has_i2c else [])
            ) if has_fw else [],
        },
        "6.1.2_sistema_build_imagem_firmware": {
            "ativo": has_build,
            "artefatos_contagem": len(inventory["build_and_firmware_files"]),
            "exemplos": inventory["build_and_firmware_files"][:10],
            "modulos_ativados": [
                "ISTG-FW-INFO-004 (Hardening Compilação)",
                "ISTG-FW-CONF-002 (Superfície Mínima)",
                "ISTG-FW[INST]-CRYPT-001 (Bootloader)",
                "ISTG-FW-CONF-001 (SBOM)",
            ] if has_build else [],
        },
        "6.1.3_backend_broker_servicos_dados": {
            "ativo": has_des,
            "artefatos_contagem": len(inventory["backend_service_files"]),
            "exemplos": inventory["backend_service_files"][:10],
            "modulos_ativados": ["ISTG-DES (Serviços de Troca de Dados)"] if has_des else [],
        },
        "6.1.4_aplicacao_web_painel_mobile_interfaces": {
            "ativo": has_ui or has_wrls,
            "artefatos_contagem": len(inventory["ui_frontend_files"]),
            "exemplos": inventory["ui_frontend_files"][:10],
            "modulos_ativados": (
                (["ISTG-UI"] if has_ui else [])
                + (["ISTG-WRLS"] if has_wrls else [])
            ),
        },
    }
    return classification


def check_checklist_progress(checklist_path: Path):
    """Etapa 3: Lê o checklist guia para informar onde o agente parou e para onde deve ir."""
    if not checklist_path.exists():
        return {
            "exists": False,
            "message": f"Checklist ainda não inicializado em {checklist_path}. Deve ser criado a partir de resources/checklist_template.md.",
        }

    content = checklist_path.read_text(encoding="utf-8", errors="ignore")
    rows = re.findall(
        r"^\|\s*`?((?:ISTG|EMB-APPSEC|FSTM-STAGE)-[A-Z0-9\[\]\-]+)`?\s*\|\s*([^|]+)\|\s*(Módulo [^|]+)\|\s*(?:[^|]+\|\s*)?`?(PASS|PARTIAL|FAIL|N/A|PENDENTE|OPCIONAL|DE ACORDO|PARCIALMENTE DE ACORDO|EM DESACORDO)`?\s*\|",
        content,
        re.M,
    )

    counts = {"PASS": 0, "PARTIAL": 0, "FAIL": 0, "N/A": 0, "PENDENTE": 0, "OPCIONAL": 0}
    last_completed = None
    next_pending = None

    for test_id, name, modulo, status in rows:
        norm_status = status.strip()
        if norm_status in {"DE ACORDO", "PASS"}:
            norm_status = "PASS"
        elif norm_status in {"PARCIALMENTE DE ACORDO", "PARTIAL"}:
            norm_status = "PARTIAL"
        elif norm_status in {"EM DESACORDO", "FAIL"}:
            norm_status = "FAIL"

        counts[norm_status] = counts.get(norm_status, 0) + 1
        if norm_status not in {"PENDENTE", "OPCIONAL"}:
            last_completed = f"{test_id} ({modulo.strip()}) -> {norm_status}"
        elif norm_status == "PENDENTE" and next_pending is None:
            next_pending = f"{test_id} ({modulo.strip()} - {name.strip()})"

    return {
        "exists": True,
        "checklist_path": str(checklist_path),
        "summary_counts": counts,
        "onde_o_agente_parou": last_completed or "Nenhum item concluído ainda (Início da Auditoria)",
        "para_onde_o_agente_deve_ir": next_pending or "Todos os itens do checklist foram concluídos! Pronto para gerar o Relatório Final.",
    }


def run_section_6_2_checks(target_dir: Path):
    """Etapa 4: Executa verificações estáticas seguindo a ordem estrita dos 6 módulos da Seção 6.2."""
    findings = {
        "Modulo_1_SAST_e_Memoria": [],
        "Modulo_2_Segredos_Identidade_Criptografia": [],
        "Modulo_3_Hardening_Build_Bootloader_Binarios": [],
        "Modulo_4_Atualizacao_Firmware_OTA": [],
        "Modulo_5_Servicos_Troca_Dados_Logica": [],
        "Modulo_6_SBOM_e_Dependencias": [],
    }

    rules = [
        # Módulo 1
        ("Modulo_1_SAST_e_Memoria", "ISTG-*-INPV-001 / EMB-APPSEC-01", "Função C/C++ insegura para manipulação de buffer", re.compile(r"\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\("), {".c", ".cpp", ".cc", ".h", ".hpp", ".ino"}),
        ("Modulo_1_SAST_e_Memoria", "EMB-APPSEC-01", "Possível mau uso de strncpy/strncat com strlen", re.compile(r"\b(strncpy|strncat)\s*\([^;]*strlen\s*\("), {".c", ".cpp", ".cc", ".h", ".hpp", ".ino"}),
        ("Modulo_1_SAST_e_Memoria", "ISTG-*-INPV-002 / EMB-APPSEC-02", "Execução de comando/processo externo (risco de Command Injection)", re.compile(r"\b(system|popen|execlp|execvp|os\.system|child_process\.exec|eval)\s*\("), {".c", ".cpp", ".py", ".js", ".ts", ".lua", ".php"}),
        # Módulo 2
        ("Modulo_2_Segredos_Identidade_Criptografia", "ISTG-FW-SCRT-003 / EMB-APPSEC-04", "Possível segredo/credencial hardcoded", re.compile(r"(?:WIFI_PASS|MQTT_PASS|PASSWORD|SECRET|API_KEY|PRIVATE_KEY)\s*[:=]\s*[\"'][^\"']{3,}[\"']|-----BEGIN (?:RSA )?PRIVATE KEY-----", re.I), SOURCE_EXTS),
        ("Modulo_2_Segredos_Identidade_Criptografia", "ISTG-*-CRYPT-001 / EMB-APPSEC-08", "Validação de certificado TLS desabilitada", re.compile(r"\b(setInsecure\s*\(\)|MBEDTLS_SSL_VERIFY_NONE|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*0)\b"), SOURCE_EXTS),
        ("Modulo_2_Segredos_Identidade_Criptografia", "ISTG-*-CRYPT-001", "Uso de algoritmo criptográfico ou hash fraco (MD5/SHA1/DES/RC4/ECB)", re.compile(r"\b(MD5|SHA1|DES|3DES|RC4|AES_ECB|ECB_MODE)\b"), SOURCE_EXTS),
        # Módulo 3
        ("Modulo_3_Hardening_Build_Bootloader_Binarios", "ISTG-INT[UART]-INFO-002", "Log serial detectado (verificar se expõe segredos/UIDs/tokens na UART)", re.compile(r"\b(Serial\.print|Serial\.println|Serial\.printf|ESP_LOG[IWDVE])\s*\([^)]*(?:pass|key|token|secret|uid|hash|pin)", re.I), {".c", ".cpp", ".h", ".hpp", ".ino"}),
        ("Modulo_3_Hardening_Build_Bootloader_Binarios", "ISTG-FW-INFO-004 / EMB-APPSEC-06", "Flag de hardening de compilação ou Secure Boot/Flash Encryption presente", re.compile(r"(-fstack-protector|-fPIE|-D_FORTIFY_SOURCE|CONFIG_SECURE_BOOT|CONFIG_SECURE_FLASH_ENC|CONFIG_ENABLE_VBOOT|CONFIG_FIT_SIGNATURE)"), {".txt", ".ini", ".mk", ".cmake", ""}),
        # Módulo 4
        ("Modulo_4_Atualizacao_Firmware_OTA", "ISTG-FW[UPDT]-*", "Rotina ou configuração de atualização de firmware (OTA) detectada", re.compile(r"\b(esp_https_ota|esp_ota_begin|ArduinoOTA|HTTPUpdate|Update\.begin|CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK)\b"), SOURCE_EXTS),
        # Módulo 5
        ("Modulo_5_Servicos_Troca_Dados_Logica", "ISTG-DES-AUTHZ-001", "Configuração de acesso anônimo ou tópico MQTT wildcard", re.compile(r"\b(allow_anonymous\s+true)\b|subscribe\s*\(\s*[\"']#[\"']"), SOURCE_EXTS),
    ]

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        rel_root = Path(root).relative_to(target_dir)

        for fname in files:
            if fname == "metodologia_owasp_iot_agente.md" or fname.startswith("owasp_iot_"):
                continue
            fpath = Path(root) / fname
            rel_path = str(rel_root / fname) if str(rel_root) != "." else fname
            ext = fpath.suffix.lower()

            if fname in {"package.json", "requirements.txt", "platformio.ini", "idf_component.yml"}:
                findings["Modulo_6_SBOM_e_Dependencias"].append({
                    "id": "ISTG-*-CONF-001 / EMB-APPSEC-10",
                    "file": rel_path,
                    "line": 1,
                    "description": f"Manifesto de dependências detectado ({fname}) para geração de SBOM e auditoria de CVEs.",
                })

            if ext not in SOURCE_EXTS and fname.lower() not in {"sdkconfig", "cmakelists.txt", "makefile", "platformio.ini"}:
                continue

            try:
                lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue

            for idx, line in enumerate(lines, start=1):
                for mod_key, ref_id, desc, pattern, allowed_exts in rules:
                    if ext in allowed_exts or fname.lower() in {"sdkconfig", "cmakelists.txt", "makefile", "platformio.ini"}:
                        if pattern.search(line):
                            findings[mod_key].append({
                                "id": ref_id,
                                "file": rel_path,
                                "line": idx,
                                "description": desc,
                                "snippet": line.strip()[:140],
                            })

    return findings


def main():
    parser = argparse.ArgumentParser(description="OWASP IoT & Embedded Security Auditor Helper")
    parser.add_argument("--target", default=".", help="Diretório raiz do projeto embarcado/IoT a ser sondado")
    parser.add_argument("--checklist", default="owasp_iot_checklist_progresso.md", help="Caminho do arquivo de checklist de progresso")
    parser.add_argument("--report", default="owasp_iot_relatorio_final.md", help="Caminho do arquivo de relatório final")
    parser.add_argument("--remediation", default="owasp_iot_plano_resolucao.md", help="Caminho do plano de resolução")
    parser.add_argument("--verify-id", default="", help="Modo 2: ID OWASP específico para reteste pontual (ex.: ISTG-FW-SCRT-003)")
    parser.add_argument("--init-checklist", action="store_true", help="Inicializa o checklist de progresso no projeto caso não exista")
    parser.add_argument("--init-remediation", action="store_true", help="Inicializa o plano de resolução no projeto caso não exista")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    checklist_path = target_dir / args.checklist
    report_path = target_dir / args.report
    remediation_path = target_dir / args.remediation

    if args.init_checklist and not checklist_path.exists():
        template_path = Path(__file__).resolve().parent.parent / "resources" / "checklist_template.md"
        if template_path.exists():
            content = template_path.read_text(encoding="utf-8")
            content = content.replace("<NOME_OU_CAMINHO_DO_PROJETO>", target_dir.name)
            content = content.replace("<YYYY-MM-DD HH:MM>", datetime.now().strftime("%Y-%m-%d %H:%M"))
            checklist_path.write_text(content, encoding="utf-8")

    if args.init_remediation and not remediation_path.exists():
        rem_template_path = Path(__file__).resolve().parent.parent / "resources" / "remediation_tracker_template.md"
        if rem_template_path.exists():
            content = rem_template_path.read_text(encoding="utf-8")
            content = content.replace("<NOME_DO_PROJETO>", target_dir.name)
            content = content.replace("<YYYY-MM-DD HH:MM>", datetime.now().strftime("%Y-%m-%d %H:%M"))
            remediation_path.write_text(content, encoding="utf-8")

    if args.verify_id.strip():
        vid = args.verify_id.strip()
        def find_matches(fpath: Path):
            if not fpath.exists():
                return []
            lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
            return [{"line": i + 1, "text": ln.strip()} for i, ln in enumerate(lines) if vid in ln]

        print(json.dumps({
            "modo": "Modo 2 - Reteste Pontual por ID OWASP",
            "id_solicitado": vid,
            "registros_no_plano_resolucao": find_matches(remediation_path),
            "registros_no_relatorio_final": find_matches(report_path),
            "registros_no_checklist": find_matches(checklist_path),
            "instrucao_agente": f"Inspecione cirurgicamente os arquivos citados para {vid}, emita o veredito (PASS/PARTIAL/FAIL) e sincronize owasp_iot_plano_resolucao.md, owasp_iot_relatorio_final.md e owasp_iot_checklist_progresso.md."
        }, indent=2, ensure_ascii=False))
        return

    inventory = scan_project_artifacts(target_dir)
    classification = classify_section_6_1(inventory)
    progress = check_checklist_progress(checklist_path)
    checks_6_2 = run_section_6_2_checks(target_dir)

    report_output = {
        "etapa_1_sondagem_geral": inventory,
        "etapa_2_classificacao_secao_6_1": classification,
        "etapa_3_estado_do_checklist": progress,
        "etapa_4_triagem_secao_6_2": checks_6_2,
    }

    print(json.dumps(report_output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()


