# -*- coding: utf-8 -*-
"""
Firmware Binary Inspector Module (IoTwizz-Inspired) — OWASP IoT & Embedded Security Auditor
Inspects raw firmware binary images (.bin, .img, .hex, .uf2, .squashfs, .jffs2):
1. Shannon Entropy Analysis ($0.0 - 8.0$ bits/byte) to detect missing Flash Encryption (ISTG-FW[INST]-CRYPT-002)
2. Magic Header Signatures (SquashFS, JFFS2, CramFS, UBIFS, U-Boot uImage, ESP32 Image Header)
3. Cleartext Secret & Credential Extraction (Wi-Fi, PEM keys, /etc/shadow, telnet backdoor)
4. Optional binwalk CLI integration when present on host
"""

import math
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

# Common Magic Signatures in Embedded Firmware
MAGIC_SIGNATURES = [
    (b"hsqs", "SquashFS Little-Endian Filesystem", "Filesystem"),
    (b"sqsh", "SquashFS Big-Endian Filesystem", "Filesystem"),
    (b"\x85\x19", "JFFS2 Filesystem", "Filesystem"),
    (b"\x45\x3d\xcd\x28", "CramFS Filesystem", "Filesystem"),
    (b"\x31\x18\x10\x06", "UBIFS Image", "Filesystem"),
    (b"\x27\x05\x19\x56", "U-Boot Legacy Image Header (uImage)", "Bootloader"),
    (b"\xe9", "ESP32 / ESP8266 ROM Header (0xE9 Magic)", "Bootloader"),
    (b"UF20", "USB Flashing Format (UF2)", "Firmware Container"),
    (b"-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key Block", "Secret"),
    (b"-----BEGIN EC PRIVATE KEY-----", "EC Private Key Block", "Secret"),
    (b"-----BEGIN CERTIFICATE-----", "X.509 Certificate Block", "PKI"),
]

BINARY_STRING_RULES = [
    (re.compile(rb"root:\$[16]\$[a-zA-Z0-9./]{8,}\$[a-zA-Z0-9./]{22,}"), "Root password hash in binary (/etc/shadow pattern)", "ISTG-FW-SCRT-001"),
    (re.compile(rb"(?:WIFI_PASS|MQTT_PASS|PASSWORD|API_KEY|SECRET)\s*[:=]\s*[\"'][^\"']{4,}[\"']", re.I), "Hardcoded credential/token embedded in binary", "ISTG-FW-SCRT-003"),
    (re.compile(rb"\b(?:telnetd|dropbear|sshd)\b.*-p\s*\d+"), "Embedded backdoor / debug service invocation string", "ISTG-FW-CONF-002"),
    (re.compile(rb"https?://[a-zA-Z0-9.-]+(?:/ota|/firmware|/update)"), "Firmware update URL in cleartext binary", "ISTG-FW[UPDT]-CRYPT-001"),
]


def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)


def inspect_firmware_binaries(target_dir: Path, inventory: dict) -> tuple:
    """
    Scans firmware image files (.bin, .img, .hex, .uf2, etc.) for:
    - Missing Flash Encryption (Entropy < 6.5 bits/byte)
    - Embedded Filesystems & Magic Signatures
    - Cleartext embedded secrets
    """
    findings = []
    telemetry = {
        "binaries_inspected": 0,
        "binwalk_available": bool(shutil.which("binwalk")),
        "details": [],
    }

    fw_files = [
        f for f in inventory.get("build_and_firmware_files", [])
        if any(str(f).lower().endswith(ext) for ext in [".bin", ".img", ".hex", ".uf2", ".squashfs", ".jffs2", ".ubifs"])
    ]

    for rel_f in fw_files:
        abs_f = target_dir / rel_f
        if not abs_f.exists():
            continue

        size = abs_f.stat().st_size
        if size == 0 or size > 30 * 1024 * 1024:  # Guard against huge ISOs
            continue

        try:
            data = abs_f.read_bytes()
        except Exception:
            continue

        telemetry["binaries_inspected"] += 1
        entropy = calculate_shannon_entropy(data)
        detected_sigs = []

        # 1. Magic Signature Scan
        for magic, label, cat in MAGIC_SIGNATURES:
            if magic in data:
                detected_sigs.append(f"{label} ({cat})")

        # 2. Entropy / Encryption Analysis (ISTG-FW[INST]-CRYPT-002)
        if entropy < 6.5 and size >= 32 * 1024:
            findings.append({
                "module": "Module_3_Hardening_Build_Bootloader_Binaries",
                "id": "ISTG-FW[INST]-CRYPT-002 / EMB-APPSEC-06",
                "file": rel_f,
                "line": 1,
                "source_tool": "IoTwizz-Entropy",
                "description": (
                    f"[IoTwizz Binary Inspection] Firmware image '{rel_f}' has low entropy ({entropy}/8.0), "
                    "indicating unencrypted plaintext code. Flash Encryption is absent or disabled."
                ),
                "snippet": f"File: {rel_f} (Size: {size} bytes, Shannon Entropy: {entropy} / 8.0 - UNENCRYPTED)",
            })

        # 3. Cleartext Secrets inside Binary (ISTG-FW-SCRT-001/003)
        for rule_re, desc, owasp_id in BINARY_STRING_RULES:
            matches = rule_re.findall(data)
            for m in matches[:3]:  # Limit duplicates
                decoded = m.decode("utf-8", errors="ignore")[:80]
                findings.append({
                    "module": "Module_2_Secrets_Identity_Cryptography",
                    "id": owasp_id,
                    "file": rel_f,
                    "line": 1,
                    "source_tool": "IoTwizz-Strings",
                    "description": f"[IoTwizz Binary Strings] Leaked artifact in binary '{rel_f}': {desc}.",
                    "snippet": f"Matched in binary: {decoded}",
                })

        # 4. Optional Binwalk Execution
        binwalk_out = None
        if shutil.which("binwalk") and size <= 10 * 1024 * 1024:
            try:
                proc = subprocess.run(
                    ["binwalk", "-B", str(abs_f)],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                binwalk_out = (proc.stdout or "")[:300].strip()
            except Exception:
                pass

        telemetry["details"].append({
            "file": rel_f,
            "size_bytes": size,
            "shannon_entropy": entropy,
            "is_likely_encrypted": entropy >= 7.5,
            "detected_signatures": detected_sigs,
            "binwalk_summary": binwalk_out,
        })

    return findings, telemetry
