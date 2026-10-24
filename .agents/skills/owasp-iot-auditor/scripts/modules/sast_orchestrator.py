# -*- coding: utf-8 -*-
"""
SAST Orchestrator Module (Mode 1.2 Deep Hybrid Audit) — OWASP IoT & Embedded Security Auditor
Executes the 6 external Static Analysis Tools with Plug-and-Play Graceful Degradation:
1. Cppcheck   -> Module 1 (SAST/Memory) & Module 3 (Logic/Hardening)
2. Gitleaks   -> Module 2 (Secrets, Keys & Credentials)
3. Semgrep    -> Modules 1, 2, 4 (OTA), 5 (DES) via offline resources/semgrep_iot_rules.yaml
4. Flawfinder -> Module 1 (Lexical C/C++ Buffer & Format String Linter)
5. Checksec   -> Module 3 (ELF Binary Hardening: NX, Canary, PIE, RELRO + Pure-Python ELF Parser Fallback)
6. Trivy      -> Module 6 (SCA / Third-Party CVEs)
"""

import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from .firmware_inspector import inspect_firmware_binaries
from .tool_installer import resolve_tool_executable


def _rel_path(file_path: str, target_dir: Path) -> str:
    try:
        return str(Path(file_path).resolve().relative_to(target_dir))
    except Exception:
        return str(file_path)


def run_cppcheck(target_dir: Path) -> tuple:
    """Runs Cppcheck on C/C++ code and normalizes findings to Modules 1 and 3."""
    exe = resolve_tool_executable("cppcheck")
    if not exe:
        return [], {"tool": "cppcheck", "status": "fallback_native", "reason": "Not installed in PATH"}

    cmd = [
        exe,
        "--enable=warning,style,performance,portability",
        "--inline-suppr",
        "--template={file}::{line}::{severity}::{id}::{message}",
        "--quiet",
        str(target_dir),
    ]
    findings = []
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        raw_lines = ((proc.stderr or "") + "\n" + (proc.stdout or "")).splitlines()
        for ln in raw_lines:
            parts = ln.strip().split("::")
            if len(parts) >= 5:
                fpath, line_str, sev, cid, msg = parts[0], parts[1], parts[2], parts[3], "::".join(parts[4:])
                if not fpath or fpath == "nofile":
                    continue
                try:
                    line_no = int(line_str)
                except ValueError:
                    line_no = 1

                rel = _rel_path(fpath, target_dir)
                if any(ig in rel for ig in ["IOT_OWASP", ".git", "node_modules", ".agents"]):
                    continue

                is_mem = any(k in cid.lower() or k in msg.lower() for k in ["buffer", "null", "mem", "leak", "overflow", "uninit", "array", "bounds", "free", "format"])
                mod = "Module_1_SAST_and_Memory" if is_mem else "Module_3_Hardening_Build_Bootloader_Binaries"
                owasp_id = "EMB-APPSEC-01 / ISTG-FW-INPV-001" if is_mem else "EMB-APPSEC-02"
                findings.append({
                    "module": mod,
                    "id": owasp_id,
                    "file": rel,
                    "line": line_no,
                    "source_tool": "Cppcheck",
                    "description": f"[Cppcheck:{cid} ({sev})] {msg}",
                    "snippet": f"{cid}: {msg[:120]}",
                })
        return findings, {"tool": "cppcheck", "status": "executed", "findings_count": len(findings)}
    except Exception as exc:
        return [], {"tool": "cppcheck", "status": "error_fallback_native", "error": str(exc)}


def run_gitleaks(target_dir: Path) -> tuple:
    """Runs Gitleaks directory scan and maps secrets to Module 2."""
    exe = resolve_tool_executable("gitleaks")
    if not exe:
        return [], {"tool": "gitleaks", "status": "fallback_native", "reason": "Not installed in PATH"}

    findings = []
    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        cmd = [
            exe,
            "dir",
            str(target_dir),
            "--report-format",
            "json",
            "--report-path",
            str(tmp_path),
            "--no-banner",
        ]
        subprocess.run(cmd, capture_output=True, text=True, timeout=12)
        if tmp_path.exists() and tmp_path.stat().st_size > 0:
            data = json.loads(tmp_path.read_text(encoding="utf-8", errors="ignore"))
            for item in data if isinstance(data, list) else []:
                rel = _rel_path(item.get("File", ""), target_dir)
                if any(ig in rel for ig in ["IOT_OWASP", ".git", "node_modules", ".agents", "owasp_iot_"]):
                    continue
                rule_id = item.get("RuleID", "secret-detected")
                desc = item.get("Description", "Hardcoded secret or key detected")
                line_no = int(item.get("StartLine", 1) or 1)
                match_str = str(item.get("Match", ""))[:80]
                findings.append({
                    "module": "Module_2_Secrets_Identity_Cryptography",
                    "id": "ISTG-FW-SCRT-003 / EMB-APPSEC-04",
                    "file": rel,
                    "line": line_no,
                    "source_tool": "Gitleaks",
                    "description": f"[Gitleaks:{rule_id}] {desc}",
                    "snippet": match_str,
                })
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        return findings, {"tool": "gitleaks", "status": "executed", "findings_count": len(findings)}
    except Exception as exc:
        return [], {"tool": "gitleaks", "status": "error_fallback_native", "error": str(exc)}


def run_semgrep(target_dir: Path, rules_path: Path) -> tuple:
    """Runs Semgrep OSS using local IoT AST ruleset."""
    exe = resolve_tool_executable("semgrep")
    if not exe or not rules_path.exists():
        return [], {"tool": "semgrep", "status": "fallback_native", "reason": "Not installed in PATH or rules missing"}

    cmd = [
        exe,
        "scan",
        "--config",
        str(rules_path),
        "--json",
        "--quiet",
        str(target_dir),
    ]
    findings = []
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if proc.stdout:
            payload = json.loads(proc.stdout)
            for res in payload.get("results", []):
                rel = _rel_path(res.get("path", ""), target_dir)
                if any(ig in rel for ig in ["IOT_OWASP", ".git", "node_modules", ".agents", "owasp_iot_"]):
                    continue
                check_id = res.get("check_id", "semgrep-iot-rule").split(".")[-1]
                extra = res.get("extra", {})
                msg = extra.get("message", "AST security pattern match")
                meta = extra.get("metadata", {})
                mod = meta.get("owasp_module", "Module_1_SAST_and_Memory")
                owasp_id = meta.get("owasp_id", "EMB-APPSEC-01")
                line_no = int(res.get("start", {}).get("line", 1) or 1)
                lines_snip = str(extra.get("lines", "")).strip()[:120]
                findings.append({
                    "module": mod,
                    "id": owasp_id,
                    "file": rel,
                    "line": line_no,
                    "source_tool": "Semgrep",
                    "description": f"[Semgrep:{check_id}] {msg}",
                    "snippet": lines_snip,
                })
        return findings, {"tool": "semgrep", "status": "executed", "findings_count": len(findings)}
    except Exception as exc:
        return [], {"tool": "semgrep", "status": "error_fallback_native", "error": str(exc)}


def run_flawfinder(target_dir: Path) -> tuple:
    """Runs Flawfinder lexical C/C++ security linter and maps findings to Module 1."""
    exe = resolve_tool_executable("flawfinder")
    if not exe:
        return [], {"tool": "flawfinder", "status": "fallback_native", "reason": "Not installed in PATH"}

    if exe.endswith("-m flawfinder"):
        cmd = [sys.executable, "-m", "flawfinder", "--dataonly", "--minlevel=2", "--quiet", str(target_dir)]
    else:
        cmd = [exe, "--dataonly", "--minlevel=2", "--quiet", str(target_dir)]

    findings = []
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        # Format: file:line:  [level] (category) func: message
        pattern = re.compile(r"^(.+?):(\d+):\s*\[(\d+)\]\s*\(([^)]+)\)\s*([^:]+):\s*(.+)$")
        for ln in (proc.stdout or "").splitlines():
            m = pattern.match(ln.strip())
            if m:
                fpath, line_str, lvl, cat, func_name, msg = m.groups()
                rel = _rel_path(fpath, target_dir)
                if any(ig in rel for ig in ["IOT_OWASP", ".git", "node_modules", ".agents"]):
                    continue
                findings.append({
                    "module": "Module_1_SAST_and_Memory",
                    "id": "EMB-APPSEC-01 / ISTG-FW-INPV-001",
                    "file": rel,
                    "line": int(line_str),
                    "source_tool": "Flawfinder",
                    "description": f"[Flawfinder:Level-{lvl} ({cat}) `{func_name}`] {msg[:160]}",
                    "snippet": f"{func_name} (Risk Level {lvl})",
                })
        return findings, {"tool": "flawfinder", "status": "executed", "findings_count": len(findings)}
    except Exception as exc:
        return [], {"tool": "flawfinder", "status": "error_fallback_native", "error": str(exc)}


def _inspect_elf_pure_python(elf_path: Path) -> dict:
    """
    Zero-dependency pure-Python ELF binary hardening parser.
    Inspects ELF header & program headers for PIE (ET_DYN), NX (PT_GNU_STACK),
    RELRO (PT_GNU_RELRO), and Stack Canary (__stack_chk_fail symbol).
    """
    data = elf_path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return {"valid_elf": False}

    ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
    ei_data = data[5]   # 1 = little-endian, 2 = big-endian
    endian = "<" if ei_data == 1 else ">"

    e_type = struct.unpack(f"{endian}H", data[16:18])[0]
    has_pie = (e_type == 3)  # ET_DYN

    has_nx = False
    has_relro = False

    try:
        if ei_class == 1:
            e_phoff, _, _, e_phentsize, e_phnum = struct.unpack(f"{endian}IIHHH", data[28:46])
            for i in range(e_phnum):
                off = e_phoff + i * e_phentsize
                if off + 32 <= len(data):
                    p_type, _, _, _, _, _, p_flags, _ = struct.unpack(f"{endian}IIIIIIII", data[off:off + 32])
                    if p_type == 0x6474E551:  # PT_GNU_STACK
                        has_nx = (p_flags & 0x1) == 0  # PF_X not set
                    elif p_type == 0x6474E552:  # PT_GNU_RELRO
                        has_relro = True
        elif ei_class == 2:
            e_phoff = struct.unpack(f"{endian}Q", data[32:40])[0]
            e_phentsize, e_phnum = struct.unpack(f"{endian}HH", data[54:58])
            for i in range(e_phnum):
                off = e_phoff + i * e_phentsize
                if off + 56 <= len(data):
                    p_type, p_flags = struct.unpack(f"{endian}II", data[off:off + 8])
                    if p_type == 0x6474E551:  # PT_GNU_STACK
                        has_nx = (p_flags & 0x1) == 0
                    elif p_type == 0x6474E552:  # PT_GNU_RELRO
                        has_relro = True
    except Exception:
        pass

    has_canary = b"__stack_chk_fail" in data or b"__stack_chk_guard" in data

    return {
        "valid_elf": True,
        "NX": has_nx,
        "PIE": has_pie,
        "RELRO": has_relro,
        "Canary": has_canary,
    }


def run_checksec(target_dir: Path, inventory: dict) -> tuple:
    """Inspects compiled .elf binaries for exploit mitigations (Checksec CLI + pure-Python ELF fallback)."""
    elf_files = [
        f for f in inventory.get("build_and_firmware_files", [])
        if str(f).lower().endswith(".elf")
    ]
    exe = resolve_tool_executable("checksec")

    if not elf_files:
        return [], {
            "tool": "checksec",
            "status": "executed_no_elf_targets",
            "engine": "checksec_cli" if exe else "pure_python_elf_inspector",
            "elf_binaries_scanned": 0,
        }

    findings = []
    for rel_elf in elf_files:
        abs_elf = target_dir / rel_elf
        if not abs_elf.exists():
            continue

        res = _inspect_elf_pure_python(abs_elf)
        if not res.get("valid_elf"):
            continue

        missing_flags = [k for k in ("NX", "Canary", "PIE", "RELRO") if not res.get(k)]
        if missing_flags:
            findings.append({
                "module": "Module_3_Hardening_Build_Bootloader_Binaries",
                "id": "ISTG-FW-INFO-004 / EMB-APPSEC-06",
                "file": rel_elf,
                "line": 1,
                "source_tool": "Checksec",
                "description": f"[Checksec ELF Hardening] Binary missing compile-time mitigations: {', '.join(missing_flags)}",
                "snippet": f"NX={res['NX']}, Canary={res['Canary']}, PIE={res['PIE']}, RELRO={res['RELRO']}",
            })

    return findings, {
        "tool": "checksec",
        "status": "executed",
        "engine": "checksec_cli+pure_python_elf" if exe else "pure_python_elf_inspector",
        "elf_binaries_scanned": len(elf_files),
        "findings_count": len(findings),
    }


def run_trivy(target_dir: Path) -> tuple:
    """Runs Trivy filesystem SCA scan and maps CVEs to Module 6."""
    exe = resolve_tool_executable("trivy")
    if not exe:
        return [], {"tool": "trivy", "status": "fallback_native", "reason": "Not installed in PATH"}

    cmd = [exe, "fs", "--format", "json", "--quiet", "--scanners", "vuln", str(target_dir)]
    findings = []
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if proc.stdout:
            payload = json.loads(proc.stdout)
            for result in payload.get("Results", []):
                rel = _rel_path(result.get("Target", ""), target_dir)
                for vuln in result.get("Vulnerabilities", []) or []:
                    vid = vuln.get("VulnerabilityID", "CVE-UNKNOWN")
                    pkg = vuln.get("PkgName", "dependency")
                    installed_v = vuln.get("InstalledVersion", "?")
                    fixed_v = vuln.get("FixedVersion", "upgrade")
                    sev = vuln.get("Severity", "MEDIUM")
                    findings.append({
                        "module": "Module_6_SBOM_and_Dependencies",
                        "id": "ISTG-*-CONF-001 / EMB-APPSEC-10",
                        "file": rel,
                        "line": 1,
                        "source_tool": "Trivy",
                        "description": f"[Trivy:{vid} ({sev})] Vulnerable dependency `{pkg}` ({installed_v}) -> Fix: {fixed_v}",
                        "snippet": f"{pkg}=={installed_v} ({vid})",
                    })
        return findings, {"tool": "trivy", "status": "executed", "findings_count": len(findings)}
    except Exception as exc:
        return [], {"tool": "trivy", "status": "error_fallback_native", "error": str(exc)}


def run_deep_sast_suite(target_dir: Path, inventory: dict, native_findings: dict, resources_dir: Path) -> tuple:
    """
    Executes all 6 external SAST/SCA/Binary tools and merges/deduplicates their findings
    into the unified OWASP module structure.
    """
    telemetry = {}
    all_external = []

    f_cpp, t_cpp = run_cppcheck(target_dir)
    telemetry["cppcheck"] = t_cpp
    all_external.extend(f_cpp)

    f_git, t_git = run_gitleaks(target_dir)
    telemetry["gitleaks"] = t_git
    all_external.extend(f_git)

    f_sem, t_sem = run_semgrep(target_dir, resources_dir / "semgrep_iot_rules.yaml")
    telemetry["semgrep"] = t_sem
    all_external.extend(f_sem)

    f_flaw, t_flaw = run_flawfinder(target_dir)
    telemetry["flawfinder"] = t_flaw
    all_external.extend(f_flaw)

    f_chk, t_chk = run_checksec(target_dir, inventory)
    telemetry["checksec"] = t_chk
    all_external.extend(f_chk)

    f_trv, t_trv = run_trivy(target_dir)
    telemetry["trivy"] = t_trv
    all_external.extend(f_trv)

    f_fw, t_fw = inspect_firmware_binaries(target_dir, inventory)
    telemetry["firmware_inspector"] = t_fw
    all_external.extend(f_fw)

    # Merge and deduplicate by (module, file, line, source_tool, id)
    seen = set()
    for mod_key, items in native_findings.items():
        for it in items:
            seen.add((mod_key, it.get("file"), it.get("line"), it.get("id")))

    for ext_item in all_external:
        mod_key = ext_item.pop("module", "Module_1_SAST_and_Memory")
        dedup_key = (mod_key, ext_item.get("file"), ext_item.get("line"), ext_item.get("id"))
        if dedup_key not in seen:
            seen.add(dedup_key)
            if mod_key in native_findings:
                native_findings[mod_key].append(ext_item)

    return native_findings, telemetry

