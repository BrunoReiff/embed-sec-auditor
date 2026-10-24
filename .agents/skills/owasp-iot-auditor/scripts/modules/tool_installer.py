# -*- coding: utf-8 -*-
"""
Tool Installer & Readiness Checker Module — OWASP IoT & Embedded Security Auditor
Handles:
1. --check-tools: Detects which of the 6 external SAST/SCA/Binary tools are installed on the host.
2. --install-tools: Executes cross-platform installation (pip / winget / choco / scoop / apt / brew)
   when the user selects Option A (Install Missing Tools Now).
"""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

TOOL_CATALOG = {
    "cppcheck": {
        "display_name": "Cppcheck",
        "domain": "Deep C/C++ Semantic & Flow SAST",
        "owasp_modules": ["Module 1 (Memory & SAST)", "Module 3 (Hardening & Logic)"],
        "win_fallback_paths": [
            r"C:\Program Files\Cppcheck\cppcheck.exe",
            r"C:\Program Files (x86)\Cppcheck\cppcheck.exe",
        ],
        "install_cmds": {
            "windows": [
                ["winget", "install", "--id", "Cppcheck.Cppcheck", "-e", "--silent", "--accept-package-agreements", "--accept-source-agreements"],
                ["choco", "install", "cppcheck", "-y"],
                ["scoop", "install", "cppcheck"],
            ],
            "linux": [["sudo", "apt-get", "install", "-y", "cppcheck"]],
            "darwin": [["brew", "install", "cppcheck"]],
        },
    },
    "gitleaks": {
        "display_name": "Gitleaks",
        "domain": "High-Speed Secret, Key & Token Scanner",
        "owasp_modules": ["Module 2 (Secrets, Identity & Crypto)"],
        "win_fallback_paths": [],
        "install_cmds": {
            "windows": [
                ["winget", "install", "--id", "Gitleaks.Gitleaks", "-e", "--silent", "--accept-package-agreements", "--accept-source-agreements"],
                ["choco", "install", "gitleaks", "-y"],
                ["scoop", "install", "gitleaks"],
            ],
            "linux": [["sudo", "apt-get", "install", "-y", "gitleaks"]],
            "darwin": [["brew", "install", "gitleaks"]],
        },
    },
    "semgrep": {
        "display_name": "Semgrep OSS",
        "domain": "AST Pattern Matching for IoT & Embedded APIs",
        "owasp_modules": ["Module 1", "Module 2", "Module 4 (OTA)", "Module 5 (DES)"],
        "win_fallback_paths": [],
        "install_cmds": {
            "windows": [[sys.executable, "-m", "pip", "install", "--upgrade", "semgrep"]],
            "linux": [[sys.executable, "-m", "pip", "install", "--upgrade", "semgrep"]],
            "darwin": [["brew", "install", "semgrep"], [sys.executable, "-m", "pip", "install", "--upgrade", "semgrep"]],
        },
    },
    "flawfinder": {
        "display_name": "Flawfinder",
        "domain": "Lexical C/C++ Security Linter with CWE Scoring",
        "owasp_modules": ["Module 1 (Memory Safety & Buffer Overflows)"],
        "win_fallback_paths": [],
        "install_cmds": {
            "windows": [[sys.executable, "-m", "pip", "install", "--upgrade", "flawfinder"]],
            "linux": [[sys.executable, "-m", "pip", "install", "--upgrade", "flawfinder"]],
            "darwin": [[sys.executable, "-m", "pip", "install", "--upgrade", "flawfinder"]],
        },
    },
    "checksec": {
        "display_name": "Checksec (Checksec-Py / Native ELF Inspector)",
        "domain": "Compiled ELF Binary Hardening Inspector (NX, PIE, Canary, RELRO)",
        "owasp_modules": ["Module 3 (Firmware & Binary Hardening)"],
        "win_fallback_paths": [],
        "install_cmds": {
            "windows": [[sys.executable, "-m", "pip", "install", "--upgrade", "checksec.py"]],
            "linux": [["sudo", "apt-get", "install", "-y", "checksec"], [sys.executable, "-m", "pip", "install", "--upgrade", "checksec.py"]],
            "darwin": [["brew", "install", "checksec"], [sys.executable, "-m", "pip", "install", "--upgrade", "checksec.py"]],
        },
    },
    "trivy": {
        "display_name": "Trivy (Aqua Security)",
        "domain": "Software Composition Analysis (SCA) & CVE Scanner",
        "owasp_modules": ["Module 6 (SBOM & Third-Party Dependencies)"],
        "win_fallback_paths": [],
        "install_cmds": {
            "windows": [
                ["winget", "install", "--id", "AquaSecurity.Trivy", "-e", "--silent", "--accept-package-agreements", "--accept-source-agreements"],
                ["choco", "install", "trivy", "-y"],
                ["scoop", "install", "trivy"],
            ],
            "linux": [["sudo", "apt-get", "install", "-y", "trivy"]],
            "darwin": [["brew", "install", "trivy"]],
        },
    },
}


def resolve_tool_executable(tool_key: str) -> str:
    """Finds the executable path for a tool via PATH, Python Scripts dir, or known OS locations."""
    exe = shutil.which(tool_key)
    if exe:
        return exe

    # Check Python user/venv Scripts directory
    py_scripts_dirs = [
        Path(sys.executable).parent / "Scripts",
        Path(sys.executable).parent / "bin",
        Path.home() / "AppData" / "Roaming" / "Python" / f"Python{sys.version_info.major}{sys.version_info.minor}" / "Scripts",
        Path.home() / ".local" / "bin",
    ]
    for sdir in py_scripts_dirs:
        for ext in ("", ".exe", ".cmd", ".bat"):
            candidate = sdir / f"{tool_key}{ext}"
            if candidate.exists():
                return str(candidate)

    # Check Windows fallback paths
    for p in TOOL_CATALOG.get(tool_key, {}).get("win_fallback_paths", []):
        if Path(p).exists():
            return p

    # Check Python module invocation for flawfinder
    if tool_key == "flawfinder":
        try:
            res = subprocess.run(
                [sys.executable, "-c", "import flawfinder; print(flawfinder.__file__)"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode == 0 and res.stdout.strip():
                return f"{sys.executable} -m flawfinder"
        except Exception:
            pass

    return ""


def get_os_key() -> str:
    sys_name = platform.system().lower()
    if "windows" in sys_name:
        return "windows"
    if "darwin" in sys_name:
        return "darwin"
    return "linux"


def check_all_tools() -> dict:
    """Checks installation readiness of all 6 static analysis tools."""
    os_key = get_os_key()
    installed = []
    missing = []
    details = {}

    for tool_key, meta in TOOL_CATALOG.items():
        exe_path = resolve_tool_executable(tool_key)
        is_present = bool(exe_path)
        if is_present:
            installed.append(tool_key)
        else:
            missing.append(tool_key)

        cmds = meta["install_cmds"].get(os_key, meta["install_cmds"]["linux"])
        readable_cmds = [" ".join(c) for c in cmds]

        details[tool_key] = {
            "display_name": meta["display_name"],
            "installed": is_present,
            "executable": exe_path or None,
            "domain": meta["domain"],
            "owasp_modules": meta["owasp_modules"],
            "builtin_python_fallback": tool_key == "checksec",
            "recommended_install_commands": readable_cmds,
        }

    all_ready = len(missing) == 0
    return {
        "os_platform": os_key,
        "all_installed": all_ready,
        "installed_count": len(installed),
        "missing_count": len(missing),
        "installed_tools": installed,
        "missing_tools": missing,
        "tools": details,
        "agent_instruction": (
            "All 6 SAST tools are installed! Proceed directly with --deep-scan."
            if all_ready
            else (
                f"MISSING TOOLS DETECTED ({', '.join(missing)}). "
                "Before running Mode 1.2 (--deep-scan), ASK THE USER if they want to install the missing tools now:\n"
                "- Option A (Install Now): Run `python .agents/skills/owasp-iot-auditor/scripts/owasp_iot_scanner.py --install-tools all`\n"
                "- Option B (Skip & Continue): Run `--deep-scan` using installed tools + native OWASP engine fallback."
            )
        ),
    }


def install_missing_tools(requested: str = "all") -> dict:
    """Attempts automated installation of missing tools requested by the user (Option A)."""
    status_before = check_all_tools()
    os_key = get_os_key()

    if requested.strip().lower() == "all":
        targets = status_before["missing_tools"]
    else:
        targets = [t.strip().lower() for t in requested.split(",") if t.strip().lower() in TOOL_CATALOG]

    install_logs = {}
    for tool_key in targets:
        if resolve_tool_executable(tool_key):
            install_logs[tool_key] = {"status": "already_installed", "executable": resolve_tool_executable(tool_key)}
            continue

        candidate_cmds = TOOL_CATALOG[tool_key]["install_cmds"].get(os_key, [])
        succeeded = False
        attempts = []

        for cmd in candidate_cmds:
            # Verify package manager binary exists before running
            pkg_mgr = cmd[0]
            if pkg_mgr != sys.executable and not shutil.which(pkg_mgr):
                attempts.append({"command": " ".join(cmd), "error": f"Package manager '{pkg_mgr}' not found in PATH"})
                continue

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                attempts.append({
                    "command": " ".join(cmd),
                    "returncode": proc.returncode,
                    "stdout_tail": (proc.stdout or "")[-300:].strip(),
                    "stderr_tail": (proc.stderr or "")[-300:].strip(),
                })
                if proc.returncode == 0 or resolve_tool_executable(tool_key):
                    succeeded = True
                    break
            except Exception as exc:
                attempts.append({"command": " ".join(cmd), "error": str(exc)})

        new_exe = resolve_tool_executable(tool_key)
        install_logs[tool_key] = {
            "status": "installed" if (succeeded or new_exe) else "failed",
            "executable": new_exe or None,
            "attempts": attempts,
        }

    status_after = check_all_tools()
    return {
        "requested_tools": targets,
        "installation_results": install_logs,
        "post_install_status": status_after,
    }

