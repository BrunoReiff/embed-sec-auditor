# -*- coding: utf-8 -*-
"""
Taint Analyzer Module (FirmAgent-Inspired) — OWASP IoT & Embedded Security Auditor
Performs intraprocedural function-scope Source-to-Sink taint correlation:
Identifies external IoT Input Sources (MQTT, HTTP, UART, BLE, NVS, JSON parsers)
and detects if their data flows into dangerous memory or execution sinks
(strcpy, sprintf, strcat, gets, memcpy, system, popen) within the same function scope.
"""

import re
from pathlib import Path

# External IoT Input Sources (Taint Sources)
TAINT_SOURCE_PATTERNS = [
    # MQTT & PubSub
    ("MQTT Payload", re.compile(r"\b(esp_mqtt_event_handle_t|event->data|payload|topic)\b")),
    ("MQTT Callback", re.compile(r"\b(mqtt_callback|onMessage|PubSubClient::callback)\b")),
    # HTTP / Web / REST APIs
    ("HTTP Request Body/Query", re.compile(r"\b(httpd_req_recv|httpd_req_get_url_query_str|req->body|server\.arg|request->getParam)\b")),
    # UART / Serial / Radio
    ("UART/Serial Read", re.compile(r"\b(uart_read_bytes|Serial\.readBytesUntil|Serial\.readString|Serial\.read)\s*\(")),
    # BLE GATT
    ("BLE GATT Write", re.compile(r"\b(pCharacteristic->getValue|onWrite|ble_gatts_write)\b")),
    # Parsers & Storage
    ("JSON/Storage Parser", re.compile(r"\b(cJSON_GetObjectItem|deserializeJson|nvs_get_str|getenv)\s*\(")),
]

# Dangerous Sinks
DANGEROUS_SINK_PATTERNS = [
    ("Unsafe Buffer Copy/Format", "EMB-APPSEC-01 / ISTG-FW-INPV-001", re.compile(r"\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\(([^)]+)\)")),
    ("Unbounded Memory Copy", "EMB-APPSEC-01 / ISTG-FW-INPV-001", re.compile(r"\b(memcpy|memmove)\s*\(([^,]+),\s*([^,]+),")),
    ("OS Command Execution", "EMB-APPSEC-02 / ISTG-FW-INPV-002", re.compile(r"\b(system|popen|execl|execvp|os\.system|child_process\.exec|eval)\s*\(([^)]+)\)")),
]

FUNCTION_START_RE = re.compile(
    r"^(?:(?:static|inline|extern|const|unsigned|signed|void|int|char|bool|uint\d+_t|int\d+_t|size_t|esp_err_t|Status)\s+)+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^;]*\)\s*\{?",
    re.M,
)


def _extract_c_functions(content: str) -> list:
    """Extracts approximate function scopes (name, start_line, end_line, lines)."""
    lines = content.splitlines()
    functions = []
    current_func = None
    open_braces = 0

    for idx, line in enumerate(lines, start=1):
        m = FUNCTION_START_RE.match(line.strip())
        if m and current_func is None and not line.strip().endswith(";"):
            current_func = {
                "name": m.group(1),
                "start_line": idx,
                "lines": [],
            }
            open_braces = 0

        if current_func is not None:
            current_func["lines"].append((idx, line))
            open_braces += line.count("{") - line.count("}")
            if open_braces <= 0 and "}" in line:
                current_func["end_line"] = idx
                functions.append(current_func)
                current_func = None
                open_braces = 0

    if current_func is not None:
        current_func["end_line"] = len(lines)
        functions.append(current_func)

    return functions


def analyze_file_taint(file_path: Path, target_dir: Path) -> list:
    """Analyzes a single source file for intraprocedural Source-to-Sink taint chains."""
    findings = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    rel_path = str(file_path.resolve().relative_to(target_dir.resolve()))
    functions = _extract_c_functions(content)

    for func in functions:
        func_name = func["name"]
        detected_sources = []
        detected_sinks = []

        # Find sources and sinks inside the function scope
        for line_no, line_text in func["lines"]:
            stripped = line_text.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            for src_name, src_re in TAINT_SOURCE_PATTERNS:
                if src_re.search(line_text):
                    detected_sources.append({
                        "type": src_name,
                        "line": line_no,
                        "snippet": stripped[:100],
                    })

            for sink_type, owasp_id, sink_re in DANGEROUS_SINK_PATTERNS:
                m_sink = sink_re.search(line_text)
                if m_sink:
                    detected_sinks.append({
                        "type": sink_type,
                        "id": owasp_id,
                        "line": line_no,
                        "snippet": stripped[:100],
                        "call": m_sink.group(0)[:60],
                    })

        # Correlate: If function contains both a taint source and a dangerous sink
        if detected_sources and detected_sinks:
            for sink in detected_sinks:
                # Pair with closest preceding source (or first available source)
                src = next((s for s in reversed(detected_sources) if s["line"] <= sink["line"]), detected_sources[0])
                
                module_key = (
                    "Module_1_SAST_and_Memory"
                    if "Buffer" in sink["type"] or "Memory" in sink["type"]
                    else "Module_1_SAST_and_Memory"
                )
                
                findings.append({
                    "module": module_key,
                    "id": sink["id"],
                    "file": rel_path,
                    "line": sink["line"],
                    "source_tool": "FirmAgent-Taint",
                    "description": (
                        f"[FirmAgent:Taint-Chain in `{func_name}()`] External input from {src['type']} (L{src['line']}) "
                        f"flows into dangerous sink `{sink['type']}` at L{sink['line']}."
                    ),
                    "snippet": f"Source L{src['line']} ({src['type']}) -> Sink L{sink['line']}: {sink['snippet']}",
                })

    return findings


def run_taint_analysis(target_dir: Path, inventory: dict) -> list:
    """Executes FirmAgent-inspired taint correlation across discovered embedded & service source files."""
    all_taint_findings = []
    scanned_candidates = (
        inventory.get("embedded_code_files", [])
        + [f for f in inventory.get("backend_service_files", []) if str(f).endswith((".py", ".js", ".ts", ".c", ".cpp"))]
    )

    for rel_f in scanned_candidates:
        abs_f = target_dir / rel_f
        if abs_f.exists() and abs_f.stat().st_size <= 500 * 1024:
            findings = analyze_file_taint(abs_f, target_dir)
            all_taint_findings.extend(findings)

    return all_taint_findings
