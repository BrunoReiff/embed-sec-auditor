# -*- coding: utf-8 -*-
"""
HTML Manager Module — OWASP IoT & Embedded Security Auditor
Handles:
1. Fast-Path static HTML template initialization (--init-all, --init-checklist, --init-report, --init-remediation)
2. Safe anchor injection preserving immutable HTML skeleton comments (--inject-anchor)
3. Checklist progress state parsing (Step 3)
4. Mode 2 targeted OWASP ID lookup (--verify-id)
"""

import re
from datetime import datetime
from pathlib import Path


def initialize_templates(
    target_dir: Path,
    resources_dir: Path,
    do_checklist: bool,
    do_report: bool,
    do_remediation: bool,
    checklist_path: Path,
    report_path: Path,
    remediation_path: Path,
) -> list:
    """Initializes requested static HTML tracking files from immutable templates if they do not exist."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    date_str = datetime.now().strftime("%Y-%m-%d")
    initialized_files = []

    if do_checklist and not checklist_path.exists():
        template_path = resources_dir / "checklist_template.html"
        if template_path.exists():
            content = template_path.read_text(encoding="utf-8")
            content = content.replace("&lt;PROJECT_NAME_OR_PATH&gt;", target_dir.name).replace("<PROJECT_NAME_OR_PATH>", target_dir.name)
            content = content.replace("&lt;YYYY-MM-DD HH:MM&gt;", now_str).replace("<YYYY-MM-DD HH:MM>", now_str)
            checklist_path.write_text(content, encoding="utf-8")
            initialized_files.append(str(checklist_path))

    if do_report and not report_path.exists():
        report_template_path = resources_dir / "report_template.html"
        if report_template_path.exists():
            content = report_template_path.read_text(encoding="utf-8")
            content = content.replace("&lt;PROJECT_NAME&gt;", target_dir.name).replace("<PROJECT_NAME>", target_dir.name)
            content = content.replace("&lt;YYYY-MM-DD&gt;", date_str).replace("<YYYY-MM-DD>", date_str)
            report_path.write_text(content, encoding="utf-8")
            initialized_files.append(str(report_path))

    if do_remediation and not remediation_path.exists():
        rem_template_path = resources_dir / "remediation_tracker_template.html"
        if rem_template_path.exists():
            content = rem_template_path.read_text(encoding="utf-8")
            content = content.replace("&lt;PROJECT_NAME&gt;", target_dir.name).replace("<PROJECT_NAME>", target_dir.name)
            content = content.replace("&lt;YYYY-MM-DD HH:MM&gt;", now_str).replace("<YYYY-MM-DD HH:MM>", now_str)
            remediation_path.write_text(content, encoding="utf-8")
            initialized_files.append(str(remediation_path))

    return initialized_files


def check_checklist_progress(checklist_path: Path) -> dict:
    """Step 3: Reads the state-tracking checklist to report where the agent stopped and where it must go next."""
    if not checklist_path.exists():
        return {
            "exists": False,
            "message": f"Checklist not yet initialized at {checklist_path}. Create it via --init-all or --init-checklist.",
        }

    content = checklist_path.read_text(encoding="utf-8", errors="ignore")

    rows = re.findall(
        r"<tr>\s*<td><code>((?:ISTG|EMB-APPSEC|FSTM-STAGE)-[A-Z0-9\[\]\-]+)</code></td>\s*<td>([^<]+)</td>\s*<td>(Modules? [^<]+)</td>\s*(?:<td>[^<]*</td>\s*)?<td>(?:<span[^>]*>|<code>)?(PASS|PARTIAL|FAIL|N/A|PENDING|OPTIONAL)(?:</span>|</code>)?</td>",
        content,
        re.I,
    )

    if not rows:
        rows = re.findall(
            r"^\|\s*`?((?:ISTG|EMB-APPSEC|FSTM-STAGE)-[A-Z0-9\[\]\-]+)`?\s*\|\s*([^|]+)\|\s*(Modules? [^|]+)\|\s*(?:[^|]+\|\s*)?`?(PASS|PARTIAL|FAIL|N/A|PENDING|OPTIONAL)`?\s*\|",
            content,
            re.M,
        )

    counts = {"PASS": 0, "PARTIAL": 0, "FAIL": 0, "N/A": 0, "PENDING": 0, "OPTIONAL": 0}
    last_completed = None
    next_pending = None

    for test_id, name, modulo, status in rows:
        norm_status = status.strip().upper()
        counts[norm_status] = counts.get(norm_status, 0) + 1
        if norm_status not in {"PENDING", "OPTIONAL"}:
            last_completed = f"{test_id} ({modulo.strip()}) -> {norm_status}"
        elif norm_status == "PENDING" and next_pending is None:
            next_pending = f"{test_id} ({modulo.strip()} - {name.strip()})"

    return {
        "exists": True,
        "checklist_path": str(checklist_path),
        "summary_counts": counts,
        "where_agent_stopped": last_completed or "No items completed yet (Start of Audit)",
        "where_agent_must_go_next": next_pending or "All mandatory checklist items completed! Ready to generate the Final Report.",
    }


def inject_into_html_anchor(html_path: Path, anchor_name: str, new_content: str) -> dict:
    """
    Safely injects HTML content into an anchor section while PRESERVING the anchor comment.
    Guarantees:
    - The anchor comment <!-- ANCHOR: <anchor_name> --> is NEVER deleted or replaced.
    - Content is placed immediately after the anchor comment.
    """
    if not html_path.exists():
        return {"success": False, "error": f"Target file does not exist: {html_path}"}

    text = html_path.read_text(encoding="utf-8")
    pattern = re.compile(rf"(<!--\s*ANCHOR:\s*{re.escape(anchor_name)}\s*-->)", re.IGNORECASE)
    match = pattern.search(text)
    if not match:
        return {"success": False, "error": f"Anchor comment not found: <!-- ANCHOR: {anchor_name} -->"}

    anchor_str = match.group(1)
    clean_content = new_content.strip()

    if clean_content in text:
        return {"success": True, "message": "Content already present under anchor", "anchor": anchor_name}

    replacement = f"{anchor_str}\n          {clean_content}"
    updated_text = text.replace(anchor_str, replacement, 1)
    html_path.write_text(updated_text, encoding="utf-8")
    return {"success": True, "message": "Content injected successfully while preserving anchor", "anchor": anchor_name}


def locate_verification_id(vid: str, remediation_path: Path, report_path: Path, checklist_path: Path) -> dict:
    """Mode 2 Fast-Path: Locates all records of a specific OWASP ID across HTML tracking files."""
    def _find_matches(fpath: Path):
        if not fpath.exists():
            return []
        lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
        return [{"line": i + 1, "text": ln.strip()} for i, ln in enumerate(lines) if vid in ln]

    return {
        "mode": "Mode 2 - Targeted Single-ID Verification",
        "requested_id": vid,
        "remediation_plan_records": _find_matches(remediation_path),
        "final_report_records": _find_matches(report_path),
        "checklist_records": _find_matches(checklist_path),
        "agent_instruction": (
            f"Surgically inspect the files referenced for {vid}, issue the verdict (PASS/PARTIAL/FAIL), "
            "and update the anchor rows and checkboxes without altering the HTML skeleton."
        ),
    }

