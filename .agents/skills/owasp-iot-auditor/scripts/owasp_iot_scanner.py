#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OWASP IoT & Embedded Security Auditor — Base CLI Router
Lightweight entrypoint that dispatches flags to specialized modules in `scripts/modules/`:
- modules/tool_installer.py    -> --check-tools, --install-tools
- modules/html_manager.py      -> --init-*, --inject-*, --verify-id
- modules/native_scanner.py    -> Mode 1.1 Standard Fast Audit
- modules/sast_orchestrator.py -> Mode 1.2 Deep Hybrid Audit (--deep-scan / --full-power)
"""

import argparse
import json
from pathlib import Path

from modules.html_manager import (
    check_checklist_progress,
    inject_into_html_anchor,
    initialize_templates,
    locate_verification_id,
)
from modules.native_scanner import classify_section_6_1, scan_project_tree
from modules.sast_orchestrator import run_deep_sast_suite
from modules.tool_installer import check_all_tools, install_missing_tools


def main():
    parser = argparse.ArgumentParser(description="OWASP IoT & Embedded Security Auditor — Base CLI Router")
    parser.add_argument("--target", default=".", help="Root directory of the embedded/IoT project to scan")
    parser.add_argument("--checklist", default="owasp_iot_progress_checklist.html", help="Progress checklist HTML file")
    parser.add_argument("--report", default="owasp_iot_final_report.html", help="Final audit report HTML file")
    parser.add_argument("--remediation", default="owasp_iot_remediation_plan.html", help="Remediation plan HTML file")

    # Mode 1.2 External SAST Tooling Flags
    parser.add_argument("--check-tools", action="store_true", help="Mode 1.2 Pre-Flight: Check which of the 6 SAST tools are installed")
    parser.add_argument("--install-tools", default="", help="Mode 1.2 Installer: Install missing tools ('all' or comma-separated list)")
    parser.add_argument("--deep-scan", "--full-power", dest="deep_scan", action="store_true", help="Mode 1.2: Run Native Audit + all 6 SAST/SCA/Binary tools")

    # Mode 2 Targeted Re-Verification Flag
    parser.add_argument("--verify-id", default="", help="Mode 2: Locate all records for a specific OWASP ID")

    # HTML Template Initialization & Safe Anchor Injection Flags
    parser.add_argument("--init-checklist", action="store_true", help="Initialize static HTML progress checklist")
    parser.add_argument("--init-remediation", action="store_true", help="Initialize static HTML remediation plan")
    parser.add_argument("--init-report", action="store_true", help="Initialize static HTML final report")
    parser.add_argument("--init-all", action="store_true", help="Initialize all 3 static HTML tracking files")
    parser.add_argument("--inject-target", choices=["report", "remediation", "checklist"], help="Target HTML file for safe anchor injection")
    parser.add_argument("--inject-anchor", default="", help="Anchor name (e.g., INSERT_FAIL_ROWS_HERE)")
    parser.add_argument("--inject-content", default="", help="HTML string to inject below the anchor")
    parser.add_argument("--inject-content-file", default="", help="File containing HTML snippet to inject")
    args = parser.parse_args()

    # 1. Mode 1.2 Tool Check / Installation Dispatcher
    if args.check_tools:
        print(json.dumps(check_all_tools(), indent=2, ensure_ascii=False))
        return

    if args.install_tools.strip():
        print(json.dumps(install_missing_tools(args.install_tools.strip()), indent=2, ensure_ascii=False))
        return

    target_dir = Path(args.target).resolve()
    checklist_path = target_dir / args.checklist
    report_path = target_dir / args.report
    remediation_path = target_dir / args.remediation
    resources_dir = Path(__file__).resolve().parent.parent / "resources"

    # 2. Safe Anchor Injection Dispatcher
    if args.inject_anchor.strip():
        target_map = {"report": report_path, "remediation": remediation_path, "checklist": checklist_path}
        dest_file = target_map.get(args.inject_target, report_path)
        content_to_inject = args.inject_content
        if args.inject_content_file and Path(args.inject_content_file).exists():
            content_to_inject = Path(args.inject_content_file).read_text(encoding="utf-8")
        res = inject_into_html_anchor(dest_file, args.inject_anchor.strip(), content_to_inject)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return

    # 3. HTML Template Initialization Dispatcher
    initialized_files = initialize_templates(
        target_dir=target_dir,
        resources_dir=resources_dir,
        do_checklist=(args.init_checklist or args.init_all),
        do_report=(args.init_report or args.init_all),
        do_remediation=(args.init_remediation or args.init_all),
        checklist_path=checklist_path,
        report_path=report_path,
        remediation_path=remediation_path,
    )

    # 4. Mode 2 Targeted ID Locator Dispatcher
    if args.verify_id.strip():
        res = locate_verification_id(args.verify_id.strip(), remediation_path, report_path, checklist_path)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return

    # 5. Mode 1.1 (Native Audit) & Mode 1.2 (Deep Hybrid Audit) Dispatcher
    inventory, checks_6_2 = scan_project_tree(target_dir)
    classification = classify_section_6_1(inventory)
    progress = check_checklist_progress(checklist_path)

    sast_telemetry = None
    if args.deep_scan:
        checks_6_2, sast_telemetry = run_deep_sast_suite(target_dir, inventory, checks_6_2, resources_dir)

    report_output = {
        "execution_mode": "Mode 1.2 - Deep Hybrid Audit (Native + External SAST)" if args.deep_scan else "Mode 1.1 - Standard Fast Native Audit",
        "step_1_general_discovery": inventory,
        "step_2_section_6_1_classification": classification,
        "step_3_checklist_state": progress,
        "step_4_section_6_2_triage": checks_6_2,
        "initialized_files": initialized_files,
    }
    if sast_telemetry is not None:
        report_output["step_4b_external_sast_telemetry"] = sast_telemetry

    print(json.dumps(report_output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
