# -*- coding: utf-8 -*-
"""
Modular backend package for the OWASP IoT & Embedded Security Auditor CLI Router.
Modules:
- html_manager: Static HTML initialization, anchor injection, checklist progress, and Mode 2 ID lookup.
- native_scanner: High-speed single-pass os.scandir discovery, Section 6.1 classification, and native regex triage.
- sast_orchestrator: Mode 1.2 external SAST/SCA/Binary execution and OWASP finding normalization.
- tool_installer: External SAST tool readiness checker (--check-tools) and automated installer (--install-tools).
- taint_analyzer: FirmAgent-inspired intraprocedural Source-to-Sink IoT taint analysis.
- firmware_inspector: IoTwizz-inspired firmware binary entropy, magic signatures, and secret extraction.
"""

