#!/usr/bin/env python3
"""Lint a Wazuh local_rules.xml before deploying it.

Checks structure and common mistakes only. The authoritative test is the
manager's own rule loader:

    sudo /var/ossec/bin/wazuh-analysisd -t

Usage: python3 scripts/lint_rules.py [path/to/local_rules.xml]
Exit code 0 = no errors (warnings allowed), 1 = errors found.
"""
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

LOCAL_RANGE = range(100000, 120001)
VAR = re.compile(r"\$\(([^)]+)\)")

path = Path(sys.argv[1] if len(sys.argv) > 1 else "detections/local_rules.xml")
errors, warnings = [], []

try:
    root = ET.parse(path).getroot()
except (ET.ParseError, FileNotFoundError) as exc:
    print(f"ERROR: cannot parse {path}: {exc}")
    sys.exit(1)

seen = {}
for rule in root.iter("rule"):
    rid = rule.attrib.get("id", "")
    label = f"rule {rid or '<no id>'}"

    if not rid.isdigit():
        errors.append(f"{label}: id is missing or not numeric")
        continue
    if int(rid) not in LOCAL_RANGE:
        errors.append(f"{label}: id outside the 100000-120000 local range")
    if rid in seen:
        errors.append(f"{label}: duplicate id")
    seen[rid] = True

    if not rule.attrib.get("level", "").isdigit():
        errors.append(f"{label}: level is missing or not numeric")

    desc = rule.findtext("description")
    if not desc or not desc.strip():
        errors.append(f"{label}: missing description")
    else:
        for var in VAR.findall(desc):
            if var.startswith(("agent.", "manager.")):
                warnings.append(
                    f"{label}: description uses $({var}); this was observed to render "
                    f"empty in this lab (see detections/CHANGELOG.md). Use a decoded field such as $(file)."
                )

    for sid in rule.findall("if_sid"):
        if not (sid.text or "").strip().isdigit():
            errors.append(f"{label}: if_sid is not numeric: {sid.text!r}")

print(f"Parsed {path}: {len(seen)} rule(s): {', '.join(seen) or 'none'}")
for w in warnings:
    print(f"WARN : {w}")
for e in errors:
    print(f"ERROR: {e}")
print("Reminder: run 'sudo /var/ossec/bin/wazuh-analysisd -t' on the manager before restarting it.")
sys.exit(1 if errors else 0)
