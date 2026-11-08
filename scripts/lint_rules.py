#!/usr/bin/env python3
"""Lint a Wazuh local_rules.xml before deploying it.

Repository-side checks only:
  - the file parses as XML (several top-level <group> blocks are allowed,
    as in real Wazuh rule files)
  - each rule has a numeric id in the 100000-120000 local range, no duplicates
  - level is an integer from 0 to 16
  - each rule has a description; warns on $(agent.*) / $(manager.*) variables,
    which rendered empty in this lab (see detections/CHANGELOG.md)
  - if_sid holds rule IDs (comma- or space-separated lists are allowed)
  - pcre2 <field> patterns compile with Python's re module. This is only an
    approximation: Python re is not PCRE2, so passing here does not prove the
    manager will accept the pattern.
  - path tests: the OpenSSH path pattern in rules 100100-100102 matches the files
    sshd actually loads and ignores editor/backup/temp files (PATH_CASES).

It does NOT replace the manager's own loader:

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
PATH_RULES = {"100100", "100101", "100102"}

# (path, should_match). sshd loads /etc/ssh/sshd_config and, through Ubuntu's
# "Include /etc/ssh/sshd_config.d/*.conf", only *.conf files in the drop-in dir.
PATH_CASES = [
    ("/etc/ssh/sshd_config", True),
    ("/etc/ssh/sshd_config.d/50-cloud-init.conf", True),
    ("/etc/ssh/sshd_config.d/99-fim-demo.conf", True),
    ("/etc/ssh/ssh_config", False),                            # client config
    ("/etc/ssh/sshd_config.bak", False),
    ("/etc/ssh/sshd_config.dpkg-old", False),
    ("/etc/ssh/sshd_config.d", False),                         # the directory itself
    ("/etc/ssh/sshd_config.d/.50-cloud-init.conf.swp", False), # vim swap file
    ("/etc/ssh/sshd_config.d/50-cloud-init.conf~", False),     # editor backup
    ("/etc/ssh/sshd_config.d/sedAbC123", False),               # sed -i temp file
    ("/etc/ssh/sshd_config.d/sub/x.conf", False),              # not loaded by sshd
]


def load(path: Path) -> ET.Element:
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)
    # Wrap so that files with several top-level <group> blocks still parse.
    return ET.fromstring(f"<lint_root>{text}</lint_root>")


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "detections/local_rules.xml")
    errors, warnings = [], []

    try:
        root = load(path)
    except (ET.ParseError, FileNotFoundError, UnicodeDecodeError) as exc:
        print(f"ERROR: cannot parse {path}: {exc}")
        return 1

    seen = []
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
        seen.append(rid)

        level = rule.attrib.get("level", "")
        if not level.isdigit() or not 0 <= int(level) <= 16:
            errors.append(f"{label}: level must be an integer from 0 to 16 (got {level!r})")

        desc = rule.findtext("description")
        if not desc or not desc.strip():
            errors.append(f"{label}: missing description")
        else:
            for var in VAR.findall(desc):
                if var.startswith(("agent.", "manager.")):
                    warnings.append(
                        f"{label}: description uses $({var}); this rendered empty in this lab "
                        f"(see detections/CHANGELOG.md). Use a decoded field such as $(file)."
                    )

        for sid in rule.findall("if_sid"):
            ids = [s for s in re.split(r"[,\s]+", (sid.text or "").strip()) if s]
            if not ids or not all(s.isdigit() for s in ids):
                errors.append(f"{label}: if_sid must list rule IDs: {sid.text!r}")

        for field in rule.findall("field"):
            if field.attrib.get("type") != "pcre2":
                continue
            pattern = field.text or ""
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                warnings.append(f"{label}: pcre2 pattern did not compile in Python re ({exc}); "
                                f"check it with wazuh-analysisd -t")
                continue
            if rid in PATH_RULES and field.attrib.get("name") == "file":
                for test_path, expected in PATH_CASES:
                    if bool(compiled.search(test_path)) != expected:
                        want = "match" if expected else "NOT match"
                        errors.append(f"{label}: path pattern should {want} {test_path}")

    missing = PATH_RULES - set(seen)
    if missing:
        warnings.append(f"expected OpenSSH rules not found: {', '.join(sorted(missing))}")

    print(f"Parsed {path}: {len(seen)} rule(s): {', '.join(seen) or 'none'}")
    print(f"Path tests: {len(PATH_CASES)} case(s) per OpenSSH rule")
    for w in warnings:
        print(f"WARN : {w}")
    for e in errors:
        print(f"ERROR: {e}")
    print("Reminder: run 'sudo /var/ossec/bin/wazuh-analysisd -t' on the manager before restarting it.")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
