# Detection Rules Changelog

## v2.1: Evidence Alignment and FIM Configuration Correction

- Corrected the repository FIM reference so real-time monitoring targets the directory `/etc/ssh` rather than an individual file. Custom rule path matching still limits Rules 100100–100102 to `/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d/*`.
- Reclassified Case 002 from **verified lifecycle detection** to **test executed, alert verification pending** because `fim_demo_timeline.txt` records the actions performed and the expected rule IDs but does not contain Wazuh alert records for Rules 100101 and 100102.
- Kept Rule 100100 as **observed** because the repository contains an authentic Wazuh Threat Hunting capture showing Rule 100100 firing at Level 8.
- Clarified that `scripts/lint_rules.py` is a repository linter and XML parser, not an XML schema validator. Native manager validation with `wazuh-analysisd -t` remains the authoritative deployment test.
- Added November 2026 authentication telemetry to the portfolio narrative: default Wazuh SSH rules 5710 and 5712, successful sudo activity, active Fail2Ban, and current UFW state.

## v2: Ruleset Expansion and Variable Refactoring

- **Status:** Authored and repository-linted. Full manager-side lifecycle validation is still pending evidence.
- Updated custom descriptions to use `$(file)` instead of the earlier `$(agent.name)` template.
- Rules:
  - `100100`: SSH configuration file modified, parent Rule 550, Level 8.
  - `100101`: SSH configuration file added, parent Rule 554, Level 7.
  - `100102`: SSH configuration file deleted, parent Rule 553, Level 7.
- **Observed root cause:** The original Rule 100100 capture rendered `SSH configuration file modified on ` with a blank variable. The v2 rules use the decoded FIM field `file`, which Wazuh supports in rule descriptions.
- **Repository QA:** `python3 scripts/lint_rules.py detections/local_rules.xml` checks XML parsing, local rule IDs, parent ID formatting, and risky description variables.
- **Required before claiming full deployment validation:**
  1. Run `sudo /var/ossec/bin/wazuh-analysisd -t` on the manager.
  2. Deploy/reload the rules.
  3. Run `scripts/fim_demo.sh`.
  4. Capture Wazuh alerts for create, modify, and delete, including Rule 100101 and Rule 100102.

## v1: Initial Detection Baseline

- `100100`: SSH configuration modified, parent Rule 550, Level 8 — **observed firing in the live lab on 14 Oct 2026 at 01:48:49**.
- `100101`: SSH configuration file added, parent Rule 554, Level 7 — authored.
- `100102`: SSH configuration file deleted, parent Rule 553, Level 7 — authored.
- Scope restricted by PCRE2 to the main OpenSSH configuration file and its drop-in directory.
