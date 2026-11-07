# Detection Rules Changelog

## v2: Ruleset Expansion & Variable Refactoring (Status: Tested & Verified via Case 002 FIM Lifecycle)

- **Change:** All three custom FIM rule descriptions updated to use `$(file)` instead of `$(agent.name)`, and ruleset expanded to cover the complete file lifecycle:
  - `100100`: SSH configuration file modified (Parent: Rule 550, Severity Level 8)
  - `100101`: SSH configuration file added (Parent: Rule 554, Severity Level 7)
  - `100102`: SSH configuration file deleted (Parent: Rule 553, Severity Level 7)
- **Root Cause & Justification:** In the initial lab alert for Rule `100100` (captured in `evidence/observed/01_rule100100_events_view.png`), the rule description rendered as `"SSH configuration file modified on "` with trailing empty space. Analysis revealed that `agent.name` is not an extracted variable in Wazuh rule descriptions, causing it to expand to an empty string. Wazuh documentation specifies `file` as the decoded syscheck field for custom FIM rules, allowing the alert to explicitly specify the modified target path (`$(file)`).
- **Validation & Testing:**
  1. **Schema & Syntax:** Validated XML structure, parent IDs, and variable formatting via `python3 scripts/lint_rules.py` (0 errors, 0 warnings).
  2. **In-Lab Lifecycle Verification:** Tested on `vultr-security-lab` using [`scripts/fim_demo.sh`](../scripts/fim_demo.sh). Verified real-time firing of Create (`100101`), Modify (`100100`), and Delete (`100102`) events for drop-in configuration file `/etc/ssh/sshd_config.d/99-fim-demo.conf` (recorded in [`evidence/demo/fim_demo_timeline.txt`](../evidence/demo/fim_demo_timeline.txt)).

## v1: Initial Detection Baseline (Status: Observed Firing in Case 001)

- **Rules Introduced:**
  - `100100`: SSH configuration modified (Parent: Rule 550, Severity Level 8) — **Fired in live lab (14 Oct 2026, 01:48:49) [VERIFIED]**
  - `100101`: SSH configuration file added (Parent: Rule 554, Severity Level 7) — **Authored in baseline**
  - `100102`: SSH configuration file deleted (Parent: Rule 553, Severity Level 7) — **Authored in baseline**
- **Scope:** Restricted via PCRE2 regular expression to `/etc/ssh/sshd_config` and drop-in configurations `/etc/ssh/sshd_config.d/*`.
- **Severity Tuning:** Severity levels established by operational impact (Level 8 warrants immediate analyst review; Level 7 flags file creation/deletion).
