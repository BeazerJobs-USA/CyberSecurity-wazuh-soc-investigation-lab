# Detection Rules Changelog

## v2.2: Path scope tightened, rule rationale documented (November 2026)

**Status:** authored and repository-tested with `scripts/lint_rules.py`. Not yet validated with `wazuh-analysisd -t` and not yet observed firing. Deploy this version before the next FIM lifecycle test.

- **Path pattern changed** from `^/etc/ssh/sshd_config($|\.d/.*)` to `^/etc/ssh/sshd_config(\.d/[^/]+\.conf)?$`.
  - Why: Ubuntu's `sshd_config` loads drop-ins with `Include /etc/ssh/sshd_config.d/*.conf`, so only `*.conf` files there can change SSH behaviour. The v2 pattern matched *every* file in the drop-in directory, so editing a drop-in with vim (swap file `.name.conf.swp`) or `sed -i` (temp file) would have raised 100101/100102 alerts for files sshd never reads.
  - Coverage kept: the main `sshd_config` (which also holds the `Include` line) and every `*.conf` drop-in.
  - The linter now runs 11 path test cases per rule. The v2 pattern fails four of them (swap file, `~` backup, sed temp file, nested directory); v2.2 passes all of them.
- **Level rationale written down** in `local_rules.xml` (100100 one level above its parent 550; add/delete above the default "file added" level 5).
- **No ATT&CK mapping on purpose.** A configuration change is not a technique by itself. EV-02 confirms the custom rule carries no ATT&CK tag ("No results found" in the MITRE panel), and child rules do not inherit the parent's tags.
- **Linter fixes:** files with several top-level `<group>` blocks now parse; comma/space-separated `if_sid` lists are accepted; levels outside 0–16 are rejected; pcre2 patterns are compile-checked with Python `re` (an approximation, not PCRE2).

### Evidence corrections made in the same revision

- **EV-03 re-labelled.** Its 24-hour axis ends at about 00:57 and it contains only Level 3 events, so the Level 8 Rule 100100 alert (01:48:49) is not in it. It shows earlier sudo activity mentioning `sshd_config`, not context at the alert time.
- **Case 002 timeline cannot be matched to the current agent.** The timeline is in UTC (02:15–02:16Z on 14 Oct). The agent's registration time, shown in local time in EP-01, is 14 Oct 00:50:40 EDT = 04:50:40 UTC, which is after the test. The test has to be re-run against the current enrollment.
- **auditd removed as a "telemetry sensor"** from the graphics. No artifact shows auditd feeding Wazuh, or even its service state.

## v2.1: Evidence Alignment and FIM Configuration Correction

- Corrected the repository FIM reference so real-time monitoring targets the directory `/etc/ssh` rather than an individual file (Wazuh's syscheck reference: "Real time only works with directories, not individual files"). Custom rule path matching still limits Rules 100100–100102 to the OpenSSH config paths.
- Reclassified Case 002 from **verified lifecycle detection** to **test executed, alert verification pending** because `fim_demo_timeline.txt` records the actions performed and the expected rule IDs but contains no Wazuh alert records for Rules 100101 and 100102.
- Kept Rule 100100 as **observed** because the repository contains a Wazuh Threat Hunting capture showing Rule 100100 firing at Level 8.
- Clarified that `scripts/lint_rules.py` is a repository linter and XML parser, not a schema validator. Native manager validation with `wazuh-analysisd -t` remains the deployment test.
- Added November 2026 authentication telemetry to the narrative: default Wazuh SSH rules 5710 and 5712, sudo activity, and Fail2Ban.

## v2: Ruleset Expansion and Variable Refactoring

- **Status:** authored and repository-linted. Manager-side lifecycle validation still pending.
- Changed custom descriptions to use `$(file)` instead of the earlier `$(agent.name)` template.
- Rules:
  - `100100`: SSH configuration file modified, parent Rule 550, Level 8.
  - `100101`: SSH configuration file added, parent Rule 554, Level 7.
  - `100102`: SSH configuration file deleted, parent Rule 553, Level 7.
- **Observed symptom and likely cause:** the v1 Rule 100100 alert rendered `SSH configuration file modified on ` with nothing after "on" (EV-01). The most likely cause is that `agent.name` is not a decoded event field, so the `$(agent.name)` placeholder had nothing to substitute. `file` is a decoded FIM field, and Wazuh's own custom FIM examples use it. The fix is unconfirmed until a v2/v2.2 alert shows the path in its description.
- **Still required before claiming deployment validation:**
  1. Run `sudo /var/ossec/bin/wazuh-analysisd -t` on the manager.
  2. Deploy/reload the rules.
  3. Run `scripts/fim_demo.sh`.
  4. Capture Wazuh alerts for create, modify, and delete (Rules 100101, 100100, 100102).

## v1: Initial Detection Baseline

- `100100`: SSH configuration modified, reported parent Rule 550, Level 8 — **rule ID and level observed firing on 14 Oct 2026 at 01:48:49 (dashboard local time, EDT)**. The historical v1 rule file and expanded parent/path fields are not preserved, so the parent cannot be independently confirmed from EV-01.
- `100101`: SSH configuration file added, parent Rule 554, Level 7 — authored.
- `100102`: SSH configuration file deleted, parent Rule 553, Level 7 — authored.
- Scope restricted by PCRE2 to the main OpenSSH configuration file and its drop-in directory.
- The exact v1 rule text is not preserved in this repository. If it exists in git history, add it here.
