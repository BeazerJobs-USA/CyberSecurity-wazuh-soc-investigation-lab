# Real-Time FIM Lifecycle Demonstration Telemetry

## Overview

This directory contains the verified test execution records for **Case 002: Real-Time File Integrity Monitoring (FIM) Lifecycle Detection**.

The test was executed on the monitored Ubuntu endpoint (`vultr-security-lab`) using the automated test harness [`scripts/fim_demo.sh`](../../scripts/fim_demo.sh) to validate the custom Wazuh ruleset across all three file lifecycle states without disrupting operational SSH daemon settings.

---

## Provenance Policy: Lab Demo Telemetry

As defined in the [Evidence Integrity Policy](../README.md), all test output generated via `scripts/fim_demo.sh` is classified as **Lab Demo Telemetry** and maintained in this dedicated `evidence/demo/` directory to preserve strict separation from initial baseline observations in `evidence/observed/`.

---

## 1. Execution Timeline Record

The recorded execution log from [`fim_demo_timeline.txt`](fim_demo_timeline.txt):

```text
2026-10-14T02:15:10Z  CREATED  /etc/ssh/sshd_config.d/99-fim-demo.conf  (expect rule 100101)
2026-10-14T02:15:20Z  MODIFIED /etc/ssh/sshd_config.d/99-fim-demo.conf  (expect rule 100100)
2026-10-14T02:16:05Z  DELETED  /etc/ssh/sshd_config.d/99-fim-demo.conf  (expect rule 100102)
```

> [!NOTE]
> The Wazuh dashboard displays timestamps in the analyst browser's local time zone. The agent inotify logs and `scripts/fim_demo.sh` record events in UTC.

---

## 2. Verified Rule Lifecycle Events

### Step 1: File Creation (Rule 100101 — Level 7)
- **Target File:** `/etc/ssh/sshd_config.d/99-fim-demo.conf`
- **Action:** File created with comment `# FIM demonstration file.`
- **Triggered Parent:** Built-in syscheck rule `554` (File added to the system).
- **Triggered Child:** Custom rule `100101` (Severity Level 7).
- **Rendered Description:** `SSH configuration file added: /etc/ssh/sshd_config.d/99-fim-demo.conf`
- **Verification Status:** **VERIFIED**

### Step 2: File Modification (Rule 100100 — Level 8)
- **Target File:** `/etc/ssh/sshd_config.d/99-fim-demo.conf`
- **Action:** Appended second comment line with timestamp.
- **Triggered Parent:** Built-in syscheck rule `550` (Integrity checksum changed).
- **Triggered Child:** Custom rule `100100` (Severity Level 8).
- **Rendered Description:** `SSH configuration file modified: /etc/ssh/sshd_config.d/99-fim-demo.conf`
- **Diff Tracking:** Captured unified textual difference in `syscheck.diff`.
- **Verification Status:** **VERIFIED**

### Step 3: File Deletion (Rule 100102 — Level 7)
- **Target File:** `/etc/ssh/sshd_config.d/99-fim-demo.conf`
- **Action:** Cleanup via `sudo scripts/fim_demo.sh --cleanup`.
- **Triggered Parent:** Built-in syscheck rule `553` (File deleted).
- **Triggered Child:** Custom rule `100102` (Severity Level 7).
- **Rendered Description:** `SSH configuration file deleted: /etc/ssh/sshd_config.d/99-fim-demo.conf`
- **Verification Status:** **VERIFIED**

---

## 3. Key Technical Takeaway

Executing this full lifecycle test confirmed that:
1. The PCRE2 regular expression `^/etc/ssh/sshd_config($|\.d/.*)` correctly matches files within the drop-in directory `/etc/ssh/sshd_config.d/`.
2. The description variable template bug is resolved in ruleset v2, rendering the explicit path `$(file)` across all three alerts.
3. Drop-in configuration tampering is reliably alerted across creation, modification, and deletion events.
