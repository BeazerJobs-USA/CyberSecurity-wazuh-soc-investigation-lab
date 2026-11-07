# Case 002: Real-Time File Integrity Monitoring (FIM) Lifecycle Detection

## Executive Summary

| Attribute | Investigation Details |
|:---|:---|
| **Incident Title** | FIM Lifecycle Testing: Create, Modify, and Delete Event Detection |
| **Monitored Asset** | `vultr-security-lab` (Ubuntu 22.04 LTS Cloud Workload) |
| **Telemetry Transport** | Tailscale Encrypted Mesh VPN to AWS Wazuh SIEM |
| **Detection Mechanism** | Wazuh File Integrity Monitoring (`syscheck`) + Ruleset v2 (Rules 100100, 100101, 100102) |
| **Target Directory** | Drop-in configuration directory `/etc/ssh/sshd_config.d/` |
| **Test Harness** | Automated safe drop-in script [`scripts/fim_demo.sh`](../scripts/fim_demo.sh) |
| **Verification Status** | **VERIFIED** — Successfully generated and verified Create, Modify, and Delete alert records |

---

## 1. Context & Detection Engineering Objectives

In modern Linux distributions such as Ubuntu 22.04 LTS, the OpenSSH server evaluates configuration drop-in files included from `/etc/ssh/sshd_config.d/*.conf`. Because OpenSSH follows **first-value-wins** parsing order, creating, editing, or removing drop-in configuration files directly affects the active authentication surface without requiring alterations to `/etc/ssh/sshd_config`.

The objective of Case 002 was to test and verify the complete real-time FIM detection lifecycle:
1. **Creation:** Detect when a new drop-in configuration file is added.
2. **Modification:** Detect when a drop-in file is edited, capturing textual change diffs.
3. **Deletion:** Detect when a drop-in file is removed.

---

## 2. Test Execution & Automated Harness

To validate detection without risking administrative lockout or altering active SSH security policies, the test harness [`scripts/fim_demo.sh`](../scripts/fim_demo.sh) was executed on `vultr-security-lab`:

- **Drop-In Filename:** `99-fim-demo.conf` (lexically ordered last to ensure it cannot override earlier configuration values).
- **Content:** Comment-only syntax (`# FIM demonstration file`).
- **Daemon Impact:** Zero SSH daemon reloads or restarts required.

### Recorded Execution Timeline

From [`evidence/demo/fim_demo_timeline.txt`](../evidence/demo/fim_demo_timeline.txt):

```text
2026-10-14T02:15:10Z  CREATED  /etc/ssh/sshd_config.d/99-fim-demo.conf  (expect rule 100101)
2026-10-14T02:15:20Z  MODIFIED /etc/ssh/sshd_config.d/99-fim-demo.conf  (expect rule 100100)
2026-10-14T02:16:05Z  DELETED  /etc/ssh/sshd_config.d/99-fim-demo.conf  (expect rule 100102)
```

---

## 3. Verified Detection Logic & Lifecycle Results

```
[File Created: 99-fim-demo.conf]  ---> syscheck 554 ---> Rule 100101 Fired (Level 7) [VERIFIED]
                 │ (10s delay)
[File Modified: Comment Added]    ---> syscheck 550 ---> Rule 100100 Fired (Level 8) [VERIFIED]
                 │ (45s delay)
[File Deleted: Cleanup Executed]  ---> syscheck 553 ---> Rule 100102 Fired (Level 7) [VERIFIED]
```

### Event 1: File Creation (Rule 100101)
- **Parent Rule:** `554` (File added to the system).
- **Matching Child:** Rule `100101` (Severity Level 7).
- **Regex Filter:** `^/etc/ssh/sshd_config($|\.d/.*)` matching `file` field.
- **Rendered Output:** `SSH configuration file added: /etc/ssh/sshd_config.d/99-fim-demo.conf`
- **Result:** Successfully validated; drop-in file creation surfaced immediately.

### Event 2: File Modification (Rule 100100)
- **Parent Rule:** `550` (Integrity checksum changed).
- **Matching Child:** Rule `100100` (Severity Level 8).
- **Diff Tracking:** Captured differential in `syscheck.diff` showing appended comment.
- **Rendered Output:** `SSH configuration file modified: /etc/ssh/sshd_config.d/99-fim-demo.conf`
- **Result:** Validated `$(file)` variable substitution, resolving the template bug identified in Case 001.

### Event 3: File Deletion (Rule 100102)
- **Parent Rule:** `553` (File deleted).
- **Matching Child:** Rule `100102` (Severity Level 7).
- **Rendered Output:** `SSH configuration file deleted: /etc/ssh/sshd_config.d/99-fim-demo.conf`
- **Result:** Validated cleanup detection upon execution of `sudo scripts/fim_demo.sh --cleanup`.

---

## 4. Comparing Detection Approaches: Auditd vs. Real-Time FIM

This lab implements a defense-in-depth approach by combining both Auditd and FIM mechanisms:

| Capability | Case 001: Auditd Detection | Case 002: Real-Time FIM (syscheck) |
|:---|:---|:---|
| **Mechanism** | Linux Kernel Audit Subsystem (`auditd`) | Inotify Filesystem Event Monitor (`syscheck`) |
| **Primary Strength** | Captures execution context, syscalls, and user identity | Captures exact textual diffs, hash transitions, and file attributes |
| **Alert Trigger** | Command execution & filesystem write syscalls | File modification, creation, or deletion events |
| **Network Transit** | Encrypted over Tailscale to AWS Wazuh SIEM | Encrypted over Tailscale to AWS Wazuh SIEM |
| **Operational Value** | Answers **WHO** executed the change and **WHAT COMMAND** was run | Answers **WHAT EXACT DIRECTIVE** changed and **WHAT FILE** was affected |

---

## 5. Conclusion & Operational Impact

The Case 002 verification confirmed that custom ruleset v2 reliably detects tampering across the complete file lifecycle in OpenSSH drop-in directories. Combining inotify FIM with auditd event logging provides the SOC analyst with both the content change diff and the execution context needed for rapid incident triage.
