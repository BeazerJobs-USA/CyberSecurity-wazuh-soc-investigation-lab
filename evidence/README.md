# Technical Evidence Index and Provenance Record

## Evidence Integrity Policy

This repository separates **observed telemetry**, **scripted test execution**, and **planned validation**. A file is not labeled verified merely because a script expected an alert to occur.

### Evidence categories

- **Observed evidence**: screenshots or terminal captures produced by the live lab.
- **Test execution evidence**: records proving that a controlled test action was performed.
- **Pending verification**: a configuration, rule, or conclusion that still needs direct supporting output.
- **Reference configuration**: hardened or corrected examples that are not automatically treated as the current live configuration.

## 1. Case 001: Wazuh FIM SSH Configuration Change

| ID | Artifact | What it proves | What it does not prove |
|:---:|:---|:---|:---|
| EV 01 | `observed/01_rule100100_events_view.png` | Rule 100100 fired once at Level 8 for `vultr-security-lab` | Exact changed directive, actor, or authorization |
| EV 02 | `observed/02_rule100100_dashboard_view.png` | One Rule 100100 alert in the filtered one hour view | Absence of host wide authentication failures |
| EV 03 | `observed/03_sshd_config_search_24h.png` | 19 Level 3 sudo related events were returned by the search | That all 19 events were benign or tied to the Rule 100100 event |

## 2. Case 002: Safe FIM Lifecycle Test

`demo/fim_demo_timeline.txt` records controlled create, modify, and delete actions against:

`/etc/ssh/sshd_config.d/99-fim-demo.conf`

The file contains **expected** custom rule IDs. It does not contain Wazuh alert records. Therefore:

| Action | Expected rule | Current evidence status |
|:---|:---:|:---|
| Create | 100101 | Test action recorded; Wazuh alert capture pending |
| Modify | 100100 | Test action recorded; v2 alert capture pending |
| Delete | 100102 | Test action recorded; Wazuh alert capture pending |

See `demo/README.md` for the verification checklist.

## 3. Case 003: SSH Authentication Attack Investigation

New November 2026 captures document real unsolicited SSH authentication activity and defensive response on the lab endpoint.

| ID | Artifact | Observed evidence |
|:---:|:---|:---|
| AUTH 01 | endpoint state capture | Current endpoint, Wazuh agent, and active security services |
| AUTH 02 | sudo events capture | Successful sudo to root events in Wazuh |
| AUTH 03 | Rule 5710 capture | Multiple attempts to authenticate with non existent users |
| AUTH 04 | Rule 5712 capture | Wazuh correlated brute force activity against non existent users |
| AUTH 05 | Fail2Ban capture | Active sshd jail with cumulative failed attempts and bans |
| AUTH 06 | host auth log capture | Raw SSH failures, accepted administrative public key login, and sudo context |

These artifacts support the conclusion that the public SSH service is receiving unsolicited authentication attempts and that Wazuh and Fail2Ban are observing/responding to that activity. They do **not** prove successful compromise.

## Sanitization and Publication Rules

Before publishing a new screenshot:

1. Mask private manager hostnames and private/Tailscale addresses that identify the lab control plane.
2. Preserve timestamps, rule IDs, levels, event descriptions, and counts unless there is a privacy reason to redact them.
3. Do not alter evidence to make an event look more severe or complete than it was.
4. Keep test generated telemetry clearly separated from unsolicited observed telemetry.
5. Record the query scope when dashboard counters are shown.

This evidence policy is intentionally conservative so that every portfolio claim can survive technical interview scrutiny.
