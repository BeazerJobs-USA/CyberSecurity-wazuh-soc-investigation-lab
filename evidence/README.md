# Technical Evidence Index & Provenance Record

## Evidence Integrity Policy

Every artifact within this repository represents authentic telemetry collected from the running cybersecurity lab. To uphold strict forensic and analytical integrity, evidence is categorized into two distinct catalogs:

- **Observed Baseline Evidence (`evidence/observed/`):** Authentic telemetry captured during live cloud server monitoring and alert triage for **Case 001 (Auditd SSH Detection)**.
- **Demonstration Telemetry (`evidence/demo/`):** Scripted lifecycle verification events generated via `scripts/fim_demo.sh` for **Case 002 (Real-Time FIM Lifecycle)**, explicitly segregated to maintain provenance.

---

## 1. Case 001: Observed Evidence Catalog (Auditd-Based Detection)

| Evidence ID | File Path | Dashboard Interface | Query / Filter Applied | Captured Telemetry | Analytical Significance |
|:---:|:---|:---|:---|:---|:---|
| **EV-01** | [`observed/01_rule100100_events_view.png`](observed/01_rule100100_events_view.png) | **Threat Hunting > Events** | `rule.id: 100100`<br>`agent.name: vultr-security-lab` | 1 hit @ 01:48:49<br>Level 8 alert<br>`vultr-security-lab` | Confirms working detection of SSH configuration modification on the Vultr endpoint. Identified template variable bug where `$(agent.name)` rendered empty, prompting the v2 `$(file)` refactoring. |
| **EV-02** | [`observed/02_rule100100_dashboard_view.png`](observed/02_rule100100_dashboard_view.png) | **Threat Hunting > Dashboard** | `rule.id: 100100`<br>`agent.name: vultr-security-lab` | 1 Total alert<br>0 Level 12+ alerts<br>0 Auth failures (filtered view)<br>No ATT&CK tags | Confirms alert isolation in the 1-hour window. Note: the 0 authentication failures metric is limited specifically to this rule 100100 filter and does not prove absence of other auth failures across the host. Shows no ATT&CK tag mapped to Rule 100100. |
| **EV-03** | [`observed/03_sshd_config_search_24h.png`](observed/03_sshd_config_search_24h.png) | **Threat Hunting > Dashboard** | Free-text search:<br>`sshd_config` (24h) | 19 Total events<br>All Level 3<br>MITRE: T1548.003 | Shows 19 historical events classified at Level 3 under MITRE `T1548.003 (Sudo and Sudo Caching)` by Wazuh's default sudo decoder, reflecting administrative command activity during host setup. |

---

## 2. Case 002: FIM Lifecycle Evidence Catalog (Create, Modify, Delete)

| Evidence ID | File Path | Telemetry Trigger | Target Path | Rule Fired | Analytical Significance |
|:---:|:---|:---|:---|:---:|:---|
| **DEMO-01** | [`demo/fim_demo_timeline.txt`](demo/fim_demo_timeline.txt)<br>line 1 | File Creation | `/etc/ssh/sshd_config.d/99-fim-demo.conf` | **Rule 100101**<br>(Level 7) | Verifies real-time detection of drop-in file addition. Child of built-in FIM rule 554. Validated with `$(file)` path rendering. |
| **DEMO-02** | [`demo/fim_demo_timeline.txt`](demo/fim_demo_timeline.txt)<br>line 2 | File Modification | `/etc/ssh/sshd_config.d/99-fim-demo.conf` | **Rule 100100**<br>(Level 8) | Verifies real-time detection of drop-in file modification with text change differential. Child of built-in FIM rule 550. |
| **DEMO-03** | [`demo/fim_demo_timeline.txt`](demo/fim_demo_timeline.txt)<br>line 3 | File Deletion | `/etc/ssh/sshd_config.d/99-fim-demo.conf` | **Rule 100102**<br>(Level 7) | Verifies real-time detection of drop-in file deletion during cleanup. Child of built-in FIM rule 553. |

*Detailed lifecycle documentation is available in [`evidence/demo/README.md`](demo/README.md).*

---

## Sanitization & Privacy Controls

To uphold security best practices and prevent unintentional credential or infrastructure leakage:
1. **Private Network Information Masked:** Browser address bar showing private network IP ranges has been cropped from Screenshot 03.
2. **Manager Hostname Masked:** Internal cloud manager hostname (`ip-172-...`) is sanitized with a solid black redaction box across all three captures.
3. **Telemetry Integrity Preserved:** All timestamps, rule IDs, event counts, severity levels, and agent identifiers remain 100% unaltered.
