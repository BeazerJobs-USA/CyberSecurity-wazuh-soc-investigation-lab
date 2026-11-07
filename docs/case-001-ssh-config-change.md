# Case 001: Auditd-Based SSH Configuration Change Detection

## Executive Summary

| Attribute | Investigation Details |
|:---|:---|
| **Incident Title** | Auditd Alert: OpenSSH Server Configuration Modification Detected |
| **Monitored Asset** | `vultr-security-lab` (Ubuntu 22.04 LTS Cloud Workload on Vultr) |
| **Telemetry Transport** | Tailscale Encrypted Mesh VPN to AWS Wazuh SIEM |
| **Detection Mechanism** | Linux `auditd` Subsystem + Wazuh SIEM Manager Rule `100100` |
| **Alert Timestamp** | 14 Oct 2026, 01:48:49 (Dashboard Local Time) |
| **Alert Level** | Level 8 (Operational Warning / Configuration Modification) |
| **Investigation Status** | **Working In-Lab Detection Verified; Host Terminal Correlation Pending** |
| **Disposition** | **Disposition Pending Supporting Evidence** — Alert generation, Tailscale transmission, and dashboard metrics verified by in-lab captures. Final administrative disposition requires host-level auth log correlation and runtime `sshd -T` verification. |

---

## 1. Threat Context & Architecture

The OpenSSH daemon controls remote administrative access to Linux cloud workloads. Alterations to `sshd_config` or its drop-in directory `/etc/ssh/sshd_config.d/` represent high-risk events that can expose hosts to unauthorized access, weakened ciphers, root login exposure, or credential compromise.

### Network Architecture: Vultr to AWS over Tailscale
In this environment:
1. **Endpoint Workload:** Hosted on **Vultr** (`vultr-security-lab`), running Ubuntu 22.04 LTS, OpenSSH server, Wazuh Agent, and the Linux `auditd` subsystem.
2. **Overlay Mesh VPN:** A private **Tailscale** network connects the Vultr cloud host directly to the SIEM, encrypting all agent telemetry in transit across cloud boundaries.
3. **Dedicated SIEM:** Hosted on **AWS EC2**, running Wazuh Manager 4.x and the Threat Hunting dashboard.

```
[Vultr Cloud Server: vultr-security-lab]
       │ (Linux auditd watcher on /etc/ssh/sshd_config)
       ▼
  Wazuh Agent
       │
       ▼ [Encrypted Point-to-Point Overlay: Tailscale Mesh VPN]
       ▼
[AWS Cloud: Dedicated Wazuh SIEM (Manager & Threat Hunting Dashboard)]
       │
       ▼
  Rule 100100 Alert (Level 8) Triggered at 01:48:49
```

---

## 2. Detection Mechanism: Linux Auditd Integration

Rule 100100 operates as the working detection mechanism for OpenSSH server configuration changes, capturing events generated when administrative utilities or processes access and modify the configuration files:

- **Subsystem:** Linux `auditd` audit watcher configured for write and attribute modification events (`-w /etc/ssh/sshd_config -p wa -k ssh_config_changes`).
- **Telemetry Processing:** Ingested by the local Wazuh agent and forwarded across the Tailscale mesh to the AWS Wazuh manager.
- **Rule Matching:** Evaluated against `local_rules.xml` on the AWS manager, firing Rule `100100` at **Level 8**.

> **Note on Alert Level:** In Wazuh, Level 8 represents an operational warning or high-priority configuration change notification. It indicates that administrative or unauthorized configuration tampering occurred, warranting interactive analyst triage.

---

## 3. Observed Evidence (Direct In-Lab Captures)

The working detection is documented by three authentic captures from the AWS Wazuh dashboard:

### Evidence 01: Threat Hunting Events View (Rule 100100)
- **Path:** `evidence/observed/01_rule100100_events_view.png`
- **Query Filter:** `rule.id: 100100` AND `agent.name: vultr-security-lab`
- **Observed Data:** Exactly 1 hit observed at 01:48:49. Alert fields capture agent name `vultr-security-lab`, rule ID `100100`, and severity Level 8.
- **Template Bug Discovery:** The rule description displayed `"SSH configuration file modified on "` with trailing empty space. Root-cause analysis revealed that `agent.name` is not an extracted variable in Wazuh rule descriptions, causing it to expand to null. This prompted the v2 refactoring to `$(file)`.

### Evidence 02: Threat Hunting Dashboard Metrics View
- **Path:** `evidence/observed/02_rule100100_dashboard_view.png`
- **Observed Metrics:** Confirms 1 Total alert in the 1-hour window. Dashboard widgets display:
  - `1` Total Alert (Rule 100100 at Level 8)
  - `0` Level 12 or above alerts
  - `0` Authentication failure events (Under query `rule.id:100100`)
  - `0` Authentication success events (Under query `rule.id:100100`)
  - `Top 10 MITRE ATT&CKS: No results found` (confirming no unverified ATT&CK tags attached).

> [!IMPORTANT]
> **Authentication Failure Metric Scope:**
> No authentication failure events were displayed in the reviewed dashboard view filtered to rule ID 100100. This observation is limited to that specific rule and query scope and does not establish the absence of other authentication failures or brute-force activity across the monitored host.

### Evidence 03: 24-Hour Contextual Free-Text Search
- **Path:** `evidence/observed/03_sshd_config_search_24h.png`
- **Query:** `sshd_config` across a 24-hour window
- **Observed Data:** Returned 19 total events, all classified at Level 3. The dashboard ATT&CK widget categorized these under technique `T1548.003 - Sudo and Sudo Caching`.
- **Contextual Significance:** These events correspond to Wazuh's default decoder matching routine administrative `sudo` command executions. The technique tag classifies the administrative elevation mechanism; it does not indicate malicious exploitation.

---

## 4. SOC Investigation Record & Verification Matrix

To maintain defensibility during technical interviews, the investigation record clearly distinguishes verified telemetry from host-level evidence requirements:

| # | Investigation Step | Verification Method | Status | Evidence Required for Verification |
|:---|:---|:---|:---:|:---|
| **1** | **Identify File & Target Directives** | Expanded alert JSON in Wazuh dashboard | **Pending Evidence** | Expanded alert JSON or raw log export showing specific directives modified. |
| **2** | **Correlate Actor & Process** | Audit active sessions & `auth.log`: `sudo grep -E 'COMMAND=.*sshd_config' /var/log/auth.log*` | **Pending Evidence** | Terminal output from `/var/log/auth.log` identifying the operator username, command line, and concurrent login session. |
| **3** | **Validate Change Authorization** | Compare timestamp against operator notes | **Pending Evidence** | Documented maintenance confirmation matching the 01:48:49 timestamp. |
| **4** | **Audit Effective SSH Posture** | Run `sudo sshd -T` and `sudo sshd -t` on host | **Pending Evidence** | Live command output from `sudo sshd -t` (syntax check) and `sudo sshd -T` confirming runtime parameters. |
| **5** | **Review Host Authentication Scope** | Query broader auth logs: `sudo journalctl -u ssh` | **Pending Evidence** | Host-level authentication logs spanning the 24-hour window to establish whether failed logins occurred outside the rule 100100 filter. |
| **6** | **Triage 24-Hour Context Events** | Audit 19 search events in Threat Hunting | **VERIFIED** | Screenshot 03 confirms 19 Level 3 events associated with `T1548.003 (Sudo and Sudo Caching)`, reflecting routine sudo executions. |

---

## 5. Containment & Remediation Playbook

In the event that an SSH configuration modification alert is determined to be unauthorized or anomalous, the following containment protocol is established:

1. **Preserve Volatile Evidence:** Do not terminate the active administrative terminal session. Export Wazuh alert JSON, captured diffs, and host memory/process state.
2. **Revert Configuration:** Restore `/etc/ssh/sshd_config` and drop-ins under `/etc/ssh/sshd_config.d/` from a trusted baseline.
3. **Validate Syntax Prior to Reload:** Always execute `sudo sshd -t` before reloading the daemon to prevent syntax-induced lockout.
4. **Reload Service:** Execute `sudo systemctl reload ssh` (or `systemctl reload sshd`).
5. **Session & Key Audit:** Review `/home/*/.ssh/authorized_keys` and `/etc/pam.d/sshd` for unauthorized persistence keys.
6. **Network Containment:** Enforce strict source restrictions via host firewall (UFW).
7. **Credential Invalidation:** Rotate administrative SSH keypairs if unauthorized access is suspected.

---

## 6. Key Takeaways

1. **Working Detection:** Rule 100100 reliably alerts on OpenSSH configuration changes on the Vultr host, with telemetry transmitted securely across cloud boundaries over Tailscale to the AWS Wazuh SIEM.
2. **Auditd & FIM Synergy:** While auditd captures command execution and process events, pairing it with real-time FIM (tested in Case 002) provides complete coverage of both execution context and file modification diffs.
