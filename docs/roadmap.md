# Engineering Roadmap & Planned Capabilities

## Overview

This roadmap defines engineering milestones for the SOC Investigation Lab. To ensure defensibility and technical integrity, **all milestones listed below are tracked with strict Definitions of Done (DoD)**, clearly distinguishing verified capabilities from planned future extensions.

---

## Phase 1: Linux Detection Engineering Enhancements

| # | Objective | Technical Scope | Definition of Done (DoD) | Implementation Status |
|:---:|:---|:---|:---|:---:|
| **1.1** | **Real-Time FIM Lifecycle Validation** | Deploy ruleset v2 (`$(file)` variable fix) to Wazuh manager; execute `scripts/fim_demo.sh` to generate file addition, modification, and deletion events. | Directory `evidence/demo/` contains verified timeline evidence and documentation for Rules 100101, 100100, and 100102 with matching UTC timestamps. | **VERIFIED (Case 002)** |
| **1.2** | **Actor Attribution via Who-Data** | Integrate Linux `auditd` on the Vultr endpoint and enable `whodata="yes"` in `ossec.conf`. | Alerts for Rule 100100 enrich with acting user (`audit.login_user.name`) and binary (`audit.process.name`), eliminating reliance on manual log correlation. | **PLANNED** |
| **1.3** | **Expanded Persistence Monitoring** | Extend FIM rules to monitor `~/.ssh/authorized_keys` and `/etc/pam.d/sshd`. | New custom rules, safe firing test scripts, and validated alerts mapped to MITRE ATT&CK T1098.004 (SSH Authorized Keys). | **PLANNED** |
| **1.4** | **Rule Tuning & Baselines** | Aggregate 7 days of operational FIM telemetry to calculate false-positive rates and tune severity levels. | Documented baseline analysis report with tuning rationale for rules 100100–100102. | **PLANNED** |

---

## Phase 2: Enterprise Cloud SIEM & Endpoint Expansion

| # | Objective | Technical Scope | Definition of Done (DoD) | Implementation Status |
|:---:|:---|:---|:---|:---:|
| **2.1** | **Windows Endpoint Telemetry** | Provision Windows 11 workstation endpoint; install Sysmon with modular SwiftOnSecurity configuration. | Sysmon event IDs 1 (Process Create), 3 (Network Connect), and 11 (File Create) actively collected. | **PLANNED** |
| **2.2** | **Microsoft Sentinel Ingestion** | Deploy Log Analytics Workspace and Azure Monitor Agent / Wazuh forwarder to ingest multi-source telemetry into Microsoft Sentinel. | Live telemetry visible in Sentinel tables (`SecurityEvent`, `Sysmon_CL`, or `CommonSecurityLog`). | **PLANNED** |
| **2.3** | **Defender XDR & KQL Investigations** | Author custom KQL threat hunting queries to detect anomalous authentication and living-off-the-land binaries (LOLBins). | Documented investigation case study with KQL queries, raw result tables, and execution screenshots. | **PLANNED** |
| **2.4** | **Automated Incident Response (SOAR)** | Implement automated playbook (e.g., Azure Logic Apps or Wazuh active response) to temporarily isolate compromised hosts or drop offending source IPs. | Automated trigger validation log and incident ticket integration documented in lab write-up. | **PLANNED** |

---

> [!NOTE]
> All future items in this roadmap remain clearly segregated from current lab deliverables in the main architecture diagram and documentation.
