# SOC Investigation Lab Roadmap

This roadmap separates completed evidence from work that still needs direct validation.

## Phase 1: Evidence hardening and Linux detection maturity

| # | Objective | Definition of done | Status |
|:---:|:---|:---|:---:|
| 1.1 | Correct real time FIM scope | Repository reference monitors `/etc/ssh` as a directory and custom rules narrow the alert paths | **COMPLETE IN REPO** |
| 1.2 | Native manager rule validation | `sudo /var/ossec/bin/wazuh-analysisd -t` passes after deploying the current ruleset | **PENDING EVIDENCE** |
| 1.3 | Complete FIM lifecycle capture | Wazuh captures show create 100101, modify 100100, and delete 100102 for the demo file | **PENDING EVIDENCE** |
| 1.4 | Verify v2 description field | Live alert shows `$(file)` resolving to the expected path | **PENDING EVIDENCE** |
| 1.5 | Verify effective SSH hardening | Sanitized `sshd -t` and `sshd -T` output matches the intended baseline | **PENDING EVIDENCE** |
| 1.6 | Who data actor attribution | Enable and validate Wazuh who data for `/etc/ssh` with user/process fields captured | **PLANNED** |
| 1.7 | Tune public SSH controls | Decide whether public SSH remains intentionally exposed for telemetry or is restricted to a management path; document compensating controls | **IN REVIEW** |

## Phase 2: Authentication detection and response

| # | Objective | Definition of done | Status |
|:---:|:---|:---|:---:|
| 2.1 | Invalid user investigation | Document Rule 5710 activity with query scope and source context | **OBSERVED** |
| 2.2 | Brute force correlation | Document Rule 5712 alerts and correlate them with host logs | **OBSERVED** |
| 2.3 | Fail2Ban response evidence | Show active sshd jail and cumulative ban metrics | **OBSERVED** |
| 2.4 | Detection to response case study | Correlate one source across Wazuh, auth logs, and Fail2Ban while preserving privacy | **PLANNED** |
| 2.5 | Baseline and tuning | Collect at least seven days of authentication telemetry and document normal versus suspicious patterns | **PLANNED** |

## Phase 3: Enterprise endpoint and cloud expansion

| # | Objective | Definition of done | Status |
|:---:|:---|:---|:---:|
| 3.1 | Windows endpoint telemetry | Windows 11 endpoint with Sysmon producing validated process, network, and file events | **PLANNED** |
| 3.2 | Microsoft Sentinel ingestion | Live lab telemetry visible in Sentinel with documented data source and query results | **PLANNED** |
| 3.3 | Defender XDR and KQL investigation | One evidence backed Windows investigation using KQL and endpoint telemetry | **PLANNED** |
| 3.4 | Identity attack detection | Controlled Active Directory or Entra identity scenario with defensible logs and analyst disposition | **PLANNED** |
| 3.5 | Automated response | Safe automated response validated against a controlled test and documented with rollback steps | **PLANNED** |

## Portfolio rule

A roadmap item is moved to **verified** only when the repository contains direct evidence of the result, not only a configuration file, expected output, or script execution record.
