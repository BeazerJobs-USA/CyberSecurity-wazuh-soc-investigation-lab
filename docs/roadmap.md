# Roadmap

A roadmap item is marked **done** only when the repository holds direct evidence of the result, not just a config file, expected output or script log.

## Phase 1: Evidence hardening and Linux detection

| # | Objective | Definition of done | Status |
|:---:|:---|:---|:---:|
| 1.1 | Correct real-time FIM scope | Reference config watches `/etc/ssh` as a directory; rules narrow the paths | **Done in repo** |
| 1.2 | Tighten rule path scope (v2.2) | Pattern limited to `sshd_config` and `*.conf` drop-ins; linter path tests pass | **Done in repo** (not deployed) |
| 1.3 | Native manager rule validation | `sudo /var/ossec/bin/wazuh-analysisd -t` passes with v2.2 deployed | **Pending evidence** |
| 1.4 | Close Case 001 gaps from the dashboard | Expanded 14 Oct event (`syscheck.path`, `mode`, hashes, diff) plus a sudo search for 01:30–01:50 | **Pending evidence** |
| 1.5 | Re-run the FIM lifecycle test | New timeline plus Wazuh captures of 100101/100100/100102 with matching SHA-256 | **Pending evidence** |
| 1.6 | Effective SSH settings | Sanitized `sshd -t` and `sshd -T` output | **Pending evidence** |
| 1.7 | Who-data actor attribution | Who-data enabled for `/etc/ssh`, with user/process fields in an alert | **Planned** |
| 1.8 | Decide on public SSH | Restrict TCP/22 to `tailscale0`, or document public SSH as deliberate | **In review** |

## Phase 2: Authentication detection and response

| # | Objective | Definition of done | Status |
|:---:|:---|:---|:---:|
| 2.1 | Invalid-user detection | Rule 5710 documented with scope and host-log correlation | **Done** (Case 003) |
| 2.2 | Composite brute-force detection | Rule 5712 alerts documented | **Done** (Case 003) |
| 2.3 | Fail2Ban response evidence | Active jail, bans, one source tied to the host log | **Done** (Case 003); thresholds pending |
| 2.4 | One source across all three tools | One IP shown in a Wazuh event (`data.srcip`), the host log and Fail2Ban | **Partial**: host log ↔ Fail2Ban done for 80.94.92.55; Wazuh side pending |
| 2.5 | Successful-login review | Every successful SSH login over 30 days traced to the admin key and a Tailscale source | **Pending**. This is the main open item in Case 003 |
| 2.6 | Controlled sudo detection test | Known sudo commands traced to 5501/5402/5502 | **Done** (Case 004); `data.command` capture pending |
| 2.7 | Alert on SSH success from outside the tailnet | Custom child rule, tested with `wazuh-logtest` | **Planned** |
| 2.8 | Passwordless sudo review | `sudo -l` captured; keep or remove `NOPASSWD`, with reasoning | **Pending** |
| 2.9 | Baseline and tuning | Seven days of authentication telemetry summarized: normal vs suspicious | **Planned** |

## Phase 3: Platform and posture

| # | Objective | Definition of done | Status |
|:---:|:---|:---|:---:|
| 3.1 | Architecture evidence | Agent `<server>` block, `ss` line for 1514, `tailscale status`, AWS security group, UFW status | **Pending evidence** |
| 3.2 | Dashboard timezone | Dashboard set to UTC, or every capture labelled with its zone | **Planned** |
| 3.3 | Vulnerability triage | Confirm running vs installed kernels, reboot, remove the old kernel, re-check counts | **Pending** |
| 3.4 | SCA | Find out why the agent shows no SCA results and enable a policy if one exists for Ubuntu 26.04 | **Planned** |

## Phase 4: Expansion (after the Linux cases are fully evidenced)

| # | Objective | Status |
|:---:|:---|:---:|
| 4.1 | Windows 11 endpoint with Sysmon, validated process/network/file events | **Planned** |
| 4.2 | Microsoft Sentinel ingestion with documented queries | **Planned** |
| 4.3 | Defender XDR / KQL investigation | **Planned** |
| 4.4 | Controlled identity-attack scenario (AD or Entra) | **Planned** |
| 4.5 | Automated response tested with rollback steps | **Planned** |
