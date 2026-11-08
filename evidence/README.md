# Evidence Index

Every screenshot here is treated as evidence. For each one the index records the **scope** (view, query, filters, time window), **what it shows**, and **what it does not prove**. Full captions are on the case pages.

## Evidence states used in this repository

| State | Meaning |
|:---|:---|
| **Verified / Observed** | Directly visible in a capture from the running lab |
| **Supported** | Indirect evidence points to it, but the direct proof has not been captured |
| **Test recorded** | A controlled action was logged, but its expected alert has not been captured |
| **Authored** | Config or code exists in the repo; not validated on the live system |
| **Not captured / Pending** | Claimed or planned, with no artifact yet |
| **Planned** | Future work |

## Time conventions

- Wazuh dashboard captures show **browser local time** (US Eastern). 14 Oct is EDT (UTC−4); 5 Nov is EST (UTC−5).
- Host log captures (`auth.log`) show **UTC** (`+00:00`).
- The Case 002 timeline is **UTC** (`Z`).
- Wazuh's `timestamp` is when the manager processed the event. In these captures it is about one second after the host log line.

---

## Case 001: Rule 100100 SSH configuration alert

| ID | File | Scope | Shows | Does not prove |
|:---|:---|:---|:---|:---|
| EV-01 | `observed/01_rule100100_events_view.png` | Events · `rule.id:100100` · agent vultr-security-lab · 14 Oct 01:01–02:01 local | One Level 8 Rule 100100 alert at 01:48:49; blank description variable | Parent rule, actual file/change, actor or authorization |
| EV-02 | `observed/02_rule100100_dashboard_view.png` | Dashboard · same filter · last 1 h | Total 1; no ATT&CK tag on the custom rule | Anything about host-wide authentication (counters are filter-scoped) |
| EV-03 | `observed/03_sshd_config_search_24h.png` | Dashboard · free text `sshd_config` · 24 h ending ≈00:57 · date not shown | 19 Level 3 sudo-tagged (T1548.003) events | Anything about the 01:48:49 alert, which is not in this view |

## Case 002: FIM lifecycle test

| ID | File | Shows | Does not prove |
|:---|:---|:---|:---|
| DEMO-01 | `demo/fim_demo_timeline.txt` | Create/modify/delete actions at 02:15–02:16 UTC, 14 Oct | Any Wazuh alert; that the run happened against the current agent enrollment (it predates the registration time in EP-01) |

## Case 003: Internet SSH probing

| ID | File | Scope | Shows | Does not prove |
|:---|:---|:---|:---|:---|
| AUTH-01 | `observed/04_auth01_rule5710_invalid_user_1h.png` | Events · `rule.id: 5710` · 5 Nov 10:58–11:58 EST | 43 invalid-user alerts, level 5 | 43 attackers or attempts (2 alerts are my own test; one attempt can make 2 alerts); any success |
| AUTH-02 | `observed/05_auth02_rule5712_bruteforce_4w.png` | Events · `rule.id: 5712` · 8 Oct–5 Nov | 2 composite alerts (15 Oct, 4 Nov), level 10 | Source IPs; password guessing; access |
| AUTH-03 | `observed/06_auth03_authlog_fail2ban_terminal.png` | Endpoint terminal, captured 12:01 EST · `auth.log` 16:34–16:45 UTC | wazuh-agent and fail2ban active; 12 public sources; my key login, sudo commands and `fakeuser` test; Fail2Ban 8,439 failed / 265 banned / 80.94.92.55 banned | History beyond 11 minutes; Fail2Ban thresholds; counter start time |
| AUTH-04 | `observed/07_auth04_fail2ban_status_followup.png` | Endpoint terminal, ≈12:09 EST | 8,449 failed / 265 banned; 80.94.92.55 still banned | Configured ban time |

## Endpoint state

| ID | File | Scope | Shows | Does not prove |
|:---|:---|:---|:---|:---|
| EP-01 | `observed/08_ep01_agent_overview.png` | Endpoints → agent 001 · panels last 1 h · 5 Nov ≈12:45 EST | Active; agent IP in Tailscale range (100.67.x.x); Wazuh v4.14.8; Ubuntu 26.04.1; registered 14 Oct 00:50:40; vulnerability counts; no SCA results; no FIM events in the last hour | That ATT&CK tactics happened ("Lateral Movement 27" is rule tagging); PCI compliance; exploitability of the vulnerability findings; FIM coverage of `/etc/ssh` |

## Case 004: Controlled sudo test

| ID | File | Scope | Shows | Does not prove |
|:---|:---|:---|:---|:---|
| PRIV-01 | `observed/09_priv01_sudo_id_whoami_terminal.png` | Endpoint terminal, captured 12:45 EST | `sudo id` / `sudo whoami` → root, no password prompt; "System restart required" | Exact run times |
| PRIV-02 | `observed/10_priv02_sudo_search_1h.png` | Events · free text `sudo` · 11:43–12:43 EST | 15 hits = 5 × (5501 → 5402 → 5502) | Every privileged action (`su`, `pkexec` wouldn't match); command names |
| PRIV-03 | `observed/11_priv03_rule5402_events_1h.png` | Events · `rule.id: 5402`, agent 001 · 11:52–12:52 EST | 3 sudo-to-root alerts: 12:09:10, 12:38:50, 12:39:02 | Command per alert (`data.command` not expanded) |
| PRIV-04 | `observed/12_priv04_rule5402_dashboard_scope.png` | Dashboard · same filters | Total 3; auth tiles 0 (filter-scoped); groups sudo/syslog; PCI 10.2.2/10.2.5 tags | Host authentication activity |

---

## Redaction and publication rules

Applied to every published capture:

1. **Manager hostname:** the tail is masked; the `ip-172-31-` prefix is kept because it shows the AWS EC2 private-DNS naming pattern.
2. **Tailscale addresses:** the last two octets are masked; the first two (for example `100.107.`) are kept so the `100.64.0.0/10` range stays visible. That is how admin traffic is told apart from internet traffic.
3. **The host's public IP and the SSH key fingerprint hash** are fully masked.
4. **Internet source addresses are kept.** They are scanners, and they are the evidence for correlation (for example, `80.94.92.55` in both the host log and Fail2Ban).
5. Timestamps, rule IDs, levels, descriptions and counts are never altered.
6. My own test traffic is labelled as such and kept separate from internet telemetry.
7. Dashboard counters are always reported with their query scope.

Masks are solid boxes (black on light UI, grey on terminal backgrounds) so the redaction is visible, not disguised.
