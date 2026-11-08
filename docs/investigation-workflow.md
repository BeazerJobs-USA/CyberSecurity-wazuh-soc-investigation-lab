# Triage Runbook: SSH Configuration FIM Alerts and SSH Authentication Alerts

## Overview

This is the workflow I follow on this lab for Wazuh FIM alerts on the SSH configuration and for SSH authentication alerts. Each step separates what the SIEM proves from what has to be confirmed on the host.

```text
Alert -> check query scope -> read raw fields -> line up times -> correlate host evidence
      -> separate my own activity -> state gaps -> disposition -> response
```

## 0. Before anything: scope and time

- **Write down the query scope** shown in the capture: query text, every filter pill, and the time window. Dashboard counters (Authentication failure/success, Level 12+) are computed *inside* those filters. A dashboard filtered to `rule.id:100100` or `rule.id:5402` showing "0 authentication failures" says nothing about the host. EV-02 and PRIV-04 are examples.
- **Line up time zones.** The dashboard shows browser local time (Eastern here); host logs are UTC. On 5 Nov, dashboard 11:43 = host 16:43. Wazuh's `timestamp` is the manager's processing time, about one second after the host log line in these captures. Setting the dashboard timezone to UTC (Dashboard Management → Advanced settings → `dateFormat:tz`) removes this step.

## 1. FIM detection

The custom OpenSSH rules are children of Wazuh's built-in FIM rules:

| Rule | Meaning | Level |
|:---|:---|:---:|
| 550 | Integrity checksum changed (built-in) | 7 |
| 554 | File added (built-in) | 5 |
| 553 | File deleted (built-in) | — |
| 100100 | SSH config modified (custom, child of 550) | 8 |
| 100101 | SSH config drop-in added (custom, child of 554) | 7 |
| 100102 | SSH config drop-in deleted (custom, child of 553) | 7 |

Real-time FIM works on directories, not single files (Wazuh syscheck reference), so the reference config watches `/etc/ssh`:

```xml
<directories check_all="yes" report_changes="yes" realtime="yes">/etc/ssh</directories>
```

The custom rules then narrow alerts to the files sshd actually loads:

```regex
^/etc/ssh/sshd_config(\.d/[^/]+\.conf)?$
```

## 2. Read the raw fields of a FIM alert

Query: `rule.id:100100 AND agent.name:"vultr-security-lab"`, then expand the event:

1. `syscheck.path`: which file. Main config, a drop-in, or something else?
2. `syscheck.event`: added, modified or deleted.
3. `syscheck.mode`: `realtime`, `scheduled` or `whodata`. This proves which FIM mode was live.
4. `syscheck.changed_attributes`, `size_before`/`size_after`, `sha256_before`/`sha256_after`.
5. `syscheck.diff`, only if present. Don't claim a diff exists until you see it.
6. `syscheck.uname_after`: the file owner, which is **not** the person who changed it.
7. Then remove the rule filter and look at everything from the host in the surrounding minutes.

## 3. SSH authentication alerts

Default Wazuh rules seen in this lab's captures:

| Rule | Meaning | Level | Seen in |
|:---|:---|:---:|:---|
| 5710 | sshd: attempt to log in using a non-existent user | 5 | AUTH-01 |
| 5712 | sshd: brute force (composite: 5710 repeating from the same source IP in a short window) | 10 | AUTH-02 |
| 5501 / 5502 | PAM login session opened / closed (here, around each sudo) | 3 | PRIV-02 |
| 5402 | Successful sudo to ROOT executed | 3 | PRIV-02/03/04 |

**Not yet captured:** the sshd authentication-success rule. Reviewing successful logins is the most important missing step in Case 003.

Then:

- Match alerts to `/var/log/auth.log` lines (or `journalctl -u ssh`) by time and source.
- **Alert counts are not attempt counts.** In Case 003 one attempt produced two 5710 alerts. Use `/var/ossec/bin/wazuh-logtest` on the manager to see which rule each log line hits.
- **Separate your own activity.** Sources in `100.64.0.0/10` are tailnet devices. My admin workstation produced an accepted key login, sudo commands and a deliberate `fakeuser` test in the same window as internet probing. A typo in an admin login looks exactly like an attack line; source context tells them apart.
- `[preauth]` means the connection ended before authentication finished. `Failed password` lines mean a password was actually tried.

## 4. Host verification

### SSH syntax and effective settings

```bash
sudo sshd -t
sudo sshd -T | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|permitemptypasswords|maxauthtries|x11forwarding) '
```

`sshd -T` reads the configuration files on disk and prints what sshd *would* use if it started now. If a file changed and sshd was not reloaded, the running daemon may still be using the old settings, so check when `ssh.service` last started or reloaded.

### Service and control state

```bash
sudo systemctl is-active wazuh-agent tailscaled ssh fail2ban auditd
sudo ufw status verbose
sudo fail2ban-client status sshd
for k in maxretry findtime bantime ignoreip; do sudo fail2ban-client get sshd "$k"; done
tailscale status
timedatectl
```

Or run `scripts/collect_lab_evidence.sh`, which gathers all of this with IP addresses tokenized.

## 5. Disposition standard

A disposition states:

- what happened, and which rule or event shows it,
- the affected asset,
- the source or actor, if known,
- whether the activity was authorized, and how you know,
- any containment already in place,
- the remaining evidence gaps.

Terms I use:

- **True positive:** the alert correctly describes what happened (for example, internet probing).
- **Benign true positive:** correct alert on expected or authorized activity (for example, my own `fakeuser` test, or my own sudo).
- **False positive:** the alert fired on something that did not happen as described.

Don't call an event benign because it carries an admin-looking ATT&CK tag (T1548.003 is on every successful sudo-to-root), and don't call a config change malicious just because FIM fired.

## 6. Response, if an SSH config change is unauthorized

1. Keep your current admin session open, so a lockout can't strand you.
2. Export the Wazuh alert before changing anything on the host.
3. Review the changed file and any diff.
4. Correlate sudo, auth and FIM records for the minutes around the change.
5. Restore a known-good copy if the change was unauthorized.
6. Run `sshd -t` before reloading SSH.
7. Review `authorized_keys`, PAM configuration and sudoers.
8. Restrict SSH exposure (for example, to `tailscale0`).
9. Rotate administrative keys if compromise is suspected.
