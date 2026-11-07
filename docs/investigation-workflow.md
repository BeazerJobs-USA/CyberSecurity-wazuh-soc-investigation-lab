# SOC Investigation Workflow and Triage Runbook

## Overview

This runbook defines a defensible workflow for Wazuh FIM and SSH authentication alerts on the lab endpoint. It separates what the SIEM proves from what must be corroborated on the host.

```text
Detection -> Rule Match -> Dashboard Triage -> Host Correlation -> Disposition -> Remediation
```

## 1. FIM Detection Phase

The custom OpenSSH configuration rules are children of Wazuh's built-in FIM rules:

- Rule 550: file integrity/checksum changed
- Rule 554: file added
- Rule 553: file deleted
- Rule 100100: custom SSH configuration modification, Level 8
- Rule 100101: custom SSH configuration addition, Level 7
- Rule 100102: custom SSH configuration deletion, Level 7

The repository reference uses directory-based real-time monitoring because Wazuh real-time monitoring applies to directories:

```xml
<directories check_all="yes" report_changes="yes" realtime="yes">/etc/ssh</directories>
```

The custom rule regex then narrows matching to:

```regex
^/etc/ssh/sshd_config($|\.d/.*)
```

## 2. Dashboard Triage

For a Rule 100100 event:

```text
rule.id:100100 AND agent.name:"vultr-security-lab"
```

Review:

1. Timestamp and event count.
2. Rule ID and level.
3. Decoded `file` path.
4. `syscheck.diff` only if the field is actually present.
5. Hash and file metadata fields if present.
6. Wider host activity without keeping the Rule 100100 filter applied.

> A dashboard filtered to Rule 100100 cannot be used to conclude that the host had zero authentication failures. Query scope must always be documented.

## 3. SSH Authentication Triage

Useful default Wazuh SSH rules observed in the lab include:

- Rule 5710, Level 5: attempt to log in using a non-existent user.
- Rule 5712, Level 10: correlated brute-force attempts against non-existent users.
- Rule 5715, Level 3: successful SSH authentication, when present.
- Rule 5402, Level 3: successful sudo to root.

Correlate SIEM events with `/var/log/auth.log` or `journalctl -u ssh`, and distinguish public hostile sources from known administrative Tailscale peers.

## 4. Host Verification

### SSH syntax
```bash
sudo sshd -t
```

### Effective configuration
```bash
sudo sshd -T | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|permitemptypasswords|maxauthtries|x11forwarding) '
```

`sshd -T` reports the effective configuration after OpenSSH processes its configuration sources. Do not describe this as configuration “in memory.”

### Service and control state
```bash
sudo systemctl is-active wazuh-agent
sudo systemctl is-active tailscaled
sudo systemctl is-active ssh
sudo systemctl is-active fail2ban
sudo systemctl is-active auditd
sudo ufw status verbose
sudo fail2ban-client status sshd
tailscale status
```

## 5. Disposition Standard

A final disposition should identify:

- what happened,
- which rule/event supports the finding,
- affected asset,
- source/actor evidence if available,
- whether activity was authorized,
- containment already applied,
- remaining evidence gaps.

Do not call an event benign merely because it carries an administrative ATT&CK tag, and do not call a configuration change malicious solely because it triggered FIM.

## 6. Response Guidance

For suspected unauthorized SSH configuration changes:

1. Preserve the active administrative session to avoid lockout.
2. Export the Wazuh alert/event before altering the system.
3. Review the changed file and any available diff.
4. Correlate auth/audit records.
5. Restore a trusted baseline if unauthorized.
6. Run `sshd -t` before reloading SSH.
7. Review authorized keys and PAM configuration.
8. Tighten UFW exposure as appropriate.
9. Rotate administrative keys if compromise is suspected.
