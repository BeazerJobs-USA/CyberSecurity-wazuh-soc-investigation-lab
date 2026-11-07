# Case 003: SSH Authentication Attack Investigation and Fail2Ban Response

## Executive Summary

The public SSH service on `vultr-security-lab` received repeated unsolicited authentication attempts from multiple external sources. Wazuh generated both individual invalid user alerts and correlated brute force alerts, while Fail2Ban maintained an active `sshd` jail and recorded cumulative bans.

This case demonstrates **real observed internet attack telemetry**. It does not claim that the host was compromised.

## Observed Evidence

### 1. Rule 5710: non existent user attempts

A Wazuh Threat Hunting view filtered to Rule 5710 shows:

- 43 hits in a one hour window
- Rule description: `sshd: Attempt to login using a non-existent user`
- Wazuh level 5
- Agent: `vultr-security-lab`

This supports the conclusion that the public SSH service was receiving repeated username probing/authentication attempts.

### 2. Rule 5712: correlated brute force activity

A four week Wazuh query filtered to Rule 5712 shows two correlated alerts:

- 15 Oct 2026
- 4 Nov 2026
- Rule description: `sshd: brute force trying to get access to the system. Non existent user.`
- Wazuh level 10

This is stronger evidence than inferring brute force from dashboard counters because the Wazuh correlation rule itself fired.

### 3. Host authentication log correlation

The host `/var/log/auth.log` capture shows:

- repeated `Invalid user` and pre authentication disconnect messages from public IP addresses
- attempts using names such as `admin`, `ubuntu`, `default`, `support`, and other invalid accounts
- a successful public key login for the known administrative account from a private Tailscale peer
- subsequent `sudo` session activity by that administrator

The distinction between public hostile sources and the known private administrative source is important. A successful login event is not automatically suspicious without source and authentication context.

### 4. Fail2Ban response

The `sshd` jail is active. A captured status check shows:

- thousands of cumulative failed attempts
- 265 cumulative bans
- one source currently banned at capture time

The exact cumulative failure counter can change between captures because the service remains live. The portfolio should therefore treat these numbers as **point in time observations**, not permanent totals.

### 5. UFW exposure context

UFW is active and default deny is enabled for incoming traffic, but TCP/22 is explicitly allowed from Anywhere for IPv4 and IPv6. This explains why unsolicited internet SSH attempts continue to reach the service.

Fail2Ban is a reactive control. It does not make public SSH equivalent to source restricted administrative access.

## Analyst Assessment

**Finding:** The endpoint is exposed to routine but genuine internet SSH credential probing. Wazuh captures both individual invalid user attempts and correlated brute force behavior. Fail2Ban actively blocks repeated sources.

**Compromise assessment:** No evidence in the supplied artifacts proves a successful unauthorized login or host compromise.

**Administrative activity:** A known public key login over the private Tailscale path and subsequent sudo events are visible in the host logs and should be separated from hostile public attempts during triage.

## Recommended Follow Up

1. Preserve one sanitized Wazuh Rule 5710 event and one Rule 5712 event with source fields.
2. Correlate one banned source across Wazuh, host auth logs, and Fail2Ban.
3. Decide whether public SSH exposure is intentional for the lab.
4. If not intentional, restrict SSH to the management path and document the before and after telemetry.
5. Verify effective SSH hardening with `sshd -t` and `sshd -T`.
6. Continue monitoring for successful authentication events from unrecognized sources.

## Hiring Manager Takeaway

This case demonstrates the analyst behavior that matters more than raw alert counts: validating query scope, correlating SIEM events with host logs, distinguishing legitimate administration from hostile activity, documenting a defensive control, and refusing to claim compromise without evidence.
