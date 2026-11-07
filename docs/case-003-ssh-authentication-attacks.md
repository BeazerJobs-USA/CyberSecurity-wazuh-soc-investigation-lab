# Case 003: SSH Authentication Attack Investigation and Fail2Ban Response

## Executive Summary

The public SSH service on `vultr-security-lab` received repeated unsolicited authentication attempts from multiple external sources. Wazuh generated both individual invalid user alerts and correlated brute force alerts, while Fail2Ban maintained an active `sshd` jail and recorded cumulative bans.

This case demonstrates **real observed internet attack telemetry**. It does not claim that the host was compromised.

## Evidence Gallery

> [!NOTE]
> The new November screenshots were reviewed for this revision but their sanitized image files still need to be committed into `evidence/observed/`. This case page is intentionally not using fabricated or substituted screenshots.

### AUTH 01: Endpoint and Security Control State

Evidence reviewed shows the current endpoint as Ubuntu 26.04.1 LTS with the Wazuh agent active along with Tailscale, SSH, Fail2Ban, and auditd. UFW is active with default deny incoming, while TCP/22 remains explicitly allowed from Anywhere.

**Publication status:** sanitized screenshot prepared, GitHub image file still pending.

### AUTH 02: Privileged Administrative Activity

Wazuh Threat Hunting captures show successful sudo to root events, including Rule 5402.

**Publication status:** sanitized screenshot prepared, GitHub image file still pending.

### AUTH 03: Rule 5710 Invalid User Attempts

A Wazuh Threat Hunting view filtered to Rule 5710 shows:

* 43 hits in a one hour window
* Rule description: `sshd: Attempt to login using a non-existent user`
* Wazuh level 5
* Agent: `vultr-security-lab`

**Publication status:** sanitized screenshot prepared, GitHub image file still pending.

### AUTH 04: Rule 5712 Brute Force Correlation

A four week Wazuh query filtered to Rule 5712 shows two correlated alerts:

* 15 Oct 2026
* 4 Nov 2026
* Rule description: `sshd: brute force trying to get access to the system. Non existent user.`
* Wazuh level 10

**Publication status:** sanitized screenshot prepared, GitHub image file still pending.

### AUTH 05: Fail2Ban Response

The `sshd` jail is active. A captured status check shows thousands of cumulative failures, 265 cumulative bans, and one source currently banned at capture time.

These values are point in time observations and will change while the service remains active.

**Publication status:** sanitized screenshot prepared, GitHub image file still pending.

---

## Host Authentication Correlation

The reviewed host authentication log shows:

* repeated `Invalid user` and pre authentication disconnect messages from public IP addresses,
* attempts using names such as `admin`, `ubuntu`, `default`, and `support`,
* a successful public key login for the known administrative account from a private Tailscale peer,
* subsequent sudo session activity by that administrator.

This distinction matters. A successful login is not automatically suspicious without source, authentication method, and account context.

## UFW Exposure Context

UFW is active and default deny incoming is enabled, but TCP/22 is explicitly allowed from Anywhere for IPv4 and IPv6. This explains why unsolicited internet SSH attempts continue to reach the service.

Fail2Ban is a reactive control. It is not equivalent to source restricting SSH at the firewall.

## Analyst Assessment

**Finding:** the endpoint is receiving genuine internet SSH credential probing. Wazuh captures individual invalid user attempts and correlated brute force behavior. Fail2Ban actively blocks repeated sources.

**Compromise assessment:** no supplied artifact proves successful unauthorized access or host compromise.

**Administrative activity:** known public key administration over the private management path and subsequent sudo activity should be separated from hostile public traffic during triage.

## Recommended Follow Up

1. Commit the sanitized Rule 5710 screenshot.
2. Commit the sanitized Rule 5712 screenshot.
3. Commit the sanitized Fail2Ban screenshot.
4. Commit the endpoint state and sudo screenshots if they add useful context.
5. Correlate one hostile source across Wazuh, host logs, and Fail2Ban.
6. Decide whether public SSH exposure remains intentional for the lab.
7. Verify effective SSH hardening with `sshd -t` and `sshd -T`.

## Hiring Manager Takeaway

The strongest part of this case is not the raw alert count. It is the analyst workflow: validating query scope, correlating SIEM events with host logs, distinguishing legitimate administration from hostile activity, documenting a defensive response, and refusing to claim compromise without evidence.
