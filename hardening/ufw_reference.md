# Host Firewall (UFW) Hardening Reference

## Overview

This reference documents the defensive firewall architecture designed for the monitored Ubuntu Linux cloud endpoint (`vultr-security-lab`). 

> [!NOTE]
> **Implementation Status: PENDING VERIFICATION**
> This document specifies the target defensive baseline. Live host verification is pending collection of sanitized `sudo ufw status verbose` terminal evidence from the running host.

---

## Defensive Objectives

1. **Default Inbound Posture:** Deny all unsolicited incoming connection attempts.
2. **Outbound Connectivity:** Allow stateful outbound traffic, enabling the Wazuh Agent (`ossec-agentd`) to communicate outbound to the Wazuh Manager over TCP/1514 (event reporting) and TCP/1515 (enrollment).
3. **Restricted Administrative Access:** Expose OpenSSH (Port 22) only to designated administrative source networks or specific management IPs.
4. **Service Minimization:** Expose zero extraneous TCP/UDP listening services to the public internet.

---

## Implementation Command Sequence

> [!IMPORTANT]
> **Remote Host Safety Rule:** Always allow SSH before enabling UFW, and maintain an active secondary terminal session until successful reconnection is confirmed.

```bash
# 1. Establish default baseline policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# 2. Permit SSH administrative access (restrict to admin IP where static)
sudo ufw allow from <ADMIN_MANAGEMENT_IP> to any port 22 proto tcp
# Alternatively, for dynamic administrative connections:
# sudo ufw allow OpenSSH

# 3. Activate firewall and verify rule ordering
sudo ufw enable
sudo ufw status numbered
sudo ufw status verbose
```

---

## Live State Audit Procedure

To capture the runtime firewall state on the live host with automated IP sanitization, execute:
```bash
bash scripts/collect_lab_evidence.sh
```
This inspects `sudo ufw status verbose` and redacts external IP addresses to ensure evidence is sanitized before inclusion in reports.
