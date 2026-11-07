# Host Firewall (UFW) Reference and Observed State

## Current Observed State

A November 2026 terminal capture shows:

- UFW status: **active**
- Default incoming policy: **deny**
- Default outgoing policy: **allow**
- TCP/22: **allowed from Anywhere** for IPv4 and IPv6
- TCP/3389: allowed on `tailscale0` for IPv4 and IPv6

This is an important distinction: the firewall is active and default-deny, but SSH is still publicly reachable because TCP/22 is explicitly allowed from anywhere. That exposure is consistent with the real SSH scanning and brute-force telemetry observed in Wazuh and Fail2Ban.

Fail2Ban is also active and is applying reactive blocking to repeated SSH failures. Fail2Ban is a useful control, but it is not equivalent to source-restricting SSH at the firewall.

## Target Hardening Baseline

For a stricter administrative posture, restrict SSH to a known management source or private overlay where operationally feasible:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Example only. Validate your management path before applying.
sudo ufw allow from <ADMIN_MANAGEMENT_IP> to any port 22 proto tcp

sudo ufw enable
sudo ufw status numbered
sudo ufw status verbose
```

If the lab intentionally keeps public SSH reachable to collect authentication telemetry, document that as a deliberate lab exposure and maintain compensating controls such as key-based authentication, Fail2Ban, monitoring, and regular review.

## Wazuh Agent Connectivity

Use current Wazuh terminology: the Linux service/process is `wazuh-agent` / `wazuh-agentd`, not `ossec-agentd`.

The lab uses a Tailscale overlay for cross-cloud connectivity. Verify the exact manager address and ports from the live agent configuration before documenting network paths as an absolute statement.

## Evidence Collection

Run:

```bash
bash scripts/collect_lab_evidence.sh
```

The script collects and redacts a point-in-time snapshot of service state, UFW, Tailscale, Fail2Ban, SSH effective settings, and listening services. Review the output before committing it.
