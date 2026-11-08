# Host Firewall (UFW): Reference and Evidence Status

## What the repository can prove today

| Statement | Evidence | Status |
|:---|:---|:---:|
| SSH (TCP/22) is reachable from the internet | `auth.log` in AUTH-03 shows connections from many public addresses, including one logged as a connection *to* the host's public IP | **Verified** |
| Fail2Ban is active and banning SSH sources | `systemctl is-active fail2ban` and `fail2ban-client status sshd` in AUTH-03 / AUTH-04 | **Verified** |
| UFW is active, default deny incoming | No `ufw status verbose` capture in the repository | **Not yet captured** |
| UFW allows TCP/22 from Anywhere (IPv4/IPv6) | No capture | **Not yet captured** |
| UFW allows TCP/3389 on `tailscale0` | No capture | **Not yet captured** |

The UFW details above were noted from an earlier terminal session, but that capture was never committed. Until it is, this repository does not claim them as observed. To close the gap, add a sanitized `sudo ufw status verbose` screenshot or run `scripts/collect_lab_evidence.sh`.

If TCP/3389 really is open on `tailscale0`, document why (for example, xrdp for remote desktop over the tailnet) and confirm it is not reachable on the public interface.

## Why the exposure matters

Public SSH explains the internet probing seen in Case 003. Fail2Ban is a *reactive* control: it bans a source only after it has already failed several times. Limiting SSH by source at the firewall is a *preventive* control. They are not equivalent.

## Target baseline (if public SSH is no longer needed)

Restrict SSH to the Tailscale interface so it is reachable only from the tailnet:

```bash
# Run these from a session that does NOT depend on the rule you are removing.
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow in on tailscale0 to any port 22 proto tcp
sudo ufw delete allow 22/tcp        # removes the "Anywhere" rule (use "delete allow OpenSSH" if it was added by app name)
sudo ufw status numbered
sudo ufw status verbose
```

If public SSH is kept on purpose to collect authentication telemetry, say so in the README as a deliberate lab exposure, and keep the compensating controls: key-only authentication (confirm with `sshd -T`), Fail2Ban, Wazuh monitoring, and regular review of successful logins.

## Wazuh agent connectivity

Use current Wazuh names: the service is `wazuh-agent` and the process is `wazuh-agentd` (not `ossec-agentd`).

The Wazuh manager records this agent's IP as an address in Tailscale's `100.64.0.0/10` range (EP-01). That supports "the agent talks to the manager over Tailscale", but the agent's `<server>` block and an `ss -tnp` line for the manager connection have not been captured yet. See `architecture/README.md`.

## Evidence collection

```bash
bash scripts/collect_lab_evidence.sh
```

The script collects a point-in-time snapshot (time sync, service state, Wazuh manager connection, FIM config, `sshd -T`, UFW, Fail2Ban thresholds, Tailscale, listening services) and replaces IP addresses with class-preserving tokens. Review the output before committing it.
