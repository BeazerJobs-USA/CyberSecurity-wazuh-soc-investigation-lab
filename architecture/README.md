# Architecture: What Is Verified and What Is Assumed

The main diagram is [`assets/architecture/lab-architecture.png`](../assets/architecture/lab-architecture.png) (source: `.svg`). This page lists each component and connection with the evidence behind it, so the diagram can be checked rather than trusted.

## Components

| Component | Where | Evidence | Status |
|:---|:---|:---|:---:|
| Monitored endpoint, Ubuntu 26.04.1 LTS, hostname `Security-Lab` | Vultr | EP-01 (agent overview); AUTH-03 (shell prompt) | **Verified** (the Vultr hosting itself is supported by the agent name and cloud CPU, not by a console capture) |
| Wazuh agent v4.14.8, agent ID 001, group `default` | Endpoint | EP-01; `systemctl is-active wazuh-agent` in AUTH-03 | **Verified** |
| Wazuh manager | AWS EC2 | Manager hostname `ip-172-31-…` follows the EC2 private-DNS pattern; cluster node `node01` (EP-01) | **Supported** (no EC2 console or security-group capture) |
| Wazuh dashboard | Reached at `https://100.101.x.x` (self-signed certificate) | Browser address bar in EP-01 and other captures | **Observed** that it is reached over Tailscale; whether it runs on the same EC2 instance as the manager is **not documented** |
| Tailscale overlay | All three machines | Admin SSH source, agent IP and dashboard URL are all in `100.64.0.0/10` | **Supported** (`tailscale status` not captured) |
| OpenSSH on public TCP/22 | Endpoint | Internet sources in `auth.log`, including a connection to the host's public IP (AUTH-03) | **Verified** |
| Fail2Ban `sshd` jail | Endpoint | AUTH-03, AUTH-04 | **Verified** (thresholds not captured) |
| Wazuh FIM on `/etc/ssh` | Endpoint | Current custom rules reference FIM parents; the v1 parent and live agent FIM configuration are not shown in the captures | **Not yet verified** (`syscheck.mode` and live directory configuration missing) |
| UFW | Endpoint | — | **Not captured** |
| auditd | Endpoint | — | **Not captured** (not used by any detection here) |
| Windows/Sysmon, Microsoft Sentinel, Defender XDR | — | — | **Planned** |

## Connections

| From → To | Path | Evidence | Status |
|:---|:---|:---|:---:|
| Admin workstation → endpoint SSH | Tailscale | `Accepted publickey for linuxuser from 100.107.x.x … ED25519` (AUTH-03) | **Verified** |
| Admin workstation → Wazuh dashboard | Tailscale, HTTPS | Address bar `https://100.101.x.x` | **Observed** |
| Wazuh agent → manager | Tailscale (expected) | The manager records the agent's IP as `100.67.x.x`, a Tailscale-range address (EP-01) | **Supported** |
| Internet → endpoint SSH | Public interface, TCP/22 | 12 public sources in 11 minutes (AUTH-03) | **Verified** |
| Endpoint logs → Wazuh rules | Agent log collection → manager | sshd and sudo log lines match Wazuh alerts within about 1 s (Cases 003, 004) | **Verified** |

### How the agent talks to the manager (Wazuh defaults, not captured from this lab)

By default a Wazuh agent sends events, keep-alives and control messages to the manager on **TCP 1514**, encrypted with a per-agent key, and enrolls on **TCP 1515**. In this lab that traffic is expected to run inside the Tailscale (WireGuard) tunnel. Whether Tailscale uses a direct path or a DERP relay between Vultr and AWS has not been checked (`tailscale status` or `tailscale ping` shows it).

## Captures that would close the gaps

1. Agent `ossec.conf` `<server>` block (manager address, port, protocol), plus `sudo ss -tnp | grep 1514` on the endpoint.
2. `tailscale status` on the endpoint, with peer names reviewed before publishing.
3. AWS security group inbound rules for the manager (to show 1514, 1515 and 443 are not open to the internet).
4. EC2 instance summary, and the Vultr instance page or firewall group.
5. `sudo ufw status verbose` on the endpoint.

`scripts/collect_lab_evidence.sh` prints items 1, 2 and 5 with IP addresses tokenized.

## Diagrams in this repository

| File | What it shows | Notes |
|:---|:---|:---|
| `assets/architecture/lab-architecture.svg` / `.png` | Full topology with evidence labels | Main diagram |
| `assets/diagrams/detection-pipeline.svg` / `.png` | FIM parent → custom child rule logic (Cases 001/002) | |
| `assets/diagrams/investigation-workflow.svg` / `.png` | Triage steps for an SSH-config FIM alert | |
| `architecture/pilot-architecture.png` | Earlier Case 001 pipeline diagram (endpoint → manager → dashboard) | Kept for history. It predates Cases 003/004, and its "FIM watches …" box describes the reference config, not a captured live config |

PNG copies are rendered from the SVG sources with `scripts/render_graphics.sh`, so the two cannot drift apart.
