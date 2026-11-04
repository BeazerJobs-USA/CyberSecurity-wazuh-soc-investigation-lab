# Wazuh SOC Investigation Lab

Multi-cloud cybersecurity lab built to practice SOC monitoring, detection engineering, Linux security, and incident investigation using Wazuh.

## Environment

- AWS EC2 Wazuh SIEM
- Vultr Ubuntu security endpoint
- Wazuh 4.14.8
- Linux auditd
- Real-time File Integrity Monitoring
- UFW
- Fail2ban
- Tailscale private networking

## Architecture

Windows Workstation  
↓  
Tailscale  
↓  
Vultr Security Lab  
↓  
Wazuh Agent  
↓  
Tailscale  
↓  
AWS Wazuh SIEM  
↓  
Threat Hunting and Analyst Investigation

## Detection Cases

### Case 001 — SSH Configuration Change Detection

Custom auditd-based Wazuh detection for changes to SSH configuration files.

Documentation in progress.

### Case 002 — Real-Time File Integrity Monitoring

Validated real-time detection of file creation, modification, and deletion on a monitored Linux endpoint.

Detected:

- Rule 554 — File added to the system
- Rule 550 — Integrity checksum changed
- Rule 553 — File deleted

[View Case 002](cases/case-002-real-time-file-integrity-monitoring.md)

## Current Status

The core SIEM and endpoint telemetry pipeline is operational. Additional investigation cases will cover SSH authentication, privilege activity, and correlated Linux audit telemetry.

## Disclaimer

This repository documents a controlled cybersecurity lab environment. Test activity was intentionally generated for learning and detection validation purposes.
