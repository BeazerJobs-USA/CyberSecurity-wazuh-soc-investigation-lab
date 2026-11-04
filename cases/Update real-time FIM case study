# Case 002 — Real-Time File Integrity Monitoring

## Objective

Validate that Wazuh can detect file creation, modification, and deletion activity in real time on a monitored Linux endpoint.

The test focused on changes within `/etc`, a sensitive Linux configuration directory, and verified that events generated on the Vultr endpoint were successfully forwarded to the AWS-hosted Wazuh SIEM for centralized investigation.

## Environment

**Endpoint:** `vultr-security-lab`  
**Operating System:** Ubuntu 26.04.1 LTS  
**Wazuh Agent:** 4.14.8  
**SIEM:** Wazuh 4.14.8  
**Wazuh Manager:** AWS EC2, Ubuntu 24.04  
**Network:** Private Tailscale connectivity between the endpoint and SIEM

## FIM Configuration

Real-time File Integrity Monitoring was enabled for `/etc` on the Vultr endpoint.

```xml
<directories realtime="yes" report_changes="yes">/etc</directories>
```

This configuration allows Wazuh to detect file activity without waiting for the normal scheduled FIM scan.

## Test Procedure

A controlled test file was created inside `/etc`:

```bash
sudo touch /etc/wazuh-fim-test.conf
```

The file was then modified:

```bash
echo "FIM test change $(date)" | sudo tee /etc/wazuh-fim-test.conf
```

Finally, the file was deleted:

```bash
sudo rm /etc/wazuh-fim-test.conf
```

These actions were intentionally generated as a validation exercise and were not malicious activity.

## Detection Results

Wazuh successfully detected all three actions.

| Action | Wazuh Rule | Level | Result |
| --- | --- | ---: | --- |
| File created | Rule 554 — File added to the system | 5 | Detected |
| File modified | Rule 550 — Integrity checksum changed | 7 | Detected |
| File deleted | Rule 553 — File deleted | 7 | Detected |

All events were associated with the `vultr-security-lab` endpoint and the path:

```text
/etc/wazuh-fim-test.conf
```

## Investigation

The Wazuh File Integrity Monitoring dashboard was used to investigate the activity.

The event sequence showed:

```text
File created
     ↓
File modified
     ↓
File deleted
```

The events were centralized from the remote Vultr endpoint into the AWS-hosted Wazuh SIEM.

The modification event received a higher severity than the initial file creation event, allowing the analyst to prioritize changes to monitored files.

## Analyst Assessment

The activity was determined to be an authorized controlled test.

In a real environment, unexpected modifications to configuration files under `/etc` could indicate:

- unauthorized administrative activity
- persistence attempts
- security configuration tampering
- application or service configuration changes
- attacker modification of authentication or remote-access settings

The alert alone does not prove malicious activity. Additional telemetry such as authentication logs, auditd events, process execution, user attribution, and change context would be used to determine whether the activity was legitimate.

## Outcome

The test successfully demonstrated:

- real-time Linux file monitoring
- detection of file creation
- detection of file modification
- detection of file deletion
- centralized endpoint telemetry
- Wazuh FIM investigation
- severity-based alert analysis

This validated the end-to-end monitoring path:

```text
Vultr Linux Endpoint
        ↓
Wazuh Agent
        ↓
Private Tailscale Network
        ↓
AWS Wazuh Manager
        ↓
Wazuh Indexer
        ↓
File Integrity Monitoring Dashboard
        ↓
Analyst Investigation
```

## Evidence

### FIM Events

![FIM Events](../evidence/fim/02_fim_events.png)

The event view demonstrates creation, modification, and deletion of `/etc/wazuh-fim-test.conf`.

### FIM Dashboard

![FIM Dashboard](../evidence/fim/01_fim_dashboard.png)

The dashboard summarizes the three actions detected during the controlled validation test.

### Detailed Modification Event

![Modified Event](../evidence/fim/03_fim_modified_event.png)

The expanded modification event provides additional event metadata for analyst review.

## Limitations

This case represents a controlled detection validation exercise and should not be interpreted as evidence of a real compromise.

The test proves that the monitoring and detection pipeline operates as intended. Additional process, authentication, and audit telemetry would be required to establish attacker intent or attribution during a real incident.

## Next Steps

Future investigation scenarios will correlate FIM activity with:

- SSH authentication events
- sudo and privilege activity
- Linux auditd telemetry
- SSH configuration changes
- Fail2ban activity

This will allow file modifications to be analyzed within a broader SOC investigation workflow rather than as isolated alerts.
