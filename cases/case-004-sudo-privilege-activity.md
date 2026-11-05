# Case 004: Sudo and Privilege Activity Investigation

## Objective

Validate that Wazuh can detect and investigate privileged Linux activity when an authorized administrator executes commands through `sudo`.

The goal was to confirm that privileged command activity on the `vultr-security-lab` endpoint generated security telemetry that could be reviewed in the centralized AWS hosted Wazuh SIEM.

This case focuses on visibility and investigation of privileged execution. It does not represent a real privilege escalation attack.

## Environment

* **Endpoint:** `vultr-security-lab`
* **Operating System:** Ubuntu 26.04.1 LTS
* **Wazuh Agent:** 4.14.8
* **SIEM:** AWS hosted Wazuh 4.14.8
* **Administrative User:** `linuxuser`
* **Privilege Mechanism:** `sudo`
* **Administrative Connectivity:** Tailscale private network

## Validation Procedure

Controlled privileged activity was generated on the Vultr endpoint using the authorized `linuxuser` account.

The first command displayed the effective identity after execution through `sudo`.

```bash id="pqon5s"
sudo id
```

The output confirmed root execution.

```text id="7axvyk"
uid=0(root) gid=0(root) groups=0(root)
```

A second command was used as an additional validation.

```bash id="f3f88g"
sudo whoami
```

The command returned:

```text id="5tgbfj"
root
```

These commands were intentionally executed by an authorized administrator for detection validation.

They should not be interpreted as evidence of unauthorized privilege escalation.

## Detection Results

Wazuh detected the privileged activity and related PAM session events.

| Rule ID | Description | Level | Investigation Value |
| --- | --- | ---: | --- |
| 5402 | Successful sudo to ROOT executed. | 3 | Confirms successful sudo activity |
| 5501 | PAM: Login session opened. | 3 | Provides session context |
| 5502 | PAM: Login session closed. | 3 | Provides session closure context |

Multiple sudo related events were visible in Wazuh Threat Hunting for the `vultr-security-lab` endpoint.

The Rule 5402 alerts confirmed that Wazuh received and processed telemetry associated with successful execution through `sudo`.

The PAM events provided additional session context surrounding the privileged activity.

## Investigation

The investigation focused on determining whether the privileged activity matched expected administrative behavior.

The observed telemetry included:

```text id="pg4vo5"
Authorized user activity
        ↓
sudo command execution
        ↓
Successful root context
        ↓
Related PAM session telemetry
        ↓
Wazuh Threat Hunting
        ↓
Analyst review
```

The exact order in which related PAM and sudo events appear in the SIEM can depend on logging and event processing.

For that reason, the investigation relied on correlated timestamps, usernames, rule information, and known test activity rather than assuming that every related event must appear in one fixed sequence.

## Rule 5402 Analysis

Wazuh Rule 5402 generated alerts for successful `sudo` activity.

```text id="g71gxy"
Rule ID: 5402
Description: Successful sudo to ROOT executed.
Level: 3
```

A successful Rule 5402 event confirms that privileged execution through `sudo` occurred.

It does not determine whether the activity was authorized or malicious.

That distinction requires additional context.

Examples include:

* user identity
* command executed
* authentication activity
* event timestamp
* administrative session
* source context
* related auditd events
* surrounding SSH activity
* file or configuration changes following the command

## PAM Session Context

Wazuh also recorded PAM session activity associated with the administrative actions.

```text id="r1ubdd"
Rule ID: 5501
Description: PAM: Login session opened.
Level: 3
```

and:

```text id="4yhu8n"
Rule ID: 5502
Description: PAM: Login session closed.
Level: 3
```

These events provide useful session context but should not be interpreted as proof of malicious activity.

PAM session events can occur during normal administrative operations.

Their value comes from correlating them with the user, time, authentication activity, and privileged commands being investigated.

## Analyst Assessment

The observed activity was determined to be authorized because the commands were intentionally generated as part of the validation exercise.

No evidence collected in this case indicated unauthorized administrative access or system compromise.

In a real investigation, unexpected `sudo` activity would require additional analysis.

An analyst would review:

* originating user
* command executed
* authentication method
* event timestamp
* SSH session activity
* sudo authentication records
* related auditd telemetry
* file modifications
* configuration changes
* process execution
* activity occurring before and after the privileged command

Unexpected privileged execution could be associated with:

* legitimate system administration
* maintenance activity
* software installation
* configuration changes
* misuse of an authorized account
* stolen credentials
* attacker activity after initial access

A `sudo` alert alone does not establish which explanation is correct.

## Severity Interpretation

Rules 5402, 5501, and 5502 were observed at Level 3.

The level provides Wazuh alerting context but should not be used by itself to decide whether an event is harmless or malicious.

An expected administrative command may generate the same detection as unexpected privileged activity.

The analyst must use surrounding evidence to determine whether the activity matches normal system behavior.

## Investigation Workflow

The validated workflow was:

```text id="6qz5oq"
Vultr Linux Endpoint
        ↓
Authorized sudo activity
        ↓
Linux authentication and PAM telemetry
        ↓
Wazuh Agent
        ↓
AWS Wazuh SIEM
        ↓
Threat Hunting
        ↓
Analyst Investigation
```

This demonstrated centralized visibility into privileged activity occurring on the remote Linux endpoint.

## Outcome

This case demonstrated:

* monitoring of Linux sudo activity
* detection of successful root execution
* Wazuh Rule 5402 alerting
* PAM session visibility
* centralized Threat Hunting
* investigation of privileged administrative activity
* comparison of endpoint actions with SIEM telemetry
* interpretation of alert severity
* distinction between detection and proof of malicious activity

The validation confirmed that privileged Linux activity could be identified and investigated through the centralized Wazuh environment.

## Evidence

### Endpoint Overview

![Endpoint Overview](../evidence/sudo-privilege/00_endpoint_overview.png)

Shows the monitored `vultr-security-lab` endpoint in Wazuh and confirms that the agent was actively reporting security telemetry.

### Sudo Detection Overview

![Sudo Detection Overview](../evidence/sudo-privilege/01_sudo_detection_overview.png)

Shows sudo related activity visible in Wazuh Threat Hunting, including successful sudo events and related PAM telemetry.

### Rule 5402 Dashboard

![Rule 5402 Dashboard](../evidence/sudo-privilege/01_sudo_rule5402_dashboard.png)

Shows the Wazuh view filtered to Rule 5402 and confirms multiple `Successful sudo to ROOT executed.` alerts associated with the monitored endpoint.

### Sudo Event Details

![Sudo Event Details](../evidence/sudo-privilege/02_sudo_event_details.png)

Shows Rule 5402 event details associated with the `vultr-security-lab` endpoint, including timestamps, severity, and rule information used during the investigation.

### Controlled Privilege Commands

![Privilege Command Evidence](../evidence/sudo-privilege/03_privilege_command_evidence.png)

Shows the controlled commands used during validation.

```bash id="0wazj2"
sudo id
sudo whoami
```

The output confirmed successful execution with root privileges.

## Limitations

This case represents a controlled detection validation exercise and does not document an actual compromise.

The evidence confirms successful use of `sudo` and related security telemetry.

It does not establish attacker identity, malicious intent, credential theft, or unauthorized privilege escalation.

The test also used simple administrative commands that did not modify sensitive system configuration.

A real investigation would require additional telemetry to determine what actions occurred after privileged access was obtained.

Relevant sources could include auditd events, process execution data, SSH authentication logs, File Integrity Monitoring alerts, configuration changes, and additional system logs.

## Conclusion

The validation demonstrated that Wazuh provided centralized visibility into privileged Linux activity occurring on the Vultr endpoint.

Rule 5402 identified successful `sudo` execution while Rules 5501 and 5502 provided related PAM session context.

The investigation also demonstrated an important SOC principle: successful root execution is an event that requires context, not automatic proof of malicious privilege escalation.

By comparing the alerts with known administrative activity, user identity, command output, session information, and surrounding telemetry, the activity was correctly classified as authorized validation rather than a security incident.