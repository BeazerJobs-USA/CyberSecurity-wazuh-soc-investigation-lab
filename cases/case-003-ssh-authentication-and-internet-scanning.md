# Case 003: SSH Authentication and Internet Scanning Investigation

## Objective

Investigate SSH authentication activity on the `vultr-security-lab` endpoint and distinguish authorized administrative access from suspicious Internet scanning, invalid user login attempts, and correlated brute force activity.

## Environment

* **Endpoint:** `vultr-security-lab`
* **Operating System:** Ubuntu 26.04.1 LTS
* **Wazuh Agent:** 4.14.8
* **SIEM:** AWS hosted Wazuh 4.14.8
* **Administrative Connectivity:** Tailscale private network
* **SSH Protection:** Fail2ban
* **Authentication Method:** SSH public key authentication for authorized administration

## Observed Activity

The endpoint received repeated SSH authentication attempts from external Internet addresses using usernames that did not exist on the system.

Examples observed in the Linux authentication logs included:

* `admin`
* `debian`
* `ubuntu`
* `default`
* `support`
* `centos`
* `jenkins`

These events were consistent with opportunistic Internet scanning and attempts to identify valid SSH accounts.

A separate controlled test using the username `fakeuser` was generated from the authorized workstation to confirm that invalid user activity was detected and forwarded to Wazuh.

The controlled test is documented separately from naturally occurring Internet activity so that test traffic is not presented as attacker activity.

## Invalid User Detection

Wazuh Rule 5710 detected attempts to authenticate using SSH accounts that did not exist on the endpoint.

```text
Rule ID: 5710
Description: sshd: Attempt to login using a non-existent user
Level: 5
```

The Wazuh Threat Hunting view showed multiple Rule 5710 events associated with the `vultr-security-lab` endpoint.

This confirmed that SSH authentication telemetry from the Linux endpoint was being collected and forwarded successfully to the centralized Wazuh SIEM.

## Brute Force Correlation

Wazuh also generated Rule 5712 alerts after correlating repeated invalid user SSH activity.

```text
Rule ID: 5712
Description: sshd: brute force trying to get access to the system. Non existent user.
Level: 10
```

Two Rule 5712 alerts were observed during the investigation period.

This is important because Wazuh did not treat every failed authentication attempt only as an isolated event. The SIEM correlated repeated activity and generated a higher severity alert when the event pattern met the conditions for Rule 5712.

The Rule 5712 alerts confirm correlation of repeated SSH authentication failures. They do not by themselves prove that an attacker successfully gained access to the endpoint.

## Authorized Authentication

A successful SSH login from the authorized Windows workstation was also observed.

The administrative session used the Tailscale private network and authenticated to the `linuxuser` account using the configured SSH key.

Wazuh recorded successful SSH authentication activity, allowing the legitimate session to be compared with the suspicious external authentication attempts.

This comparison provided useful investigation context because the authorized session had known characteristics:

* expected username
* successful authentication result
* SSH key based authentication
* known administrative workstation
* Tailscale network path
* expected time of activity

These attributes helped distinguish authorized administration from unrelated Internet scanning.

## Fail2ban Response

Fail2ban was active on the endpoint and monitoring the SSH service.

At the time evidence was collected, Fail2ban reported:

```text
Total failed attempts: 8439
Total banned: 265
Currently banned: 1
```

These values represent cumulative Fail2ban statistics observed on the endpoint at that time.

They should not be interpreted as a one to one match with the Wazuh Rule 5710 or Rule 5712 alerts shown in this case.

Instead, the Fail2ban statistics demonstrate that the endpoint had experienced a significant amount of SSH authentication activity and that automated blocking was actively being enforced.

The defensive workflow was:

```text
Internet SSH activity
        ↓
Linux authentication logs
        ↓
Wazuh collection and correlation
        ↓
Threat Hunting and analyst review
        ↓
Fail2ban automated enforcement
```

## Investigation

The investigation used several sources of context to distinguish expected activity from suspicious activity.

The analyst reviewed:

* authentication result
* username
* event timestamp
* Wazuh rule ID
* source context
* authentication method
* Tailscale administrative activity
* Fail2ban status
* surrounding SSH events

Rule 5710 provided visibility into invalid account authentication attempts.

Rule 5712 provided higher severity correlation when repeated invalid user activity met the Wazuh brute force detection conditions.

Successful SSH authentication provided a comparison point for legitimate administrative access.

Fail2ban provided an additional host level control capable of automatically blocking repeated offenders.

## Analyst Assessment

The repeated invalid user events were consistent with automated Internet scanning and SSH account probing commonly seen on publicly reachable SSH services.

No evidence collected in this case demonstrated successful unauthorized authentication or system compromise.

The activity should therefore be classified as suspicious authentication activity rather than a confirmed intrusion.

The successful administrative login was expected and authorized.

The combination of Wazuh telemetry, authentication logs, Tailscale context, and Fail2ban status allowed authorized activity to be separated from suspicious external activity without overstating the evidence.

## Outcome

This case demonstrated:

* centralized SSH authentication monitoring
* detection of invalid user authentication attempts
* Wazuh Rule 5710 alerting
* Wazuh Rule 5712 brute force correlation
* visibility into successful SSH authentication
* comparison of authorized and suspicious activity
* Fail2ban automated enforcement
* analyst review of Linux authentication telemetry
* correlation of endpoint activity with SIEM alerts

## Evidence

### Rule 5710 Invalid User Detection

![Rule 5710 Invalid Users](../evidence/ssh-authentication/01_rule5710_invalid_users.png)

Shows Wazuh Threat Hunting events generated by Rule 5710 for attempts to authenticate with SSH usernames that did not exist on the endpoint.

### Rule 5715 Successful Authentication

![Rule 5715 Successful Login](../evidence/ssh-authentication/02_rule5715_successful_login.png)

Shows successful SSH authentication associated with authorized administrative access.

### Rule 5712 Brute Force Correlation

![Rule 5712 Brute Force Correlation](../evidence/ssh-authentication/03_rule5712_bruteforce_if_present.png)

Shows Wazuh Rule 5712 alerts generated after repeated invalid user authentication activity was correlated into a higher severity detection.

### Fail2ban Status

![Fail2ban Status](../evidence/ssh-authentication/04_fail2ban_status.png)

Shows the Fail2ban SSH jail status and the cumulative failure and blocking statistics observed during the investigation.

## Limitations

This case does not establish attacker identity, intent, or successful compromise.

Repeated SSH authentication attempts are common on Internet reachable systems and may originate from automated scanners, bots, security research infrastructure, or malicious actors.

The evidence supports classification of the activity as suspicious authentication behavior and Internet scanning.

The Fail2ban statistics are cumulative endpoint statistics and are not presented as direct counts of the Wazuh alerts documented in this case.

## Conclusion

The investigation demonstrated that the Linux endpoint, Wazuh SIEM, and Fail2ban provided complementary visibility and protection for SSH authentication activity.

Wazuh identified individual invalid user attempts, correlated repeated activity into higher severity Rule 5712 alerts, and provided centralized visibility for investigation.

At the same time, legitimate SSH administration remained distinguishable through authentication results, known account activity, SSH key usage, and Tailscale context.

No evidence collected during this investigation indicated successful unauthorized access.