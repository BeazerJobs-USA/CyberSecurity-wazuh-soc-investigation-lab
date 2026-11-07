# Case 002: Safe FIM Lifecycle Test Harness

## Executive Summary

| Attribute | Investigation Details |
|:---|:---|
| **Purpose** | Exercise create, modify, and delete actions in the OpenSSH drop-in directory without changing SSH behavior |
| **Target** | `/etc/ssh/sshd_config.d/99-fim-demo.conf` |
| **Test Harness** | `scripts/fim_demo.sh` |
| **Expected Custom Rules** | Create 100101, Modify 100100, Delete 100102 |
| **Current Verification Status** | **TEST EXECUTED; WAZUH ALERT CAPTURE PENDING** |

## What the Existing Evidence Proves

The file `evidence/demo/fim_demo_timeline.txt` records that the demo script performed three filesystem actions:

```text
2026-10-14T02:15:10Z  CREATED  /etc/ssh/sshd_config.d/99-fim-demo.conf  (expect rule 100101)
2026-10-14T02:15:20Z  MODIFIED /etc/ssh/sshd_config.d/99-fim-demo.conf  (expect rule 100100)
2026-10-14T02:16:05Z  DELETED  /etc/ssh/sshd_config.d/99-fim-demo.conf  (expect rule 100102)
```

That timeline is valid evidence of **test execution**. It is not, by itself, evidence that Wazuh generated all three corresponding alerts.

## Expected Detection Logic

| Action | Built-in FIM Parent | Custom Child | Evidence State |
|:---|:---:|:---:|:---|
| File modified | 550 | 100100 | Custom rule observed historically in Case 001; v2 path rendering still needs live capture |
| File added | 554 | 100101 | Authored; alert capture pending |
| File deleted | 553 | 100102 | Authored; alert capture pending |

## Corrected Real-Time FIM Reference

Wazuh real-time FIM works on directories. The repository reference configuration therefore monitors `/etc/ssh` in real time and uses the custom PCRE2 rule filter to narrow custom alerts to `sshd_config` and `sshd_config.d/*`.

See `detections/ossec_fim_snippet.xml`.

## Definition of Done

Case 002 becomes **VERIFIED** only after all of the following are present:

1. Native manager validation passes with `sudo /var/ossec/bin/wazuh-analysisd -t`.
2. The corrected directory-based FIM configuration is confirmed on the live agent.
3. Wazuh Threat Hunting captures show Rule 100101 for create.
4. Wazuh Threat Hunting captures show Rule 100100 using the v2 `$(file)` description for modify.
5. Wazuh Threat Hunting captures show Rule 100102 for delete.
6. If claiming content change reporting, an alert is expanded to show `syscheck.diff`.

Until then, this case demonstrates **safe test design and expected detection logic**, not a completed lifecycle validation.
