# Case 001: Wazuh FIM SSH Configuration Change Detection

## Executive Summary

| Attribute | Investigation Details |
|:---|:---|
| **Incident Title** | OpenSSH configuration modification detected by custom Wazuh FIM rule |
| **Monitored Asset** | `vultr-security-lab` on Vultr |
| **Current Endpoint Snapshot** | Ubuntu 26.04.1 LTS, Wazuh agent v4.14.8, agent ID 001 |
| **Telemetry Path** | Wazuh agent reporting through the lab's cloud monitoring architecture |
| **Detection Mechanism** | Wazuh FIM/syscheck parent Rule 550 with custom child Rule 100100 |
| **Alert Timestamp** | 14 Oct 2026, 01:48:49, dashboard local time |
| **Alert Level** | Custom Rule 100100, Level 8 |
| **Investigation Status** | Alert observed; final change attribution and configuration diff remain unverified |
| **Disposition** | **Pending supporting evidence** |

## Why This Case Matters

Changes to `/etc/ssh/sshd_config` or `/etc/ssh/sshd_config.d/` can alter remote access controls. This case demonstrates an analyst workflow that starts with a real SIEM alert, validates what the dashboard actually proves, identifies gaps, and avoids assigning a benign or malicious disposition without supporting host evidence.

---

## Visual Evidence

### EV 01: Rule 100100 Event

<div align="center">
  <img src="../evidence/observed/01_rule100100_events_view.png" alt="Wazuh Rule 100100 event" width="95%"/>
</div>

**Observed:** one Level 8 Rule 100100 hit for `vultr-security-lab` at approximately 01:48:49.

The historical alert description ended with a blank value after `modified on`. That defect became part of the troubleshooting story and led to the revised rule description using `$(file)`.

### EV 02: Rule 100100 Dashboard Context

<div align="center">
  <img src="../evidence/observed/02_rule100100_dashboard_view.png" alt="Wazuh Rule 100100 dashboard context" width="95%"/>
</div>

**Observed:** one total event in the filtered Rule 100100 view and no Level 12 or greater alerts in that same query scope.

> [!IMPORTANT]
> The authentication counters are also filtered to Rule 100100. They cannot be used as evidence that the host had no authentication failures outside that query.

### EV 03: 24 Hour `sshd_config` Search

<div align="center">
  <img src="../evidence/observed/03_sshd_config_search_24h.png" alt="Wazuh sshd_config 24 hour context search" width="95%"/>
</div>

**Observed:** 19 Level 3 events were returned and the Wazuh dashboard associated the results with `T1548.003 Sudo and Sudo Caching`.

The ATT&CK classification identifies an elevation mechanism. It does **not** prove that every event was authorized, benign, or tied to the Rule 100100 change.

---

## Detection Basis

The repository's `local_rules.xml` shows Rule 100100 as a child of built in Wazuh FIM Rule 550:

```xml
<rule id="100100" level="8">
  <if_sid>550</if_sid>
  <field name="file" type="pcre2">^/etc/ssh/sshd_config($|\.d/.*)</field>
  <description>SSH configuration file modified: $(file)</description>
</rule>
```

This means the observed Rule 100100 event is defensibly described as **FIM/syscheck based**. Although `auditd` is active on the current endpoint, the repository does not contain evidence proving that the historical Rule 100100 alert was generated from a standalone auditd watch.

---

## Evidence Gaps and Required Verification

| Step | Status | What Is Still Needed |
|:---|:---:|:---|
| Identify exact file/path from expanded Rule 100100 alert | Pending | Exported alert JSON or expanded event fields |
| Review `syscheck.diff` | Pending | Alert field showing actual changed text, if available |
| Attribute actor/process | Pending | Correlated auth/audit evidence at the Oct 14 alert timestamp |
| Validate SSH syntax | Pending | `sudo sshd -t` output |
| Validate effective SSH posture | Pending | `sudo sshd -T` output |
| Determine change authorization | Pending | Maintenance record or operator confirmation tied to the timestamp |

## Analyst Conclusion

**Verified:** Rule 100100 fired as a Level 8 custom child of Wazuh FIM Rule 550 against the monitored endpoint.

**Not yet verified:** the exact changed directive, the actor/process responsible, whether the change was authorized, and whether the current v2 `$(file)` description has been observed in a complete lifecycle test.

The correct disposition is therefore **pending supporting evidence**, not “benign change” and not “malicious tampering.”
