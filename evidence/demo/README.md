# FIM Lifecycle Test Record (Case 002)

## Purpose

This folder holds the execution record of the controlled FIM test run with `scripts/fim_demo.sh`. The script creates, modifies and deletes a comment-only file under `/etc/ssh/sshd_config.d/`, which exercises the custom rule paths without changing SSH behaviour.

## Recorded actions (UTC)

```text
2026-10-14T02:15:10Z  CREATED  /etc/ssh/sshd_config.d/99-fim-demo.conf  (expect rule 100101)
2026-10-14T02:15:20Z  MODIFIED /etc/ssh/sshd_config.d/99-fim-demo.conf  (expect rule 100100)
2026-10-14T02:16:05Z  DELETED  /etc/ssh/sshd_config.d/99-fim-demo.conf  (expect rule 100102)
```

## Status

**TEST RECORDED. ALERTS NOT CAPTURED. RE-RUN REQUIRED.**

- The timeline shows the three filesystem actions happened. It does not show that Wazuh generated Rules 100101, 100100 and 100102.
- This run is about 2.5 hours **earlier** than the current agent's registration time (14 Oct 00:50:40 EDT = 04:50:40 UTC, from EP-01), so it cannot be matched to alerts from the current enrollment.
- The line format comes from an earlier version of the script. The current script also logs `; verify in Wazuh` and a SHA-256 for each step.

## What a complete record needs

1. `wazuh-analysisd -t` passes on the manager with the v2.2 rules deployed.
2. The live agent config shows real-time FIM covering `/etc/ssh`.
3. A new timeline from the current script, committed here.
4. Wazuh captures of 100101, 100100 and 100102 for that run, with the path in the description.
5. `syscheck.sha256_after` in the create/modify alerts matching the timeline hashes.
6. The Rule 5402 alert for the `sudo … fim_demo.sh` command (who ran it).
7. `syscheck.diff` in an expanded event, if diffs are claimed.

Until then, this folder is labelled **test execution evidence**, not verified alert telemetry.
