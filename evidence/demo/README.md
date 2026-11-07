# Safe FIM Lifecycle Test Evidence

## Purpose

This directory contains the execution record for the controlled FIM lifecycle test performed with `scripts/fim_demo.sh`.

The script creates, modifies, and deletes a comment only file under `/etc/ssh/sshd_config.d/`. It is designed to exercise the custom rule paths without changing active SSH behavior.

## Recorded test actions

```text
2026-10-14T02:15:10Z  CREATED  /etc/ssh/sshd_config.d/99-fim-demo.conf  (expect rule 100101)
2026-10-14T02:15:20Z  MODIFIED /etc/ssh/sshd_config.d/99-fim-demo.conf  (expect rule 100100)
2026-10-14T02:16:05Z  DELETED  /etc/ssh/sshd_config.d/99-fim-demo.conf  (expect rule 100102)
```

## Current status

**TEST EXECUTED. ALERT VERIFICATION PENDING.**

The timeline proves that the three filesystem actions occurred. It does not prove that Wazuh generated Rules 100101, 100100, and 100102 for those actions.

## Required evidence before calling this case verified

1. `wazuh-analysisd -t` passes on the manager after the v2 rules are deployed.
2. The live agent configuration shows directory based FIM coverage for `/etc/ssh`.
3. A Wazuh event capture shows Rule 100101 for the test file creation.
4. A Wazuh event capture shows Rule 100100 for the test file modification and the v2 `$(file)` description.
5. A Wazuh event capture shows Rule 100102 for the cleanup deletion.
6. If the project claims text change reporting, the expanded event should show `syscheck.diff`.

Until those artifacts exist, this directory is intentionally labeled **test execution evidence**, not verified alert telemetry.
