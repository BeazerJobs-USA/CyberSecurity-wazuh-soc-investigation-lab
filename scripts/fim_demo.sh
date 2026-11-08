#!/usr/bin/env bash
# Safe Wazuh FIM test for the OpenSSH drop-in directory on the Ubuntu endpoint.
#
#   sudo scripts/fim_demo.sh             create + modify the demo file
#                                        (expected: 100101, then 100100)
#   sudo scripts/fim_demo.sh --cleanup   delete the demo file
#                                        (expected: 100102)
#
# IMPORTANT:
# This script proves that the filesystem actions happened. It does NOT prove
# that Wazuh generated the expected alerts. Capture the matching Wazuh events
# before marking a rule as verified.
#
# Matching alerts to actions:
#   - Each step logs the file's SHA-256. The Wazuh alert for the same change
#     carries syscheck.sha256_after; equal hashes tie the alert to this run.
#   - Running the script with sudo also produces a Wazuh 5402 alert
#     (COMMAND=...fim_demo.sh). Capture it: it shows who ran the test.
#   - Timeline timestamps are UTC. The Wazuh dashboard shows browser local time
#     unless its timezone setting was changed.
#
# The demo file is comment-only, so it changes no SSH behaviour, and sshd is
# never restarted or reloaded.
#
# Prerequisites:
#   - Wazuh agent running
#   - a real-time FIM directory watch covering /etc/ssh
#   - detections/local_rules.xml deployed and wazuh-analysisd -t passed
set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/etc/ssh/sshd_config.d}"
DEMO_FILE="$DEMO_DIR/99-fim-demo.conf"
SLEEP_SECS="${SLEEP_SECS:-10}"
LOG="${LOG:-./fim_demo_timeline.txt}"

utc()  { date -u +%Y-%m-%dT%H:%M:%SZ; }
log()  { printf '%s  %s\n' "$(utc)" "$*" | tee -a "$LOG"; }
hash() { sha256sum "$1" | cut -d' ' -f1; }

if [[ "$DEMO_DIR" == "/etc/ssh/sshd_config.d" && "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: sudo $0 ${1:-}"; exit 1
fi

if [[ ! -d "$DEMO_DIR" ]]; then
  echo "Directory $DEMO_DIR does not exist. Stopping."; exit 1
fi

if [[ "${1:-}" == "--cleanup" ]]; then
  [[ -e "$DEMO_FILE" ]] || { echo "Nothing to clean up: $DEMO_FILE not found."; exit 1; }
  log "START    cleanup on host=$(hostname) by user=${SUDO_USER:-$(id -un)}"
  rm "$DEMO_FILE"
  log "DELETED  $DEMO_FILE  (expect rule 100102; verify in Wazuh)"
  exit 0
fi

if [[ -e "$DEMO_FILE" ]]; then
  echo "$DEMO_FILE already exists. Run with --cleanup first."; exit 1
fi

log "START    test on host=$(hostname) by user=${SUDO_USER:-$(id -un)}"

cat > "$DEMO_FILE" <<'DEMO'
# FIM demonstration file. Comment only: no SSH behaviour is changed by this file.
DEMO
chmod 0644 "$DEMO_FILE"
log "CREATED  $DEMO_FILE  sha256=$(hash "$DEMO_FILE")  (expect rule 100101; verify in Wazuh)"

sleep "$SLEEP_SECS"

printf '# Second comment added at %s\n' "$(utc)" >> "$DEMO_FILE"
log "MODIFIED $DEMO_FILE  sha256=$(hash "$DEMO_FILE")  (expect rule 100100; verify in Wazuh)"

echo
echo "No SSH restart or reload was performed. Timeline saved to $LOG"
echo "Capture the Wazuh alerts (compare syscheck.sha256_after), then run: sudo $0 --cleanup"
