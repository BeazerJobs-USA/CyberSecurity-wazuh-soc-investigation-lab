#!/usr/bin/env bash
# Safe Wazuh FIM demonstration for the Ubuntu lab endpoint.
#
#   sudo scripts/fim_demo.sh             create + modify the demo file
#                                        (expected: 100101, then 100100)
#   sudo scripts/fim_demo.sh --cleanup   delete the demo file
#                                        (expected: 100102)
#
# IMPORTANT:
# This script proves that the filesystem test actions occurred. It does NOT
# prove that Wazuh generated the expected alerts. Capture and export the
# corresponding Wazuh events before marking a rule as verified.
#
# The demo file is comment-only, so it changes no SSH behavior and sshd is
# never restarted.
#
# Prerequisites:
#   - Wazuh agent running
#   - a real-time directory watch covering /etc/ssh
#   - detections/local_rules.xml deployed and manager validation passed
set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/etc/ssh/sshd_config.d}"
DEMO_FILE="$DEMO_DIR/99-fim-demo.conf"
SLEEP_SECS="${SLEEP_SECS:-10}"
LOG="${LOG:-./fim_demo_timeline.txt}"

utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { printf '%s  %s\n' "$(utc)" "$*" | tee -a "$LOG"; }

if [[ "$DEMO_DIR" == "/etc/ssh/sshd_config.d" && "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: sudo $0 ${1:-}"; exit 1
fi

if [[ ! -d "$DEMO_DIR" ]]; then
  echo "Directory $DEMO_DIR does not exist. Stopping."; exit 1
fi

if [[ "${1:-}" == "--cleanup" ]]; then
  [[ -e "$DEMO_FILE" ]] || { echo "Nothing to clean up: $DEMO_FILE not found."; exit 1; }
  rm "$DEMO_FILE"
  log "DELETED  $DEMO_FILE  (expect rule 100102; verify in Wazuh)"
  exit 0
fi

if [[ -e "$DEMO_FILE" ]]; then
  echo "$DEMO_FILE already exists. Run with --cleanup first."; exit 1
fi

cat > "$DEMO_FILE" <<'DEMO'
# FIM demonstration file. Comment only: no SSH behavior is changed by this file.
DEMO
chmod 0644 "$DEMO_FILE"
log "CREATED  $DEMO_FILE  (expect rule 100101; verify in Wazuh)"

sleep "$SLEEP_SECS"

printf '# Second comment added at %s\n' "$(utc)" >> "$DEMO_FILE"
log "MODIFIED $DEMO_FILE  (expect rule 100100; verify in Wazuh)"

echo
echo "No SSH restart was performed. Timeline saved to $LOG"
echo "Capture/export the Wazuh alerts, then run: sudo $0 --cleanup"
