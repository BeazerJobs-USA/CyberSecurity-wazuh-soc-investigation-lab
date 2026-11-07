#!/usr/bin/env bash
# Safe Wazuh FIM demonstration for the Ubuntu lab endpoint.
#
#   sudo scripts/fim_demo.sh             create + modify the demo file
#                                        (expect rule 100101, then rule 100100)
#   sudo scripts/fim_demo.sh --cleanup   delete the demo file (expect rule 100102)
#
# The demo file is comment-only, so it changes no SSH behavior, and sshd is
# never restarted. It is named 99-* because sshd reads drop-ins in lexical
# order and keeps the first value for each keyword, so a 99- file cannot
# override anything set earlier.
#
# Prerequisites: Wazuh agent running, /etc/ssh/sshd_config.d monitored by FIM,
# and detections/local_rules.xml loaded on the manager.
#
# Every action is printed with a UTC timestamp and appended to a timeline file.
# The Wazuh dashboard shows your BROWSER's time zone, so convert before
# matching alerts to this timeline.
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
  log "DELETED  $DEMO_FILE  (expect rule 100102)"
  exit 0
fi

if [[ -e "$DEMO_FILE" ]]; then
  echo "$DEMO_FILE already exists. Run with --cleanup first."; exit 1
fi

cat > "$DEMO_FILE" <<'DEMO'
# FIM demonstration file. Comment only: no SSH behavior is changed by this file.
DEMO
chmod 0644 "$DEMO_FILE"
log "CREATED  $DEMO_FILE  (expect rule 100101)"

sleep "$SLEEP_SECS"

printf '# Second comment added at %s\n' "$(utc)" >> "$DEMO_FILE"
log "MODIFIED $DEMO_FILE  (expect rule 100100)"

echo
echo "No SSH restart was performed. Timeline saved to $LOG"
echo "Capture the alerts in Threat Hunting, then run: sudo $0 --cleanup"
