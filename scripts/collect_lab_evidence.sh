#!/usr/bin/env bash
# Point in time evidence snapshot for the monitored Ubuntu endpoint.
#
# Run on the endpoint:
#   bash scripts/collect_lab_evidence.sh [output_dir]
#
# Non loopback IP addresses are redacted in the output. Review the file before
# committing it because logs may still contain usernames, paths, or other
# environment specific data.
set -uo pipefail
umask 077

OUT_DIR="${1:-./collected_evidence}"
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/lab_evidence_$(date -u +%Y%m%dT%H%M%SZ).txt"

redact() {
  perl -pe '
    s/\b(?!127\.|0\.0\.0\.0\b)(?:\d{1,3}\.){3}\d{1,3}\b/<IPv4-REDACTED>/g;
    s{(?<![0-9A-Fa-f:.])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?![0-9A-Fa-f:])}
     { my $m = $1; ($m =~ /^::1?$/ || (($m =~ tr/://) < 4 && $m !~ /::/)) ? $m : "<IPv6-REDACTED>" }ge;
  '
}
section() { printf '\n=== %s ===\n' "$1"; }

{
  echo "SOC Investigation Lab: endpoint evidence snapshot"
  echo "Collected UTC: $(date -u --iso-8601=seconds)"

  section "OS AND KERNEL"
  grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release
  uname -sr

  section "SECURITY SERVICE STATE"
  for svc in wazuh-agent tailscaled ssh fail2ban auditd; do
    printf '%-16s %s\n' "$svc" "$(systemctl is-active "$svc" 2>&1)"
  done

  section "WAZUH AGENT"
  sudo /var/ossec/bin/wazuh-control info 2>&1

  section "FIM CONFIGURATION"
  sudo grep -nE '<directories' /var/ossec/etc/ossec.conf 2>&1

  section "SSH EFFECTIVE SETTINGS"
  sudo sshd -T 2>&1 | grep -E '^(permitrootlogin|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|permitemptypasswords|maxauthtries|x11forwarding) '

  section "SSH SYNTAX"
  sudo sshd -t 2>&1 && echo "sshd -t: OK"

  section "SSH SETTING SOURCES"
  sudo grep -rniE '^\s*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|KbdInteractiveAuthentication|MaxAuthTries)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>&1

  section "UFW"
  sudo ufw status verbose 2>&1

  section "FAIL2BAN SSHD"
  sudo fail2ban-client status sshd 2>&1

  section "TAILSCALE"
  tailscale status 2>&1

  section "LISTENING SERVICES"
  sudo ss -lntup 2>&1

  section "RECENT SSH AUTHENTICATION CONTEXT"
  sudo journalctl -u ssh --since "-30 min" --no-pager 2>&1 | tail -n 80
} 2>&1 | redact > "$OUT"

echo "Evidence written to $OUT"
echo "Review it before committing. Publish only what is necessary for the case study."
