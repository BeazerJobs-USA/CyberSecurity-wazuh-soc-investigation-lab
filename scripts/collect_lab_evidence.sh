#!/usr/bin/env bash
# Point-in-time snapshot of the monitored Ubuntu endpoint for the evidence folder.
#
# Run ON the monitored server:   bash scripts/collect_lab_evidence.sh [output_dir]
#
# Non-loopback IPv4/IPv6 addresses are redacted in the output. Machine ID and
# boot ID are never collected. Still read the file before committing it.
set -uo pipefail   # no -e on purpose: keep going if one section fails
umask 077

OUT_DIR="${1:-./collected_evidence}"
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/lab_evidence_$(date -u +%Y%m%dT%H%M%SZ).txt"

redact() {
  # IPv4: everything except loopback (127.x) and the 0.0.0.0 wildcard.
  # IPv6: anything with "::" or 4+ colons, except "::" and "::1". Clock times
  # (hh:mm:ss) have only 2 colons and are left alone.
  perl -pe '
    s/\b(?!127\.|0\.0\.0\.0\b)(?:\d{1,3}\.){3}\d{1,3}\b/<IPv4-REDACTED>/g;
    s{(?<![0-9A-Fa-f:.])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?![0-9A-Fa-f:])}
     { my $m = $1; ($m =~ /^::1?$/ || (($m =~ tr/://) < 4 && $m !~ /::/)) ? $m : "<IPv6-REDACTED>" }ge;
  '
}
section() { printf '\n=== %s ===\n' "$1"; }

{
  echo "SOC Investigation Lab: endpoint evidence snapshot"
  echo "Collected (UTC): $(date -u --iso-8601=seconds)"

  section "OS AND KERNEL"
  grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release
  uname -sr

  section "WAZUH AGENT"
  sudo /var/ossec/bin/wazuh-control info 2>&1
  echo "wazuh-agent service: $(systemctl is-active wazuh-agent 2>&1)"

  section "FIM CONFIGURATION (<directories> entries in ossec.conf)"
  sudo grep -nE '<directories' /var/ossec/etc/ossec.conf 2>&1

  section "SSH: EFFECTIVE SETTINGS (sshd -T)"
  sudo sshd -T 2>&1 | grep -E '^(permitrootlogin|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|permitemptypasswords|maxauthtries|x11forwarding) '

  section "SSH: CONFIG SYNTAX CHECK (sshd -t)"
  sudo sshd -t 2>&1 && echo "sshd -t: OK"

  section "SSH: WHERE KEY SETTINGS ARE DEFINED (sshd uses the first value it reads)"
  sudo grep -rniE '^\s*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>&1

  section "SSH: CONFIG FILE METADATA"
  sudo stat -c '%n  owner=%U  mode=%a  modified=%y' /etc/ssh/sshd_config 2>&1
  sudo ls -l --time-style=long-iso /etc/ssh/sshd_config.d/ 2>&1

  section "UFW"
  sudo ufw status verbose 2>&1

  section "LISTENING SERVICES"
  sudo ss -lntup 2>&1
} 2>&1 | redact > "$OUT"

echo "Evidence written to $OUT"
echo "Review it before committing. Add collected_evidence/ to .gitignore and copy over only what you intend to publish."
