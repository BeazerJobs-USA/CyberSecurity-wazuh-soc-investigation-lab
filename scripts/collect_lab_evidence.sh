#!/usr/bin/env bash
# Point-in-time evidence snapshot for the monitored Ubuntu endpoint.
#
# Run on the endpoint:
#   bash scripts/collect_lab_evidence.sh [output_dir]
#
# Privacy: IP addresses are replaced with stable tokens that keep their class,
# so correlation still works inside one report:
#   <public-ip-1>, <tailscale-ip-1> (100.64.0.0/10), <private-ip-1> (RFC 1918),
#   <aws-private-host-1> (ip-a-b-c-d hostnames). Loopback is kept.
# The same address always gets the same token within one run, so you can still
# say "the source in auth.log is the source Fail2Ban banned".
# Review the file before committing: hostnames, usernames, paths and tailnet
# peer names are NOT removed.
set -uo pipefail     # no -e on purpose: one failing check must not stop the rest
umask 077

OUT_DIR="${1:-./collected_evidence}"
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/lab_evidence_$(date -u +%Y%m%dT%H%M%SZ).txt"

redact() {
  perl -pe '
    BEGIN { our (%map, %n); }
    sub tok { my ($v, $c) = @_; $map{$v} //= sprintf("<%s-%d>", $c, ++$n{$c}); $map{$v} }
    s{\bip-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})\b}{tok("ip-$1-$2-$3-$4", "aws-private-host")}ge;
    s{\b((?:\d{1,3}\.){3}\d{1,3})\b}{
      my $ip = $1; my @o = split /\./, $ip;
        ($ip =~ /^127\./ || $ip eq "0.0.0.0")                       ? $ip
      : ($o[0] == 100 && $o[1] >= 64 && $o[1] <= 127)               ? tok($ip, "tailscale-ip")
      : ($o[0] == 10 || ($o[0] == 172 && $o[1] >= 16 && $o[1] <= 31)
         || ($o[0] == 192 && $o[1] == 168))                         ? tok($ip, "private-ip")
      :                                                               tok($ip, "public-ip")
    }ge;
    s{\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b}{tok(lc $1, "mac")}ge;
    s{(?<![0-9A-Fa-f:.])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?![0-9A-Fa-f:])}
     { my $m = $1; ($m =~ /^::1?$/ || (($m =~ tr/://) < 4 && $m !~ /::/)) ? $m : tok($m, "ipv6") }ge;
  '
}
section() { printf '\n=== %s ===\n' "$1"; }

{
  echo "SOC Investigation Lab: endpoint evidence snapshot"
  echo "Collected UTC: $(date -u --iso-8601=seconds)"

  section "TIME SYNC AND TIMEZONE (needed to line up host logs with Wazuh)"
  timedatectl 2>&1

  section "OS AND KERNEL"
  grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release
  uname -sr
  ls /boot/vmlinuz-* 2>&1
  if [ -f /var/run/reboot-required ]; then
    cat /var/run/reboot-required
    echo "Packages requesting the reboot:"
    cat /var/run/reboot-required.pkgs 2>&1
  else
    echo "No reboot pending."
  fi

  section "SECURITY SERVICE STATE"
  for svc in wazuh-agent tailscaled ssh fail2ban auditd; do
    printf '%-16s %s\n' "$svc" "$(systemctl is-active "$svc" 2>&1)"
  done

  section "WAZUH AGENT"
  sudo /var/ossec/bin/wazuh-control info 2>&1

  section "WAZUH MANAGER CONNECTION (agent side)"
  sudo grep -A6 '<server>' /var/ossec/etc/ossec.conf 2>&1
  echo "Established connections to the manager port (default 1514/tcp):"
  sudo ss -tnp 2>&1 | grep -E ':1514\b' || echo "none found on 1514"

  section "FIM CONFIGURATION"
  sudo grep -nE '<directories' /var/ossec/etc/ossec.conf 2>&1
  if sudo test -f /var/ossec/etc/shared/agent.conf; then
    echo "Centralized config (agent.conf from the manager group):"
    sudo grep -nE '<directories' /var/ossec/etc/shared/agent.conf 2>&1
  fi

  section "SSH EFFECTIVE SETTINGS (what sshd would use if it started now)"
  sudo sshd -T 2>&1 | grep -E '^(permitrootlogin|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|permitemptypasswords|maxauthtries|x11forwarding) '

  section "SSH SYNTAX"
  sudo sshd -t 2>&1 && echo "sshd -t: OK"

  section "SSH SETTING SOURCES"
  sudo grep -rniE '^\s*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|KbdInteractiveAuthentication|MaxAuthTries)\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>&1

  section "SSH SUCCESSFUL LOGINS (last 7 days)"
  sudo journalctl -u ssh --since "-7 days" --no-pager 2>&1 | grep -E 'Accepted (publickey|password|keyboard-interactive)' | tail -n 50

  section "UFW"
  sudo ufw status verbose 2>&1

  section "FAIL2BAN SSHD"
  sudo fail2ban-client status sshd 2>&1
  for key in maxretry findtime bantime ignoreip; do
    printf '%-9s %s\n' "$key" "$(sudo fail2ban-client get sshd "$key" 2>&1 | tr '\n' ' ')"
  done

  section "AUDITD RULES"
  sudo auditctl -l 2>&1

  section "TAILSCALE"
  tailscale status 2>&1

  section "LISTENING SERVICES"
  sudo ss -lntup 2>&1

  section "RECENT SSH AUTHENTICATION CONTEXT"
  sudo journalctl -u ssh --since "-30 min" --no-pager 2>&1 | tail -n 80
} 2>&1 | redact > "$OUT"

echo "Evidence written to $OUT"
echo "Review it before committing. Publish only what the case study needs."
