#!/usr/bin/env bash
set -euo pipefail
ALLOW_IPS=(
  100.64.0.100
  100.64.0.45
  100.64.0.132
  100.64.0.103
  100.64.0.102
  100.64.0.11
  100.64.0.22
  100.64.0.13
)
ALLOW_IP6S=(
  2001:db8:a1e0::100
  2001:db8:a1e0::45
  2001:db8:a1e0::132
  2001:db8:a1e0::103
  2001:db8:a1e0::102
  2001:db8:a1e0::11
  2001:db8:a1e0::22
  2001:db8:a1e0::13
)

# B2 Restricted Guest Pass for GrokBot: ONLY :8080 StarHub Home OS Web/API, NEVER :22 SSH
GROKBOT_B2_IPS=(
  100.64.0.201
  100.64.0.202
)
GROKBOT_B2_IP6S=(
  2001:db8:a1e0::201
  2001:db8:a1e0::202
)

if command -v tailscale >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  while IFS=' ' read -r kind addr; do
    if [[ "${kind:-}" == "v4" && -n "${addr:-}" ]]; then
      GROKBOT_B2_IPS+=("$addr")
    elif [[ "${kind:-}" == "v6" && -n "${addr:-}" ]]; then
      GROKBOT_B2_IP6S+=("$addr")
    fi
  done < <(tailscale status --json 2>/dev/null | python3 -c '
import json, re, sys
try:
    d = json.load(sys.stdin)
    pat = re.compile(r"^(grok-?bot|cso-grokbot|catx?-box)", re.I)
    for p in (d.get("Peer") or {}).values():
        hn = (p.get("HostName") or "").strip()
        dn = (p.get("DNSName") or "").split(".")[0].strip()
        if pat.match(hn) or pat.match(dn):
            for ip in p.get("TailscaleIPs") or []:
                print(("v6 " if ":" in ip else "v4 ") + ip)
except Exception:
    pass
' || true)
fi

for _ in $(seq 1 30); do iptables -C INPUT -j ts-input 2>/dev/null && ip6tables -C INPUT -j ts-input 2>/dev/null && break; sleep 0.5; done
iptables -N STARHUB-HOME-ACL 2>/dev/null || true
iptables -F STARHUB-HOME-ACL
iptables -A STARHUB-HOME-ACL -i lo -j RETURN
iptables -A STARHUB-HOME-ACL -s 127.0.0.0/8 -j RETURN
iptables -A STARHUB-HOME-ACL -s 192.0.2.0/24 -j RETURN
for ip in "${ALLOW_IPS[@]}"; do
  iptables -A STARHUB-HOME-ACL -s "${ip}/32" -j RETURN
done

iptables -N STARHUB-BOT-NOSSH 2>/dev/null || true
iptables -F STARHUB-BOT-NOSSH
for gip in $(printf '%s\n' "${GROKBOT_B2_IPS[@]}" | sort -u); do
  [[ -z "$gip" ]] && continue
  iptables -A STARHUB-HOME-ACL -s "${gip}/32" -p tcp --dport 8080 -j RETURN
  iptables -A STARHUB-BOT-NOSSH -s "${gip}/32" -p tcp --dport 22 -j DROP
done
iptables -A STARHUB-HOME-ACL -j DROP

while iptables -C INPUT -p tcp --dport 22 -j STARHUB-BOT-NOSSH 2>/dev/null; do
  iptables -D INPUT -p tcp --dport 22 -j STARHUB-BOT-NOSSH
done
iptables -I INPUT 1 -p tcp --dport 22 -j STARHUB-BOT-NOSSH

while iptables -C INPUT -p tcp --dport 8080 -j STARHUB-HOME-ACL 2>/dev/null; do
  iptables -D INPUT -p tcp --dport 8080 -j STARHUB-HOME-ACL
done
iptables -I INPUT 1 -p tcp --dport 8080 -j STARHUB-HOME-ACL

if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -N STARHUB-HOME-ACL6 2>/dev/null || true
  ip6tables -F STARHUB-HOME-ACL6
  ip6tables -A STARHUB-HOME-ACL6 -i lo -j RETURN
  ip6tables -A STARHUB-HOME-ACL6 -s ::1/128 -j RETURN
  ip6tables -A STARHUB-HOME-ACL6 -s fe80::/10 -j RETURN
  for ip6 in "${ALLOW_IP6S[@]}"; do
    ip6tables -A STARHUB-HOME-ACL6 -s "${ip6}/128" -j RETURN
  done

  ip6tables -N STARHUB-BOT-NOSSH6 2>/dev/null || true
  ip6tables -F STARHUB-BOT-NOSSH6
  for gip6 in $(printf '%s\n' "${GROKBOT_B2_IP6S[@]}" | sort -u); do
    [[ -z "$gip6" ]] && continue
    ip6tables -A STARHUB-HOME-ACL6 -s "${gip6}/128" -p tcp --dport 8080 -j RETURN
    ip6tables -A STARHUB-BOT-NOSSH6 -s "${gip6}/128" -p tcp --dport 22 -j DROP
  done
  ip6tables -A STARHUB-HOME-ACL6 -j DROP

  while ip6tables -C INPUT -p tcp --dport 22 -j STARHUB-BOT-NOSSH6 2>/dev/null; do
    ip6tables -D INPUT -p tcp --dport 22 -j STARHUB-BOT-NOSSH6
  done
  ip6tables -I INPUT 1 -p tcp --dport 22 -j STARHUB-BOT-NOSSH6

  while ip6tables -C INPUT -p tcp --dport 8080 -j STARHUB-HOME-ACL6 2>/dev/null; do
    ip6tables -D INPUT -p tcp --dport 8080 -j STARHUB-HOME-ACL6
  done
  ip6tables -I INPUT 1 -p tcp --dport 8080 -j STARHUB-HOME-ACL6
fi
