#!/usr/bin/env bash
set -euo pipefail
for _ in $(seq 1 30); do
  iptables -C INPUT -j ts-input 2>/dev/null && \
  iptables -C FORWARD -j ts-forward 2>/dev/null && \
  ip6tables -C INPUT -j ts-input 2>/dev/null && break
  sleep 0.5
done

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

# B2 Restricted Guest Pass for GrokBot: ONLY :3001 Dashboard Web/API, NEVER :22 SSH or :8000/:9000/:9443 Portainer
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

iptables -N STARHUB-DASH-ACL 2>/dev/null || true
iptables -F STARHUB-DASH-ACL
iptables -A STARHUB-DASH-ACL -i lo -j RETURN
iptables -A STARHUB-DASH-ACL -s 127.0.0.0/8 -j RETURN
iptables -A STARHUB-DASH-ACL -s 192.0.2.0/24 -j RETURN
iptables -A STARHUB-DASH-ACL -s 172.16.0.0/12 -j RETURN
for ip in "${ALLOW_IPS[@]}"; do
  iptables -A STARHUB-DASH-ACL -s "${ip}/32" -j RETURN
done

# GrokBot B2: allow :3001 Dashboard (host INPUT :3001 and Docker DNAT ctorigdstport 3001 -> container :3000)
iptables -N STARHUB-BOT-NOSSH 2>/dev/null || true
iptables -F STARHUB-BOT-NOSSH
for gip in $(printf '%s\n' "${GROKBOT_B2_IPS[@]}" | sort -u); do
  [[ -z "$gip" ]] && continue
  iptables -A STARHUB-DASH-ACL -p tcp --dport 3001 -s "${gip}/32" -j RETURN
  if ! iptables -A STARHUB-DASH-ACL -p tcp -m conntrack --ctorigdstport 3001 -s "${gip}/32" -j RETURN 2>/dev/null; then
    iptables -A STARHUB-DASH-ACL -p tcp --dport 3000 -s "${gip}/32" -j RETURN
  fi
  iptables -A STARHUB-BOT-NOSSH -s "${gip}/32" -p tcp --dport 22 -j DROP
done
iptables -A STARHUB-DASH-ACL -j DROP

while iptables -C INPUT -p tcp --dport 22 -j STARHUB-BOT-NOSSH 2>/dev/null; do
  iptables -D INPUT -p tcp --dport 22 -j STARHUB-BOT-NOSSH
done
iptables -I INPUT 1 -p tcp --dport 22 -j STARHUB-BOT-NOSSH

for p in 3001 3000 8000 9443 9000; do
  while iptables -C INPUT -p tcp --dport "$p" -j STARHUB-DASH-ACL 2>/dev/null; do
    iptables -D INPUT -p tcp --dport "$p" -j STARHUB-DASH-ACL
  done
  iptables -I INPUT 1 -p tcp --dport "$p" -j STARHUB-DASH-ACL
done

for p in 3001 3000 8000 9443 9000; do
  while iptables -C FORWARD -p tcp --dport "$p" -j STARHUB-DASH-ACL 2>/dev/null; do
    iptables -D FORWARD -p tcp --dport "$p" -j STARHUB-DASH-ACL
  done
  iptables -I FORWARD 1 -p tcp --dport "$p" -j STARHUB-DASH-ACL
  if iptables -L DOCKER-USER >/dev/null 2>&1; then
    while iptables -C DOCKER-USER -p tcp --dport "$p" -j STARHUB-DASH-ACL 2>/dev/null; do
      iptables -D DOCKER-USER -p tcp --dport "$p" -j STARHUB-DASH-ACL
    done
    iptables -I DOCKER-USER 1 -p tcp --dport "$p" -j STARHUB-DASH-ACL
  fi
done

if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -N STARHUB-DASH-ACL6 2>/dev/null || true
  ip6tables -F STARHUB-DASH-ACL6
  ip6tables -A STARHUB-DASH-ACL6 -i lo -j RETURN
  ip6tables -A STARHUB-DASH-ACL6 -s ::1/128 -j RETURN
  ip6tables -A STARHUB-DASH-ACL6 -s fe80::/10 -j RETURN
  for ip6 in "${ALLOW_IP6S[@]}"; do
    ip6tables -A STARHUB-DASH-ACL6 -s "${ip6}/128" -j RETURN
  done

  ip6tables -N STARHUB-BOT-NOSSH6 2>/dev/null || true
  ip6tables -F STARHUB-BOT-NOSSH6
  for gip6 in $(printf '%s\n' "${GROKBOT_B2_IP6S[@]}" | sort -u); do
    [[ -z "$gip6" ]] && continue
    ip6tables -A STARHUB-DASH-ACL6 -p tcp --dport 3001 -s "${gip6}/128" -j RETURN
    if ! ip6tables -A STARHUB-DASH-ACL6 -p tcp -m conntrack --ctorigdstport 3001 -s "${gip6}/128" -j RETURN 2>/dev/null; then
      ip6tables -A STARHUB-DASH-ACL6 -p tcp --dport 3000 -s "${gip6}/128" -j RETURN
    fi
    ip6tables -A STARHUB-BOT-NOSSH6 -s "${gip6}/128" -p tcp --dport 22 -j DROP
  done
  ip6tables -A STARHUB-DASH-ACL6 -j DROP

  while ip6tables -C INPUT -p tcp --dport 22 -j STARHUB-BOT-NOSSH6 2>/dev/null; do
    ip6tables -D INPUT -p tcp --dport 22 -j STARHUB-BOT-NOSSH6
  done
  ip6tables -I INPUT 1 -p tcp --dport 22 -j STARHUB-BOT-NOSSH6

  for p in 3001 3000 8000 9443 9000; do
    while ip6tables -C INPUT -p tcp --dport "$p" -j STARHUB-DASH-ACL6 2>/dev/null; do
      ip6tables -D INPUT -p tcp --dport "$p" -j STARHUB-DASH-ACL6
    done
    ip6tables -I INPUT 1 -p tcp --dport "$p" -j STARHUB-DASH-ACL6
  done
  for p in 3001 3000 8000 9443 9000; do
    while ip6tables -C FORWARD -p tcp --dport "$p" -j STARHUB-DASH-ACL6 2>/dev/null; do
      ip6tables -D FORWARD -p tcp --dport "$p" -j STARHUB-DASH-ACL6
    done
    ip6tables -I FORWARD 1 -p tcp --dport "$p" -j STARHUB-DASH-ACL6
    if ip6tables -L DOCKER-USER >/dev/null 2>&1; then
      while ip6tables -C DOCKER-USER -p tcp --dport "$p" -j STARHUB-DASH-ACL6 2>/dev/null; do
        ip6tables -D DOCKER-USER -p tcp --dport "$p" -j STARHUB-DASH-ACL6
      done
      ip6tables -I DOCKER-USER 1 -p tcp --dport "$p" -j STARHUB-DASH-ACL6
    fi
  done
fi
