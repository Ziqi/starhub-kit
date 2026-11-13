#!/usr/bin/env bash
# StarHub Gateway (.11 / gw) Dual-Stack Allowlist, DNS VIP, MSS Clamp & IPv6 Exit Guard
set -euo pipefail

ip addr add 192.0.2.12/24 dev eth0 2>/dev/null || true

iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 1053 2>/dev/null \
  || iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 1053
iptables -t nat -C PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports 1053 2>/dev/null \
  || iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports 1053

iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
  || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t nat -C POSTROUTING -o tailscale0 -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -o tailscale0 -j MASQUERADE

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

iptables -N STARHUB-GW-ACL 2>/dev/null || true
iptables -F STARHUB-GW-ACL
iptables -A STARHUB-GW-ACL -i lo -j RETURN
iptables -A STARHUB-GW-ACL -s 127.0.0.0/8 -j RETURN
iptables -A STARHUB-GW-ACL -s 192.0.2.0/24 -j RETURN
for ip in "${ALLOW_IPS[@]}"; do
  iptables -A STARHUB-GW-ACL -s "${ip}/32" -j RETURN
done
iptables -A STARHUB-GW-ACL -j DROP

for p in 7890 9090; do
  while iptables -C INPUT -p tcp --dport "$p" -j STARHUB-GW-ACL 2>/dev/null; do
    iptables -D INPUT -p tcp --dport "$p" -j STARHUB-GW-ACL
  done
  iptables -I INPUT 1 -p tcp --dport "$p" -j STARHUB-GW-ACL
done

if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -N STARHUB-GW-ACL6 2>/dev/null || true
  ip6tables -F STARHUB-GW-ACL6
  ip6tables -A STARHUB-GW-ACL6 -i lo -j RETURN
  ip6tables -A STARHUB-GW-ACL6 -s ::1/128 -j RETURN
  ip6tables -A STARHUB-GW-ACL6 -s fe80::/10 -j RETURN
  for ip6 in "${ALLOW_IP6S[@]}"; do
    ip6tables -A STARHUB-GW-ACL6 -s "${ip6}/128" -j RETURN
  done
  ip6tables -A STARHUB-GW-ACL6 -j DROP

  for p in 7890 9090; do
    while ip6tables -C INPUT -p tcp --dport "$p" -j STARHUB-GW-ACL6 2>/dev/null; do
      ip6tables -D INPUT -p tcp --dport "$p" -j STARHUB-GW-ACL6
    done
    ip6tables -I INPUT 1 -p tcp --dport "$p" -j STARHUB-GW-ACL6
  done

  ip6tables -N STARHUB-IPV6-EXIT-GUARD 2>/dev/null || true
  ip6tables -F STARHUB-IPV6-EXIT-GUARD
  ip6tables -A STARHUB-IPV6-EXIT-GUARD -i tailscale0 -d fd7a:115c:a1e0::/48 -j RETURN
  ip6tables -A STARHUB-IPV6-EXIT-GUARD -i tailscale0 -j REJECT --reject-with icmp6-adm-prohibited
  while ip6tables -C FORWARD -j STARHUB-IPV6-EXIT-GUARD 2>/dev/null; do
    ip6tables -D FORWARD -j STARHUB-IPV6-EXIT-GUARD
  done
  ip6tables -I FORWARD 1 -j STARHUB-IPV6-EXIT-GUARD
fi
