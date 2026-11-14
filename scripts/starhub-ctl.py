#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 StarHub Contributors
# SPDX-License-Identifier: MIT
"""
StarHub Declarative Topology Compiler & Toolkit CLI (starhub-ctl.py)
Zero third-party dependencies (Python 3.9+ stdlib only).

Subcommands:
  init [--force]
      Initialize STARHUB_GROUND_TRUTH.json from topology.example.json if absent.
  render [--check | --in-place | --out-dir <dir>]
      Deterministically compile dual-stack firewall scripts, Cloud Agent B2
      sandbox bootstrap, Mihomo shared guardrails, gateway config skeleton,
      camera cloud kill-switch, SSH config drop-in, and Lifeline systemd units
      from STARHUB_GROUND_TRUTH.json.
  doctor [extra args...]
      Run StarHub EGM 3.0 zero-drift & zero-PII verification harness.
  export-workstation
      Export [WORKSTATION] entries from docs/ops/STARHUB-LEDGER.md.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys

DEFAULT_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_json_compatible(path: pathlib.Path) -> dict:
    raw_lines = path.read_text(encoding="utf-8").splitlines()
    json_body = "\n".join(
        line for line in raw_lines if not line.lstrip().startswith("#")
    )
    return json.loads(json_body)


def normalize_lf(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"


def _collect_admin_allowlists(gt: dict) -> tuple[list[str], list[str]]:
    nodes = gt.get("nodes", {})
    order = gt.get(
        "admin_allowlist_nodes",
        [
            "laptop",
            "site-b-node",
            "workstation",
            "mobile-phone",
            "mobile-tablet",
            "gw",
            "home",
            "panel",
        ],
    )
    v4_list: list[str] = []
    v6_list: list[str] = []
    for key in order:
        nd = nodes.get(key, {})
        ip4 = nd.get("tailscale_ip")
        ip6 = nd.get("tailscale_ip6")
        if ip4:
            v4_list.append(ip4)
        if ip6:
            v6_list.append(ip6)
    return v4_list, v6_list


def render_dash_fw(gt: dict) -> str:
    allow_ips, allow_ip6s = _collect_admin_allowlists(gt)
    nodes = gt.get("nodes", {})
    b2 = nodes.get("agent_sandbox", {})
    b2_ips = b2.get("tailscale_ips", [])
    b2_ip6s = b2.get("tailscale_ip6s", [])
    dyn_pat = b2.get("dynamic_hostname_pattern", "^(ai-agent|sandbox-worker)")
    lan_cidr = gt.get("home_lan_cidr", "192.0.2.0/24")
    dash_port = gt.get("ssot_workspace", {}).get("dashboard_port", 3001)
    prot_ports = nodes.get("panel", {}).get(
        "protected_ports", [dash_port, 3000, 8000, 9443, 9000]
    )
    ports_str = " ".join(str(p) for p in prot_ports)

    allow_v4_block = "\n".join(f"  {ip}" for ip in allow_ips)
    allow_v6_block = "\n".join(f"  {ip6}" for ip6 in allow_ip6s)
    b2_v4_block = "\n".join(f"  {ip}" for ip in b2_ips)
    b2_v6_block = "\n".join(f"  {ip6}" for ip6 in b2_ip6s)

    return f"""#!/usr/bin/env bash
set -euo pipefail
for _ in $(seq 1 30); do
  iptables -C INPUT -j ts-input 2>/dev/null && \\
  iptables -C FORWARD -j ts-forward 2>/dev/null && \\
  ip6tables -C INPUT -j ts-input 2>/dev/null && break
  sleep 0.5
done

ALLOW_IPS=(
{allow_v4_block}
)
ALLOW_IP6S=(
{allow_v6_block}
)

# B2 Restricted Guest Pass for Cloud AI Sandbox: ONLY :{dash_port} Dashboard Web/API, NEVER :22 SSH or :8000/:9000/:9443 Portainer
AGENT_B2_IPS=(
{b2_v4_block}
)
AGENT_B2_IP6S=(
{b2_v6_block}
)

if command -v tailscale >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  while IFS=' ' read -r kind addr; do
    if [[ "${{kind:-}}" == "v4" && -n "${{addr:-}}" ]]; then
      AGENT_B2_IPS+=("$addr")
    elif [[ "${{kind:-}}" == "v6" && -n "${{addr:-}}" ]]; then
      AGENT_B2_IP6S+=("$addr")
    fi
  done < <(tailscale status --json 2>/dev/null | python3 -c '
import json, re, sys
try:
    d = json.load(sys.stdin)
    pat = re.compile(r"{dyn_pat}", re.I)
    for p in (d.get("Peer") or {{}}).values():
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
iptables -A STARHUB-DASH-ACL -s {lan_cidr} -j RETURN
iptables -A STARHUB-DASH-ACL -s 172.16.0.0/12 -j RETURN
for ip in "${{ALLOW_IPS[@]}}"; do
  iptables -A STARHUB-DASH-ACL -s "${{ip}}/32" -j RETURN
done

# Cloud AI Sandbox B2: allow :{dash_port} Dashboard (host INPUT :{dash_port} and Docker DNAT ctorigdstport {dash_port} -> container :3000)
iptables -N STARHUB-BOT-NOSSH 2>/dev/null || true
iptables -F STARHUB-BOT-NOSSH
for gip in $(printf '%s\\n' "${{AGENT_B2_IPS[@]}}" | sort -u); do
  [[ -z "$gip" ]] && continue
  iptables -A STARHUB-DASH-ACL -p tcp --dport {dash_port} -s "${{gip}}/32" -j RETURN
  if ! iptables -A STARHUB-DASH-ACL -p tcp -m conntrack --ctorigdstport {dash_port} -s "${{gip}}/32" -j RETURN 2>/dev/null; then
    iptables -A STARHUB-DASH-ACL -p tcp --dport 3000 -s "${{gip}}/32" -j RETURN
  fi
  iptables -A STARHUB-BOT-NOSSH -s "${{gip}}/32" -p tcp --dport 22 -j DROP
done
iptables -A STARHUB-DASH-ACL -j DROP

while iptables -C INPUT -p tcp --dport 22 -j STARHUB-BOT-NOSSH 2>/dev/null; do
  iptables -D INPUT -p tcp --dport 22 -j STARHUB-BOT-NOSSH
done
iptables -I INPUT 1 -p tcp --dport 22 -j STARHUB-BOT-NOSSH

for p in {ports_str}; do
  while iptables -C INPUT -p tcp --dport "$p" -j STARHUB-DASH-ACL 2>/dev/null; do
    iptables -D INPUT -p tcp --dport "$p" -j STARHUB-DASH-ACL
  done
  iptables -I INPUT 1 -p tcp --dport "$p" -j STARHUB-DASH-ACL
done

for p in {ports_str}; do
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
  for ip6 in "${{ALLOW_IP6S[@]}}"; do
    ip6tables -A STARHUB-DASH-ACL6 -s "${{ip6}}/128" -j RETURN
  done

  ip6tables -N STARHUB-BOT-NOSSH6 2>/dev/null || true
  ip6tables -F STARHUB-BOT-NOSSH6
  for gip6 in $(printf '%s\\n' "${{AGENT_B2_IP6S[@]}}" | sort -u); do
    [[ -z "$gip6" ]] && continue
    ip6tables -A STARHUB-DASH-ACL6 -p tcp --dport {dash_port} -s "${{gip6}}/128" -j RETURN
    if ! ip6tables -A STARHUB-DASH-ACL6 -p tcp -m conntrack --ctorigdstport {dash_port} -s "${{gip6}}/128" -j RETURN 2>/dev/null; then
      ip6tables -A STARHUB-DASH-ACL6 -p tcp --dport 3000 -s "${{gip6}}/128" -j RETURN
    fi
    ip6tables -A STARHUB-BOT-NOSSH6 -s "${{gip6}}/128" -p tcp --dport 22 -j DROP
  done
  ip6tables -A STARHUB-DASH-ACL6 -j DROP

  while ip6tables -C INPUT -p tcp --dport 22 -j STARHUB-BOT-NOSSH6 2>/dev/null; do
    ip6tables -D INPUT -p tcp --dport 22 -j STARHUB-BOT-NOSSH6
  done
  ip6tables -I INPUT 1 -p tcp --dport 22 -j STARHUB-BOT-NOSSH6

  for p in {ports_str}; do
    while ip6tables -C INPUT -p tcp --dport "$p" -j STARHUB-DASH-ACL6 2>/dev/null; do
      ip6tables -D INPUT -p tcp --dport "$p" -j STARHUB-DASH-ACL6
    done
    ip6tables -I INPUT 1 -p tcp --dport "$p" -j STARHUB-DASH-ACL6
  done
  for p in {ports_str}; do
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
"""


def render_home_fw(gt: dict) -> str:
    allow_ips, allow_ip6s = _collect_admin_allowlists(gt)
    nodes = gt.get("nodes", {})
    b2 = nodes.get("agent_sandbox", {})
    b2_ips = b2.get("tailscale_ips", [])
    b2_ip6s = b2.get("tailscale_ip6s", [])
    dyn_pat = b2.get("dynamic_hostname_pattern", "^(ai-agent|sandbox-worker)")
    lan_cidr = gt.get("home_lan_cidr", "192.0.2.0/24")
    web_port = nodes.get("home", {}).get("web_port", 8080)

    allow_v4_block = "\n".join(f"  {ip}" for ip in allow_ips)
    allow_v6_block = "\n".join(f"  {ip6}" for ip6 in allow_ip6s)
    b2_v4_block = "\n".join(f"  {ip}" for ip in b2_ips)
    b2_v6_block = "\n".join(f"  {ip6}" for ip6 in b2_ip6s)

    return f"""#!/usr/bin/env bash
set -euo pipefail
ALLOW_IPS=(
{allow_v4_block}
)
ALLOW_IP6S=(
{allow_v6_block}
)

# B2 Restricted Guest Pass for Cloud AI Sandbox: ONLY :{web_port} StarHub Home OS Web/API, NEVER :22 SSH
AGENT_B2_IPS=(
{b2_v4_block}
)
AGENT_B2_IP6S=(
{b2_v6_block}
)

if command -v tailscale >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  while IFS=' ' read -r kind addr; do
    if [[ "${{kind:-}}" == "v4" && -n "${{addr:-}}" ]]; then
      AGENT_B2_IPS+=("$addr")
    elif [[ "${{kind:-}}" == "v6" && -n "${{addr:-}}" ]]; then
      AGENT_B2_IP6S+=("$addr")
    fi
  done < <(tailscale status --json 2>/dev/null | python3 -c '
import json, re, sys
try:
    d = json.load(sys.stdin)
    pat = re.compile(r"{dyn_pat}", re.I)
    for p in (d.get("Peer") or {{}}).values():
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
iptables -A STARHUB-HOME-ACL -s {lan_cidr} -j RETURN
for ip in "${{ALLOW_IPS[@]}}"; do
  iptables -A STARHUB-HOME-ACL -s "${{ip}}/32" -j RETURN
done

iptables -N STARHUB-BOT-NOSSH 2>/dev/null || true
iptables -F STARHUB-BOT-NOSSH
for gip in $(printf '%s\\n' "${{AGENT_B2_IPS[@]}}" | sort -u); do
  [[ -z "$gip" ]] && continue
  iptables -A STARHUB-HOME-ACL -s "${{gip}}/32" -p tcp --dport {web_port} -j RETURN
  iptables -A STARHUB-BOT-NOSSH -s "${{gip}}/32" -p tcp --dport 22 -j DROP
done
iptables -A STARHUB-HOME-ACL -j DROP

while iptables -C INPUT -p tcp --dport 22 -j STARHUB-BOT-NOSSH 2>/dev/null; do
  iptables -D INPUT -p tcp --dport 22 -j STARHUB-BOT-NOSSH
done
iptables -I INPUT 1 -p tcp --dport 22 -j STARHUB-BOT-NOSSH

while iptables -C INPUT -p tcp --dport {web_port} -j STARHUB-HOME-ACL 2>/dev/null; do
  iptables -D INPUT -p tcp --dport {web_port} -j STARHUB-HOME-ACL
done
iptables -I INPUT 1 -p tcp --dport {web_port} -j STARHUB-HOME-ACL

if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -N STARHUB-HOME-ACL6 2>/dev/null || true
  ip6tables -F STARHUB-HOME-ACL6
  ip6tables -A STARHUB-HOME-ACL6 -i lo -j RETURN
  ip6tables -A STARHUB-HOME-ACL6 -s ::1/128 -j RETURN
  ip6tables -A STARHUB-HOME-ACL6 -s fe80::/10 -j RETURN
  for ip6 in "${{ALLOW_IP6S[@]}}"; do
    ip6tables -A STARHUB-HOME-ACL6 -s "${{ip6}}/128" -j RETURN
  done

  ip6tables -N STARHUB-BOT-NOSSH6 2>/dev/null || true
  ip6tables -F STARHUB-BOT-NOSSH6
  for gip6 in $(printf '%s\\n' "${{AGENT_B2_IP6S[@]}}" | sort -u); do
    [[ -z "$gip6" ]] && continue
    ip6tables -A STARHUB-HOME-ACL6 -s "${{gip6}}/128" -p tcp --dport {web_port} -j RETURN
    ip6tables -A STARHUB-BOT-NOSSH6 -s "${{gip6}}/128" -p tcp --dport 22 -j DROP
  done
  ip6tables -A STARHUB-HOME-ACL6 -j DROP

  while ip6tables -C INPUT -p tcp --dport 22 -j STARHUB-BOT-NOSSH6 2>/dev/null; do
    ip6tables -D INPUT -p tcp --dport 22 -j STARHUB-BOT-NOSSH6
  done
  ip6tables -I INPUT 1 -p tcp --dport 22 -j STARHUB-BOT-NOSSH6

  while ip6tables -C INPUT -p tcp --dport {web_port} -j STARHUB-HOME-ACL6 2>/dev/null; do
    ip6tables -D INPUT -p tcp --dport {web_port} -j STARHUB-HOME-ACL6
  done
  ip6tables -I INPUT 1 -p tcp --dport {web_port} -j STARHUB-HOME-ACL6
fi
"""


def render_agent_bootstrap(gt: dict) -> str:
    nodes = gt.get("nodes", {})
    panel = nodes.get("panel", {})
    home = nodes.get("home", {})
    laptop = nodes.get("laptop", {})
    b2 = nodes.get("agent_sandbox", {})

    panel_ts = panel.get("tailscale_ip", "100.64.0.15")
    home_ts = home.get("tailscale_ip", "100.64.0.20")
    laptop_ts = laptop.get("tailscale_ip", "100.64.0.31")

    panel_suffix = "." + panel.get("lan_ip", "192.0.2.15").split(".")[-1]
    home_suffix = "." + home.get("lan_ip", "192.0.2.20").split(".")[-1]

    dash_port = gt.get("ssot_workspace", {}).get("dashboard_port", 3001)
    home_port = home.get("web_port", 8080)
    proxy_addr = b2.get("proxy_listen", "127.0.0.1:1055")
    host_prefix = b2.get("hostname_prefix", "ai-agent")
    warmup = b2.get("warmup_targets", [panel_ts, home_ts, laptop_ts])
    warmup_str = " ".join(warmup)

    return f"""#!/usr/bin/env bash
# ==============================================================================
# StarHub Cloud AI Sandbox Tailscale Bootstrap (B2 Restricted Guest Mode)
# Purpose:
#   1. Per-instance state isolation (--statedir=/tmp/tailscale-<instance>) to
#      prevent multi-sandbox NodeKey/HomeDERP split-brain.
#   2. Userspace networking + local SOCKS5/HTTP proxy on {proxy_addr}.
#   3. DERP / WireGuard handshake pre-warm against {panel_suffix} ({panel_ts}),
#      {home_suffix} ({home_ts}), and primary controller ({laptop_ts}).
# ==============================================================================
set -euo pipefail

RAW_ID="${{AGENT_INSTANCE_ID:-$(hostname -s 2>/dev/null || true)}}"
if [[ -z "${{RAW_ID}}" || "${{RAW_ID}}" == "localhost" || "${{RAW_ID}}" == "box" ]]; then
  RAW_ID="$(cut -c1-8 /proc/sys/kernel/random/boot_id 2>/dev/null || echo "$$")"
fi
SAFE_ID="$(printf '%s' "${{RAW_ID}}" | tr -cd 'a-zA-Z0-9_-')"

STATE_DIR="/tmp/tailscale-${{SAFE_ID}}"
SOCK="${{STATE_DIR}}/tailscaled.sock"
PROXY_ADDR="{proxy_addr}"
HOSTNAME_TAG="{host_prefix}-${{SAFE_ID}}"

mkdir -p "${{STATE_DIR}}"
chmod 700 "${{STATE_DIR}}"

if ! tailscale --socket="${{SOCK}}" status >/dev/null 2>&1; then
  nohup tailscaled \\
    --tun=userspace-networking \\
    --statedir="${{STATE_DIR}}" \\
    --socket="${{SOCK}}" \\
    --socks5-server="${{PROXY_ADDR}}" \\
    --outbound-http-proxy-listen="${{PROXY_ADDR}}" \\
    >"${{STATE_DIR}}/tailscaled.log" 2>&1 &
  for _ in $(seq 1 20); do
    [[ -S "${{SOCK}}" ]] && break
    sleep 0.3
  done
fi

UP_ARGS=(--socket="${{SOCK}}" up --accept-routes=false --accept-dns=false --hostname="${{HOSTNAME_TAG}}")
if [[ -n "${{TS_AUTHKEY:-}}" ]]; then
  UP_ARGS+=(--authkey="${{TS_AUTHKEY}}")
fi
tailscale "${{UP_ARGS[@]}}"

# Pre-warm WireGuard / DERP sessions to StarHub B2 endpoints
for peer in {warmup_str}; do
  tailscale --socket="${{SOCK}}" ping -c 1 --timeout=4s "${{peer}}" >/dev/null 2>&1 || true
done

cat <<EOF
[StarHub B2 Ready]
  Instance   : ${{HOSTNAME_TAG}}
  Socket     : ${{SOCK}}
  Proxy      : socks5h://${{PROXY_ADDR}} (HTTP: http://${{PROXY_ADDR}})
  Dashboard  : curl --socks5-hostname ${{PROXY_ADDR}} -fsS http://{panel_ts}:{dash_port}/api/health
  Home OS    : curl --socks5-hostname ${{PROXY_ADDR}} -fsS http://{home_ts}:{home_port}/api/status
EOF
"""


def render_mihomo_guardrails(gt: dict) -> str:
    updated_at = gt.get("updated_at", "2026-11-13")
    ssot_path = gt.get("ssot_workspace", {}).get("path", "/opt/starhub-kit")
    nodes = gt.get("nodes", {})
    derp = nodes.get("derp", {}) if isinstance(nodes.get("derp"), dict) else {}
    derp_suffix = derp.get("root_domain_suffix", "")
    derp_ip = derp.get("public_ip", "")
    egress = gt.get("egress_vps", {})
    primary_egress = next(iter(egress.values()), {"name": "EgressPrimary"})["name"]

    anti_loop = [
        "DST-PORT,3478,DIRECT",
        "DOMAIN-SUFFIX,tailscale.com,DIRECT",
        "DOMAIN-SUFFIX,ts.net,DIRECT",
    ]
    if derp_suffix:
        anti_loop.append(f"DOMAIN-SUFFIX,{derp_suffix},DIRECT")
    if derp_ip:
        anti_loop.append(f"IP-CIDR,{derp_ip}/32,DIRECT,no-resolve")
    for vps in egress.values():
        anti_loop.append(f"IP-CIDR,{vps['ip']}/32,DIRECT,no-resolve")
    anti_loop.append("IP-CIDR,100.64.0.0/10,DIRECT,no-resolve")

    apple_rules = [
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,tv.apple.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,itunes.apple.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,media.apple.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,apps.apple.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,apis.apple.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,music.apple.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,videos.apple.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,mzstatic.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,aaplimg.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,itunes.apple.com.edgesuite.net)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,itunes-apple.com.akadns.net)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,apple.map.fastly.net)),REJECT",
    ]
    gmail_rules = [
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,mail.google.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,inbox.google.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,gmail.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,oauth2.googleapis.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,oauthaccountmanager.googleapis.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,gogaccountservice-pa.googleapis.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,notifications-pa.googleapis.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,peoplestack-pa.googleapis.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,taskassist-pa.googleapis.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,addons-pa.googleapis.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,appsgenaiserver-pa.googleapis.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,robinfrontend-pa.googleapis.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,mail-attachment.googleusercontent.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,ci3.googleusercontent.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,ci4.googleusercontent.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,ci5.googleusercontent.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,ci6.googleusercontent.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,lh3.googleusercontent.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,lh4.googleusercontent.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,lh5.googleusercontent.com)),REJECT",
        "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,lh6.googleusercontent.com)),REJECT",
    ]
    yt_domains = [
        "youtube.com",
        "googlevideo.com",
        "youtubei.googleapis.com",
        "gstatic.com",
    ]

    def fmt_str_list(items: list[str], indent: int = 4) -> str:
        pad = " " * indent
        return ",\n".join(f'{pad}"{it}"' for it in items)

    return f"""# ==============================================================================
# StarHub 3.0 — Mihomo 跨节点共享防环与协议治理规则母版 (Mihomo Ruleset Invariants)
# 路径: {ssot_path}/scripts/profiles/mihomo-shared-guardrails.yaml
# 说明: 专职定义 Mihomo DNS、防环与精准应用层 QUIC 规则不变量（节点/IoT/退役黑名单均
#       唯一归口于根目录 STARHUB_GROUND_TRUTH.json，杜绝双处重复维护）。
#       采用 JSON 兼容的 YAML 1.2 子集编写，无需额外安装 PyYAML 即可由标准库解析。
# 顺序护栏 (Section 9a): gmail_quic_reject_rules 必须置于任何广义 Google 代理规则
#       (如 DOMAIN-SUFFIX,googleapis.com / googleusercontent.com / GEOSITE,google) 上方。
# 严禁事项: 本文件严禁写入任何 UUID、私钥、Bearer Secret 等敏感凭据。
# ==============================================================================
{{
  "schema_version": "3.0.0",
  "updated_at": "{updated_at}",
  "gw_dns_invariants": {{
    "require_respect_rules": true,
    "forbid_blind_fallback": true,
    "required_nameserver_policy_pairs": [
      ["+.ts.net", "100.100.100.100#tailscale0"],
      ["geosite:cn,private", "https://dns.alidns.com/dns-query"],
      ["geosite:geolocation-!cn", "https://1.1.1.1/dns-query#{primary_egress}"]
    ]
  }},
  "mandatory_anti_loop_rules": [
{fmt_str_list(anti_loop)}
  ],
  "apple_quic_reject_rules": [
{fmt_str_list(apple_rules)}
  ],
  "gmail_quic_reject_rules": [
{fmt_str_list(gmail_rules)}
  ],
  "protected_youtube_cronet_domains": [
{fmt_str_list(yt_domains)}
  ]
}}
"""


def render_mihomo_gateway_skeleton(gt: dict) -> str:
    guard = load_json_compatible_from_str(render_mihomo_guardrails(gt))
    egress = gt.get("egress_vps", {})
    primary_egress = next(
        iter(egress.values()),
        {
            "name": "EgressPrimary",
            "ip": "198.51.100.11",
            "port": 443,
            "sni": "cdn.example.com",
        },
    )
    proxy_lines: list[str] = []
    proxy_names: list[str] = []
    for vps in egress.values():
        proxy_names.append(f'"{vps["name"]}"')
        proxy_lines.append(
            f"""  - name: "{vps['name']}"
    type: vless
    server: {vps['ip']}
    port: {vps.get('port', 443)}
    uuid: "<REPLACE_WITH_YOUR_VLESS_UUID>"
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: {vps.get('sni', 'cdn.example.com')}
    client-fingerprint: chrome
    reality-opts:
      public-key: "<REPLACE_WITH_REALITY_PUBLIC_KEY>"
      short-id: "<REPLACE_WITH_SHORT_ID>" """.rstrip()
        )

    rule_sections: list[str] = [
        "  # Section 1: Tailscale STUN/DERP & Egress Anti-Loop Direct Exemptions"
    ]
    rule_sections.extend(f"  - {r}" for r in guard["mandatory_anti_loop_rules"])
    rule_sections.append(
        "  # Section 9a: Surgical Apple Media & Mobile Gmail QUIC (UDP/443 REJECT)"
    )
    rule_sections.append(
        "  # IMPORTANT: Must precede any broad googleapis.com / googleusercontent.com / GEOSITE,google proxy rules!"
    )
    rule_sections.extend(f"  - {r}" for r in guard["apple_quic_reject_rules"])
    rule_sections.extend(f"  - {r}" for r in guard["gmail_quic_reject_rules"])
    rule_sections.append("  # Section 10: Domestic Direct & Default Proxy Routing")
    rule_sections.extend(
        [
            "  - GEOSITE,cn,DIRECT",
            "  - GEOIP,CN,DIRECT,no-resolve",
            "  - MATCH,PROXY",
        ]
    )
    rules_yaml = "\n".join(rule_sections)
    proxies_yaml = "\n".join(proxy_lines)
    group_members = ", ".join(proxy_names)

    return f"""# StarHub 3.0 Deterministic Transparent Gateway Config Skeleton (chmod 0600 on live host)
mixed-port: 7890
redir-port: 7892
allow-lan: true
mode: rule
log-level: info
ipv6: true
external-controller: 0.0.0.0:9090
secret: ""

sniffer:
  enable: true
  override-destination: false

tun:
  enable: true
  stack: gvisor
  device: Meta
  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53

dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/16
  respect-rules: true
  default-nameserver:
    - 223.5.5.5
  nameserver:
    - https://dns.alidns.com/dns-query
  nameserver-policy:
    "+.ts.net":
      - "100.100.100.100#tailscale0"
    "geosite:cn,private":
      - "https://dns.alidns.com/dns-query"
    "geosite:geolocation-!cn":
      - "https://1.1.1.1/dns-query#{primary_egress['name']}"

proxies:
{proxies_yaml}

proxy-groups:
  - name: "PROXY"
    type: fallback
    url: "https://www.gstatic.com/generate_204"
    interval: 120
    proxies: [{group_members}]

rules:
{rules_yaml}
"""


def render_gw_ts_mss_clamp(gt: dict) -> str:
    allow_ips, allow_ip6s = _collect_admin_allowlists(gt)
    gw = gt.get("nodes", {}).get("gw", {})
    lan_cidr = gt.get("home_lan_cidr", "192.0.2.0/24")
    vip = gw.get("lan_vip", "")
    vip_line = (
        f"ip addr add {vip}/24 dev eth0 2>/dev/null || true"
        if vip
        else "# Optional secondary DNS VIP on eth0 disabled"
    )
    v4_lines = "\n".join(f"  {ip}" for ip in allow_ips)
    v6_lines = "\n".join(f"  {ip6}" for ip6 in allow_ip6s)
    return f"""#!/usr/bin/env bash
# StarHub Gateway (.11 / gw) Dual-Stack Allowlist, DNS VIP, MSS Clamp & IPv6 Exit Guard
set -euo pipefail

{vip_line}

iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 1053 2>/dev/null \\
  || iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 1053
iptables -t nat -C PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports 1053 2>/dev/null \\
  || iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports 1053

iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \\
  || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t nat -C POSTROUTING -o tailscale0 -j MASQUERADE 2>/dev/null \\
  || iptables -t nat -A POSTROUTING -o tailscale0 -j MASQUERADE

ALLOW_IPS=(
{v4_lines}
)
ALLOW_IP6S=(
{v6_lines}
)

iptables -N STARHUB-GW-ACL 2>/dev/null || true
iptables -F STARHUB-GW-ACL
iptables -A STARHUB-GW-ACL -i lo -j RETURN
iptables -A STARHUB-GW-ACL -s 127.0.0.0/8 -j RETURN
iptables -A STARHUB-GW-ACL -s {lan_cidr} -j RETURN
for ip in "${{ALLOW_IPS[@]}}"; do
  iptables -A STARHUB-GW-ACL -s "${{ip}}/32" -j RETURN
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
  for ip6 in "${{ALLOW_IP6S[@]}}"; do
    ip6tables -A STARHUB-GW-ACL6 -s "${{ip6}}/128" -j RETURN
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
"""


def render_cam_gate(gt: dict) -> str:
    cam = gt.get("smart_home_devices", {}).get("ip_camera", {})
    cam_ip = cam.get("lan_ip", "192.0.2.61")
    return f"""#!/usr/bin/env bash
# StarHub Cam-Gate: Physical gateway-level cloud uplink kill-switch for IoT camera ({cam_ip})
set -uo pipefail
FLAG=/var/lib/starhub-probe/cam-gate.off
mkdir -p /var/lib/starhub-probe

apply_drop() {{
  iptables -t mangle -C FORWARD -s {cam_ip} -o Meta -j DROP 2>/dev/null \\
    || iptables -t mangle -I FORWARD 1 -s {cam_ip} -o Meta -j DROP
}}

clear_drop() {{
  while iptables -t mangle -D FORWARD -s {cam_ip} -o Meta -j DROP 2>/dev/null; do
    :
  done
}}

case "${{1:-status}}" in
  off)
    touch "$FLAG"
    apply_drop
    echo off
    ;;
  on)
    clear_drop
    rm -f "$FLAG"
    echo on
    ;;
  status)
    if [[ -f "$FLAG" ]]; then
      apply_drop
      echo off
    else
      echo on
    fi
    ;;
  *)
    echo "usage: cam-gate.sh on|off|status" >&2
    exit 2
    ;;
esac
"""


def render_ssh_config(gt: dict) -> str:
    nodes = gt.get("nodes", {})
    derp = nodes.get("derp", {}) if isinstance(nodes.get("derp"), dict) else {}
    derp_ip = derp.get("public_ip", "")
    lines = [
        "# ==============================================================================",
        "# Auto-generated by starhub-ctl.py from STARHUB_GROUND_TRUTH.json",
        "# Drop into ~/.ssh/config.d/starhub.conf (Include ~/.ssh/config.d/*.conf)",
        "# ==============================================================================",
        "",
    ]
    if derp_ip:
        lines.extend(
            [
                "Host derp",
                f"  HostName {derp_ip}",
                "  User root",
                "  ServerAliveInterval 30",
                "  ServerAliveCountMax 3",
                "",
            ]
        )
    one_way_keys = {"gpu-worker", "workstation"}
    for key, nd in nodes.items():
        if key in ("modem", "mobile-tablet", "mobile-phone", "derp", "agent_sandbox"):
            continue
        aliases = nd.get("ssh_alias", [key])
        primary_alias = aliases[0]
        target_host = (
            nd.get("tailscale_ip")
            or nd.get("tailscale_4via6")
            or nd.get("public_ip")
            or nd.get("lan_ip")
        )
        if not target_host:
            continue
        is_one_way = bool(nd.get("one_way_controlled")) or (key in one_way_keys)
        lines.append(f"Host {primary_alias}")
        lines.append(f"  HostName {target_host}")
        lines.append(f"  User {nd.get('ssh_user', 'root')}")
        if is_one_way:
            lines.append("  ForwardAgent no")
            lines.append("  IdentitiesOnly yes")
        lines.append("  ServerAliveInterval 30")
        lines.append("")
        rescue_port = nd.get("rescue_port")
        if rescue_port and derp_ip:
            lines.append(f"Host {primary_alias}-rescue")
            lines.append("  HostName 127.0.0.1")
            lines.append(f"  Port {rescue_port}")
            lines.append("  ProxyJump derp")
            lines.append(f"  User {nd.get('ssh_user', 'root')}")
            if is_one_way:
                lines.append("  ForwardAgent no")
                lines.append("  IdentitiesOnly yes")
            lines.append("")
    return "\n".join(lines)


def render_lifeline_units(gt: dict) -> dict[str, str]:
    nodes = gt.get("nodes", {})
    derp_ip = nodes.get("derp", {}).get("public_ip", "203.0.113.10")
    units: dict[str, str] = {}
    for key, nd in nodes.items():
        rport = nd.get("rescue_port")
        if not rport:
            continue
        units[f"starhub-lifeline-{key}.service"] = f"""[Unit]
Description=StarHub Out-of-Band Reverse SSH Lifeline ({key} -> {derp_ip}:{rport})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=10
ExecStart=/usr/bin/ssh -N \\
  -o BatchMode=yes \\
  -o ExitOnForwardFailure=yes \\
  -o ServerAliveInterval=15 \\
  -o ServerAliveCountMax=2 \\
  -o StrictHostKeyChecking=accept-new \\
  -i /usr/local/starhub/lifeline/id_ed25519 \\
  -R 127.0.0.1:{rport}:127.0.0.1:22 \\
  lifeline@{derp_ip}

[Install]
WantedBy=multi-user.target
"""
    return units


def load_json_compatible_from_str(text: str) -> dict:
    body = "\n".join(
        ln for ln in text.splitlines() if not ln.lstrip().startswith("#")
    )
    return json.loads(body)


def render_standalone_mihomo_guardrails(gt: dict) -> str:
    guard = load_json_compatible_from_str(render_mihomo_guardrails(gt))
    egress = gt.get("egress_vps", {})
    primary_name = next(iter(egress.values()), {"name": "PROXY"})["name"]
    apple_lines = "\n".join(f"  - {r}" for r in guard["apple_quic_reject_rules"])
    gmail_lines = "\n".join(f"  - {r}" for r in guard["gmail_quic_reject_rules"])
    return f"""# ==============================================================================
# StarHub Kit (Tier 0) — Standalone Drop-In Mihomo / Clash Meta × Tailscale Pack
# Zero Python / Zero Compiler Required: Copy-paste `dns:` and `rules:` sections
# directly into OpenWrt (OpenClash / Nikki), Clash Verge Rev, Mihomo Party, or Stash.
#
# Solves 4 real-world bugs immediately:
#   1. Prevents Fake-IP (198.18.0.0/16) from hijacking Tailscale (*.ts.net / STUN :3478)
#   2. Eliminates blind `fallback:` DNS racing (`context canceled` & CDN GeoIP pollution)
#   3. Instant TCP fallback (`UDP/443 REJECT`) for Apple Media & Mobile Gmail attachments
#   4. Preserves native HTTP/3 QUIC (`UDP/443`) for YouTube 4K Cronet (`googlevideo.com`)
# ==============================================================================

dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.0/16
  respect-rules: true
  default-nameserver:
    - 223.5.5.5
  nameserver:
    - https://dns.alidns.com/dns-query
  # NOTE: Do NOT add a `fallback:` block — deterministic `nameserver-policy` avoids race drops.
  nameserver-policy:
    "+.ts.net":
      - "100.100.100.100#tailscale0"
    "geosite:cn,private":
      - "https://dns.alidns.com/dns-query"
    "geosite:geolocation-!cn":
      - "https://1.1.1.1/dns-query#{primary_name}"

rules:
  # --- [1] Tailscale STUN, Control Plane & CGNAT Anti-Loop Direct Exemptions ---
  - DST-PORT,3478,DIRECT
  - DOMAIN-SUFFIX,tailscale.com,DIRECT
  - DOMAIN-SUFFIX,ts.net,DIRECT
  - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve

  # --- [2] Section 9a: Surgical Apple & Mobile Gmail QUIC (UDP/443 -> REJECT) ---
  # CRITICAL ORDERING: Keep this block STRICTLY ABOVE any broad `googleapis.com`,
  # `googleusercontent.com`, or `GEOSITE,google` proxy rules!
  # Do NOT add `youtube.com` or `googlevideo.com` here so YouTube Cronet keeps HTTP/3.
{apple_lines}
{gmail_lines}

  # --- [3] Place your standard GeoSite / GeoIP / Proxy rules below this line ---
  # - GEOSITE,cn,DIRECT
  # - GEOIP,CN,DIRECT,no-resolve
  # - MATCH,{primary_name}
"""


def canonical_repo_targets(gt: dict) -> dict[str, tuple[str, int]]:
    nodes = gt.get("nodes", {}) if isinstance(gt.get("nodes"), dict) else {}
    is_minimal = gt.get("deployment_tier") == "minimal"
    targets: dict[str, tuple[str, int]] = {
        "scripts/profiles/mihomo-shared-guardrails.yaml": (
            render_mihomo_guardrails(gt),
            0o644,
        ),
        "scripts/profiles/standalone-mihomo-tailscale-guardrails.yaml": (
            render_standalone_mihomo_guardrails(gt),
            0o644,
        ),
    }
    if not is_minimal or "panel" in nodes:
        targets["scripts/starhub-dash-fw.sh"] = (render_dash_fw(gt), 0o755)
    if not is_minimal or "home" in nodes:
        targets["scripts/starhub-home-fw.sh"] = (render_home_fw(gt), 0o755)
    if not is_minimal or "agent_sandbox" in nodes:
        targets["scripts/agent-tailscale-bootstrap.sh"] = (render_agent_bootstrap(gt), 0o755)
    if gt.get("repo_profile") == "open_source_kit":
        targets["scripts/starhub-ts-mss-clamp.sh"] = (render_gw_ts_mss_clamp(gt), 0o755)
        targets["scripts/mihomo-config-backup.yaml"] = (
            render_mihomo_gateway_skeleton(gt),
            0o644,
        )
        if not is_minimal or "ip_camera" in (gt.get("smart_home_devices") or {}):
            targets["scripts/cam-gate.sh"] = (render_cam_gate(gt), 0o755)
    return targets


def _resolve_profile_template(repo_root: pathlib.Path, profile: str) -> pathlib.Path:
    if profile == "minimal":
        return repo_root / "profiles" / "topology.minimal.json"
    return repo_root / "topology.example.json"


def cmd_init(repo_root: pathlib.Path, force: bool, profile: str = "full") -> int:
    example_path = _resolve_profile_template(repo_root, profile)
    gt_path = repo_root / "STARHUB_GROUND_TRUTH.json"
    if not example_path.is_file():
        print(f"ERROR: example template not found: {example_path}", file=sys.stderr)
        return 1
    if gt_path.exists() and not force:
        print(f"[starhub-ctl] {gt_path} already exists (pass --force to overwrite).")
        return 0
    shutil.copyfile(example_path, gt_path)
    print(f"[starhub-ctl] Initialized {gt_path} from {example_path.relative_to(repo_root)} (profile={profile}).")
    return 0


def cmd_render(
    repo_root: pathlib.Path,
    check_only: bool,
    in_place: bool,
    out_dir: pathlib.Path | None,
    profile: str = "full",
) -> int:
    if profile == "minimal" and not check_only and not in_place:
        gt_path = _resolve_profile_template(repo_root, "minimal")
    else:
        gt_path = repo_root / "STARHUB_GROUND_TRUTH.json"
    if not gt_path.is_file():
        print(f"ERROR: {gt_path} not found. Run 'starhub init' first.", file=sys.stderr)
        return 1
    gt = load_json_compatible(gt_path)
    targets = canonical_repo_targets(gt)

    if check_only:
        drifted: list[str] = []
        for rel, (expected_text, _) in targets.items():
            fp = repo_root / rel
            if not fp.is_file():
                drifted.append(f"{rel} (missing)")
                continue
            actual_norm = normalize_lf(fp.read_text(encoding="utf-8"))
            expected_norm = normalize_lf(expected_text)
            if actual_norm != expected_norm:
                drifted.append(f"{rel} (content drift vs STARHUB_GROUND_TRUTH.json)")
        if drifted:
            for item in drifted:
                print(f"[FAIL] [COMPILER-PARITY] {item}", file=sys.stderr)
            return 1
        print(
            f"[PASS] [COMPILER-PARITY] {len(targets)}/{len(targets)} compiled artifacts match STARHUB_GROUND_TRUTH.json (0 drift)."
        )
        return 0

    if in_place:
        for rel, (content, mode) in targets.items():
            fp = repo_root / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(normalize_lf(content), encoding="utf-8")
            os.chmod(fp, mode)
        print(f"[starhub-ctl] Rendered {len(targets)} canonical files in-place under {repo_root}.")
        return 0

    default_dir_name = "dist-minimal" if (profile == "minimal" or gt.get("deployment_tier") == "minimal") else "dist"
    dest = (out_dir or (repo_root / default_dir_name)).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    nodes = gt.get("nodes", {}) if isinstance(gt.get("nodes"), dict) else {}
    is_minimal = gt.get("deployment_tier") == "minimal"
    bundle: dict[str, tuple[str, int]] = {
        "starhub-ts-mss-clamp.sh": (render_gw_ts_mss_clamp(gt), 0o755),
        "profiles/mihomo-shared-guardrails.yaml": (render_mihomo_guardrails(gt), 0o644),
        "profiles/standalone-mihomo-tailscale-guardrails.yaml": (
            render_standalone_mihomo_guardrails(gt),
            0o644,
        ),
        "mihomo-gateway.yaml": (render_mihomo_gateway_skeleton(gt), 0o600),
        "ssh_config.starhub": (render_ssh_config(gt), 0o644),
    }
    if not is_minimal or "panel" in nodes:
        bundle["starhub-dash-fw.sh"] = (render_dash_fw(gt), 0o755)
    if not is_minimal or "home" in nodes:
        bundle["starhub-home-fw.sh"] = (render_home_fw(gt), 0o755)
    if not is_minimal or "agent_sandbox" in nodes:
        bundle["agent-tailscale-bootstrap.sh"] = (render_agent_bootstrap(gt), 0o755)
    if not is_minimal or "ip_camera" in (gt.get("smart_home_devices") or {}):
        bundle["cam-gate.sh"] = (render_cam_gate(gt), 0o755)
    if "derp" in nodes:
        for unit_name, unit_body in render_lifeline_units(gt).items():
            bundle[f"systemd/{unit_name}"] = (unit_body, 0o644)

    for rel, (content, mode) in bundle.items():
        fp = dest / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(normalize_lf(content), encoding="utf-8")
        os.chmod(fp, mode)
    print(f"[starhub-ctl] Rendered {len(bundle)} deployment artifacts into {dest} (profile={profile})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="StarHub 3.0 Declarative Compiler & Open-Source Toolkit CLI"
    )
    parser.add_argument(
        "--repo-root",
        type=pathlib.Path,
        default=DEFAULT_REPO_ROOT,
        help="Repository root directory",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_init = sub.add_parser("init", help="Create STARHUB_GROUND_TRUTH.json from full or minimal template")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing STARHUB_GROUND_TRUTH.json")
    p_init.add_argument("--profile", choices=("full", "minimal"), default="full", help="Topology template tier")

    p_render = sub.add_parser("render", help="Compile network/firewall/Mihomo/Lifeline artifacts from SSOT")
    p_render.add_argument("--profile", choices=("full", "minimal"), default="full", help="Render full SSOT or minimal single-gateway tier")
    g_mode = p_render.add_mutually_exclusive_group()
    g_mode.add_argument("--check", action="store_true", help="Verify canonical repo scripts match SSOT with zero drift")
    g_mode.add_argument("--in-place", action="store_true", help="Update canonical scripts under scripts/ in-place")
    g_mode.add_argument("--out-dir", type=pathlib.Path, help="Output directory for rendered bundle (default: ./dist or ./dist-minimal)")

    sub.add_parser("doctor", help="Run StarHub EGM 3.0 zero-drift & zero-PII verification harness")
    sub.add_parser("export-workstation", help="Export [WORKSTATION] ledger entries")

    args, extra_args = parser.parse_known_args()
    repo_root = args.repo_root.resolve()

    if args.subcommand in ("init", "render", "export-workstation") and extra_args:
        parser.error(f"unrecognized arguments: {' '.join(extra_args)}")

    if args.subcommand == "init":
        return cmd_init(repo_root, args.force, args.profile)
    if args.subcommand == "render":
        return cmd_render(repo_root, args.check, args.in_place, args.out_dir, args.profile)
    if args.subcommand == "export-workstation":
        doctor_script = repo_root / "scripts" / "starhub-doctor.py"
        return subprocess.call(
            [sys.executable, str(doctor_script), "--repo-root", str(repo_root), "--export-workstation"]
        )
    if args.subcommand == "doctor":
        doctor_script = repo_root / "scripts" / "starhub-doctor.py"
        fwd = [a for a in extra_args if a != "--"]
        return subprocess.call(
            [sys.executable, str(doctor_script), "--repo-root", str(repo_root)] + fwd
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
