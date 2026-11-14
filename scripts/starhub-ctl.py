#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 StarHub Contributors
# SPDX-License-Identifier: MIT
"""
StarHub Declarative Topology Compiler & Toolkit CLI (starhub-ctl.py)
Zero third-party dependencies (Python 3.9+ stdlib only).

Subcommands:
  init [--force] [--profile full|minimal|ai-sandbox]
      Initialize STARHUB_GROUND_TRUTH.json from full, minimal, or ai-sandbox template.
  render [--profile full|minimal|ai-sandbox] [--only all|firewall|mihomo|ai-sandbox|lifeline]
         [--target default|nftables|macos-pf|tailscale-acl|singbox|all]
         [--check | --in-place | --out-dir <dir> | --dry-run]
      Deterministically compile dual-stack firewall scripts, Linux nftables, macOS pf,
      Tailscale ACL JSON, Sing-box / Mihomo QUIC & split-DNS guardrails, Cloud Agent B2
      sandbox bootstrap, SSH config drop-in, and Lifeline systemd units.
  audit [--profile full|minimal|ai-sandbox]
      Audit topology JSON for RFC 1918 Wi-Fi collision risks and exposed AI sandbox ports.
  mcp
      Run zero-dependency Model Context Protocol (MCP) JSON-RPC 2.0 server over stdio.
  archive [--output <tar.gz>] [--prefix <dir>] [--verify] [--verify-file <tar.gz>]
      Build or verify a bit-for-bit reproducible source tarball (mtime=0, uid/gid=0).
  doctor [extra args...]
      Run StarHub EGM 3.0 zero-drift & zero-PII verification harness.
  export-workstation
      Export [WORKSTATION] entries from docs/ops/STARHUB-LEDGER.md.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import ipaddress
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile

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


APPLE_QUIC_SUFFIXES = [
    "tv.apple.com",
    "itunes.apple.com",
    "media.apple.com",
    "apps.apple.com",
    "apis.apple.com",
    "music.apple.com",
    "videos.apple.com",
    "mzstatic.com",
    "aaplimg.com",
    "itunes.apple.com.edgesuite.net",
    "itunes-apple.com.akadns.net",
    "apple.map.fastly.net",
]
GMAIL_QUIC_SUFFIXES = ["mail.google.com", "inbox.google.com", "gmail.com"]
GMAIL_QUIC_DOMAINS = [
    "oauth2.googleapis.com",
    "oauthaccountmanager.googleapis.com",
    "gogaccountservice-pa.googleapis.com",
    "notifications-pa.googleapis.com",
    "peoplestack-pa.googleapis.com",
    "taskassist-pa.googleapis.com",
    "addons-pa.googleapis.com",
    "appsgenaiserver-pa.googleapis.com",
    "robinfrontend-pa.googleapis.com",
    "mail-attachment.googleusercontent.com",
    "ci3.googleusercontent.com",
    "ci4.googleusercontent.com",
    "ci5.googleusercontent.com",
    "ci6.googleusercontent.com",
    "lh3.googleusercontent.com",
    "lh4.googleusercontent.com",
    "lh5.googleusercontent.com",
    "lh6.googleusercontent.com",
]


def _extract_sandbox_ports_and_ips(gt: dict) -> tuple[list[str], list[str], list[int], list[int]]:
    nodes = gt.get("nodes", {}) if isinstance(gt.get("nodes"), dict) else {}
    b2 = nodes.get("agent_sandbox", {}) if isinstance(nodes.get("agent_sandbox"), dict) else {}
    v4_ips = list(b2.get("tailscale_ips") or ["100.64.0.201"])
    v6_ips = list(b2.get("tailscale_ip6s") or ["2001:db8:a1e0::201"])
    allowed_ports: list[int] = []
    for item in b2.get("allowed_targets") or ["100.64.0.15:3001"]:
        if ":" in str(item):
            port_val = int(str(item).rsplit(":", 1)[1])
            if port_val != 22 and port_val not in allowed_ports:
                allowed_ports.append(port_val)
    if not allowed_ports:
        allowed_ports = [3001]
    blocked_ports = sorted({22, 2375, 3306, 5432, 6379, 9000, *(int(p) for p in (b2.get("blocked_ports") or []))})
    return v4_ips, v6_ips, allowed_ports, blocked_ports


def render_nftables_sandbox_guard(gt: dict) -> str:
    admin_v4, admin_v6 = _collect_admin_allowlists(gt)
    sb_v4, sb_v6, allowed_ports, blocked_ports = _extract_sandbox_ports_and_ips(gt)
    v4_set = ", ".join(sb_v4)
    v6_set = ", ".join(sb_v6)
    adm_v4 = ", ".join(admin_v4 or ["100.64.0.31"])
    adm_v6 = ", ".join(admin_v6 or ["2001:db8:a1e0::31"])
    allow_p = ", ".join(str(p) for p in allowed_ports)
    block_p = ", ".join(str(p) for p in blocked_ports)
    return f"""#!/usr/sbin/nft -f
# StarHub AI Agent Sandbox Firewall (Linux nftables dual-stack inet table)
# Hard-blocks autonomous coding agents (Claude Code / Codex / OpenHands / Docker MCP)
# from TCP :22 SSH, Docker sockets, databases, and RFC 1918 LAN lateral movement.

table inet starhub_ai_guard
delete table inet starhub_ai_guard

table inet starhub_ai_guard {{
  set admin_v4 {{ type ipv4_addr; elements = {{ {adm_v4} }} }}
  set admin_v6 {{ type ipv6_addr; elements = {{ {adm_v6} }} }}
  set ai_sandbox_v4 {{ type ipv4_addr; elements = {{ {v4_set} }} }}
  set ai_sandbox_v6 {{ type ipv6_addr; elements = {{ {v6_set} }} }}

  chain input {{
    type filter hook input priority -10; policy accept;
    iifname "lo" accept
    ip saddr @admin_v4 accept
    ip6 saddr @admin_v6 accept
    ip saddr @ai_sandbox_v4 tcp dport {{ {block_p} }} counter drop
    ip6 saddr @ai_sandbox_v6 tcp dport {{ {block_p} }} counter drop
    ip saddr @ai_sandbox_v4 tcp dport {{ {allow_p} }} accept
    ip6 saddr @ai_sandbox_v6 tcp dport {{ {allow_p} }} accept
    ip saddr @ai_sandbox_v4 counter drop
    ip6 saddr @ai_sandbox_v6 counter drop
  }}

  chain forward {{
    type filter hook forward priority -10; policy accept;
    ip saddr @ai_sandbox_v4 ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }} counter drop
    ip saddr @ai_sandbox_v4 tcp dport {{ {block_p} }} counter drop
    ip6 saddr @ai_sandbox_v6 tcp dport {{ {block_p} }} counter drop
  }}
}}
"""


def render_macos_pf_sandbox_anchor(gt: dict) -> str:
    admin_v4, admin_v6 = _collect_admin_allowlists(gt)
    sb_v4, sb_v6, allowed_ports, blocked_ports = _extract_sandbox_ports_and_ips(gt)
    admins = " ".join([*admin_v4, *admin_v6] or ["100.64.0.31"])
    sandboxes = " ".join([*sb_v4, *sb_v6])
    allow_p = ", ".join(str(p) for p in allowed_ports)
    block_p = ", ".join(str(p) for p in blocked_ports)
    return f"""# StarHub AI Agent Sandbox Anchor for macOS Packet Filter (pf)
# Install: sudo cp com.starhub.ai-sandbox.pf.conf /etc/pf.anchors/com.starhub.ai_sandbox
# Activate in /etc/pf.conf: anchor "com.starhub.ai_sandbox" + load anchor from file, then `sudo pfctl -f /etc/pf.conf -e`

table <starhub_admin_hosts> persist {{ {admins} }}
table <starhub_ai_sandboxes> persist {{ {sandboxes} }}
table <starhub_rfc1918_lan> const {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }}

pass in quick from <starhub_admin_hosts> to any keep state
block return in quick proto tcp from <starhub_ai_sandboxes> to any port {{ {block_p} }}
pass in quick proto tcp from <starhub_ai_sandboxes> to any port {{ {allow_p} }} keep state
block return in quick from <starhub_ai_sandboxes> to any
block return out quick from <starhub_ai_sandboxes> to <starhub_rfc1918_lan>
"""


def render_tailscale_acl_policy(gt: dict) -> str:
    admin_v4, _ = _collect_admin_allowlists(gt)
    sb_v4, _, allowed_ports, _ = _extract_sandbox_ports_and_ips(gt)
    nodes = gt.get("nodes", {}) if isinstance(gt.get("nodes"), dict) else {}
    api_hosts: list[str] = []
    for key in ("panel", "home"):
        nd = nodes.get(key)
        if isinstance(nd, dict) and nd.get("tailscale_ip"):
            api_hosts.append(str(nd["tailscale_ip"]))
    if not api_hosts:
        api_hosts = ["100.64.0.15"]
    dst_specs = [f"{host}:{port}" for host in api_hosts for port in allowed_ports if port != 22]
    policy = {
        "tagOwners": {
            "tag:admin": ["autogroup:admin"],
            "tag:internal-api": ["autogroup:admin"],
            "tag:ai-sandbox": ["autogroup:admin"],
        },
        "hosts": {
            "starhub-primary-admin": (admin_v4[0] if admin_v4 else "100.64.0.31"),
            "starhub-ai-sandbox-1": sb_v4[0],
        },
        "acls": [
            {"action": "accept", "src": ["tag:admin", "autogroup:admin"], "dst": ["*:*"]},
            {"action": "accept", "src": ["tag:ai-sandbox", *sb_v4], "dst": dst_specs},
        ],
        "ssh": [
            {
                "action": "accept",
                "src": ["tag:admin", "autogroup:admin"],
                "dst": ["tag:internal-api", "autogroup:self"],
                "users": ["autogroup:nonroot", "root"],
            }
        ],
    }
    return json.dumps(policy, indent=2) + "\n"


def render_singbox_guardrails(gt: dict) -> str:
    egress = gt.get("egress_vps", {}) if isinstance(gt.get("egress_vps"), dict) else {}
    primary_tag = next(iter(egress.values()), {"name": "proxy-out"}).get("name", "proxy-out")
    cfg = {
        "dns": {
            "servers": [
                {"tag": "dns-tailscale", "address": "100.100.100.100", "detour": "direct-out"},
                {"tag": "dns-direct", "address": "https://223.5.5.5/dns-query", "detour": "direct-out"},
                {"tag": "dns-remote", "address": "https://1.1.1.1/dns-query", "detour": primary_tag},
            ],
            "rules": [
                {"domain_suffix": [".ts.net", "tailscale.com"], "server": "dns-tailscale"},
                {"rule_set": ["geosite-cn"], "server": "dns-direct"},
            ],
            "final": "dns-remote",
            "independent_cache": True,
        },
        "route": {
            "rules": [
                {
                    "port": [3478],
                    "outbound": "direct-out",
                },
                {
                    "ip_cidr": ["100.64.0.0/10"],
                    "domain_suffix": [".ts.net", "tailscale.com"],
                    "outbound": "direct-out",
                },
                {
                    "network": ["udp"],
                    "port": [443],
                    "domain_suffix": [*APPLE_QUIC_SUFFIXES, *GMAIL_QUIC_SUFFIXES],
                    "domain": GMAIL_QUIC_DOMAINS,
                    "action": "reject",
                },
            ],
            "final": primary_tag,
        },
    }
    return json.dumps(cfg, indent=2) + "\n"


def audit_topology_security(gt: dict) -> dict:
    findings: list[str] = []
    lan_cidr = str(gt.get("home_lan_cidr", ""))
    try:
        net = ipaddress.ip_network(lan_cidr, strict=False)
        is_rfc1918_slash24 = (
            net.version == 4
            and net.prefixlen >= 24
            and (
                net.subnet_of(ipaddress.ip_network("192.168.0.0/16"))
                or net.subnet_of(ipaddress.ip_network("10.0.0.0/8"))
                or net.subnet_of(ipaddress.ip_network("172.16.0.0/12"))
            )
        )
    except ValueError:
        is_rfc1918_slash24 = False
    if is_rfc1918_slash24:
        findings.append(
            f"HIGH_COLLISION_RISK: home_lan_cidr={lan_cidr} overlaps common hotel/coffee-shop Wi-Fi; prefer native Tailscale 100.x + 4via6."
        )
    admin_v4, admin_v6 = _collect_admin_allowlists(gt)
    if not admin_v4 and not admin_v6:
        findings.append("EMPTY_ADMIN_ALLOWLIST: no admin Tailscale IPv4/IPv6 addresses resolved from admin_allowlist_nodes.")
    nodes = gt.get("nodes", {}) if isinstance(gt.get("nodes"), dict) else {}
    b2 = nodes.get("agent_sandbox")
    if isinstance(b2, dict):
        dangerous = {22, 2375, 3306, 5432, 6379}
        for target in b2.get("allowed_targets") or []:
            if ":" in str(target):
                port = int(str(target).rsplit(":", 1)[1])
                if port in dangerous:
                    findings.append(f"SANDBOX_PRIVILEGE_EXPOSURE: agent_sandbox allowed_targets exposes sensitive port :{port} ({target}).")
    return {
        "passed": len(findings) == 0,
        "risk_count": len(findings),
        "findings": findings,
        "summary": "0 security/collision issues detected" if not findings else f"{len(findings)} issue(s) require attention",
    }


def _resolve_profile_template(repo_root: pathlib.Path, profile: str) -> pathlib.Path:
    if profile == "minimal":
        return repo_root / "profiles" / "topology.minimal.json"
    if profile == "ai-sandbox":
        return repo_root / "profiles" / "topology.ai-sandbox.json"
    return repo_root / "topology.example.json"


def _build_cross_platform_targets(gt: dict, target: str) -> dict[str, tuple[str, int]]:
    extra: dict[str, tuple[str, int]] = {}
    if target in ("nftables", "all"):
        extra["nftables/starhub-ai-sandbox.nft"] = (render_nftables_sandbox_guard(gt), 0o644)
    if target in ("macos-pf", "all"):
        extra["macos-pf/com.starhub.ai-sandbox.pf.conf"] = (render_macos_pf_sandbox_anchor(gt), 0o644)
    if target in ("tailscale-acl", "all"):
        extra["tailscale-acl/tailscale-policy.json"] = (render_tailscale_acl_policy(gt), 0o644)
    if target in ("singbox", "all"):
        extra["singbox/singbox-tailscale-quic-guard.json"] = (render_singbox_guardrails(gt), 0o644)
    return extra


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


def _build_bundle_dict(gt: dict) -> dict[str, tuple[str, int]]:
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
    return bundle


def _filter_by_module(
    items: dict[str, tuple[str, int]], only_module: str
) -> dict[str, tuple[str, int]]:
    if only_module == "all":
        return items
    filtered: dict[str, tuple[str, int]] = {}
    for rel, val in items.items():
        match = False
        if only_module == "mihomo":
            match = "mihomo" in rel
        elif only_module == "firewall":
            match = any(tok in rel for tok in ("-fw.sh", "mss-clamp.sh", "cam-gate.sh"))
        elif only_module == "ai-sandbox":
            match = any(
                tok in rel
                for tok in ("agent-tailscale-bootstrap.sh", "starhub-dash-fw.sh", "starhub-home-fw.sh")
            )
        elif only_module == "lifeline":
            match = "ssh_config.starhub" in rel or "systemd/" in rel
        if match:
            filtered[rel] = val
    return filtered


def _select_bundle_for_target(
    gt: dict, only_module: str, target: str
) -> dict[str, tuple[str, int]]:
    if target == "default":
        return _filter_by_module(_build_bundle_dict(gt), only_module)
    if target == "all":
        merged = dict(_filter_by_module(_build_bundle_dict(gt), only_module))
        merged.update(_build_cross_platform_targets(gt, "all"))
        return merged
    return _build_cross_platform_targets(gt, target)


def cmd_render(
    repo_root: pathlib.Path,
    check_only: bool,
    in_place: bool,
    out_dir: pathlib.Path | None,
    profile: str = "full",
    only_module: str = "all",
    dry_run: bool = False,
    target: str = "default",
) -> int:
    if profile in ("minimal", "ai-sandbox") and not check_only and not in_place:
        gt_path = _resolve_profile_template(repo_root, profile)
    else:
        gt_path = repo_root / "STARHUB_GROUND_TRUTH.json"
        if dry_run and not gt_path.is_file():
            gt_path = _resolve_profile_template(repo_root, "full")
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

    if dry_run:
        preview_items = _select_bundle_for_target(gt, only_module, target)
        if not preview_items:
            print(
                f"# [starhub-ctl] No artifacts matched --only={only_module} --target={target} under profile={profile} "
                f"(pass --profile full to preview optional sandbox/DERP modules)."
            )
            return 0
        for rel, (content, mode) in preview_items.items():
            print(
                f"# === [DRY-RUN PREVIEW] {rel} (mode=0o{mode:o}, profile={profile}, only={only_module}, target={target}) ==="
            )
            print(normalize_lf(content).rstrip("\n"))
            print()
        print(
            f"# [starhub-ctl] Dry-run preview complete: {len(preview_items)} artifact(s) rendered to stdout (0 files written, non-root safe)."
        )
        return 0

    if in_place:
        selected_targets = _filter_by_module(targets, only_module)
        for rel, (content, mode) in selected_targets.items():
            fp = repo_root / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(normalize_lf(content), encoding="utf-8")
            os.chmod(fp, mode)
        print(f"[starhub-ctl] Rendered {len(selected_targets)} canonical files in-place under {repo_root}.")
        return 0

    tier = gt.get("deployment_tier")
    if profile == "minimal" or tier == "minimal":
        default_dir_name = "dist-minimal"
    elif profile == "ai-sandbox" or tier == "ai-sandbox":
        default_dir_name = "dist-ai-sandbox"
    else:
        default_dir_name = "dist"
    dest = (out_dir or (repo_root / default_dir_name)).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    bundle = _select_bundle_for_target(gt, only_module, target)

    for rel, (content, mode) in bundle.items():
        fp = dest / rel
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(normalize_lf(content), encoding="utf-8")
        os.chmod(fp, mode)
    print(
        f"[starhub-ctl] Rendered {len(bundle)} deployment artifacts into {dest} (profile={profile}, only={only_module}, target={target})"
    )
    return 0


def cmd_audit(repo_root: pathlib.Path, profile: str = "full") -> int:
    if profile in ("minimal", "ai-sandbox"):
        gt_path = _resolve_profile_template(repo_root, profile)
    else:
        gt_path = repo_root / "STARHUB_GROUND_TRUTH.json"
        if not gt_path.is_file():
            gt_path = _resolve_profile_template(repo_root, "full")
    gt = load_json_compatible(gt_path)
    report = audit_topology_security(gt)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


MCP_TOOLS_SPEC = [
    {
        "name": "compile_ai_sandbox_policy",
        "description": "Compile zero-lateral-movement firewall / ACL policy for autonomous AI coding agents (Linux nftables, macOS pf, Tailscale ACL JSON, or Linux iptables).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "backend": {
                    "type": "string",
                    "enum": ["nftables", "macos-pf", "tailscale-acl", "iptables"],
                    "default": "nftables",
                },
                "sandbox_ips": {"type": "array", "items": {"type": "string"}},
                "allowed_api_targets": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    {
        "name": "render_quic_mesh_guardrails",
        "description": "Render deterministic Tailscale split-DNS + surgical Apple/Gmail UDP/443 QUIC ruleset for Sing-box or Mihomo (Clash Meta).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "engine": {"type": "string", "enum": ["singbox", "mihomo"], "default": "singbox"}
            },
        },
    },
    {
        "name": "audit_topology_security",
        "description": "Audit a StarHub topology JSON for RFC 1918 Wi-Fi subnet collisions and exposed AI sandbox SSH/database ports.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "topology_json": {"type": "string"}
            },
        },
    },
]


def _handle_mcp_request(repo_root: pathlib.Path, req: dict) -> dict | None:
    method = req.get("method", "")
    req_id = req.get("id")
    if req_id is None or method.startswith("notifications/"):
        return None
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "starhub-kit", "version": "1.3.0"},
            },
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCP_TOOLS_SPEC}}
    if method == "tools/call":
        params = req.get("params") or {}
        tool_name = params.get("name")
        t_args = params.get("arguments") or {}
        base_gt = load_json_compatible(_resolve_profile_template(repo_root, "ai-sandbox"))
        if tool_name == "compile_ai_sandbox_policy":
            b2 = base_gt.setdefault("nodes", {}).setdefault("agent_sandbox", {})
            if t_args.get("sandbox_ips"):
                b2["tailscale_ips"] = list(t_args["sandbox_ips"])
            if t_args.get("allowed_api_targets"):
                b2["allowed_targets"] = list(t_args["allowed_api_targets"])
            backend = t_args.get("backend", "nftables")
            if backend == "nftables":
                out = render_nftables_sandbox_guard(base_gt)
            elif backend == "macos-pf":
                out = render_macos_pf_sandbox_anchor(base_gt)
            elif backend == "tailscale-acl":
                out = render_tailscale_acl_policy(base_gt)
            else:
                out = render_dash_fw(base_gt)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": out}], "isError": False},
            }
        if tool_name == "render_quic_mesh_guardrails":
            engine = t_args.get("engine", "singbox")
            out = render_singbox_guardrails(base_gt) if engine == "singbox" else render_standalone_mihomo_guardrails(base_gt)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": out}], "isError": False},
            }
        if tool_name == "audit_topology_security":
            raw_json = t_args.get("topology_json")
            gt_obj = load_json_compatible_from_str(raw_json) if raw_json else base_gt
            verdict = audit_topology_security(gt_obj)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(verdict, indent=2)}],
                    "isError": not verdict["passed"],
                },
            }
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32602, "message": f"Unknown tool: {tool_name}"},
        }
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def serve_mcp_stdio(repo_root: pathlib.Path, in_stream, out_stream) -> int:
    while True:
        line = in_stream.readline()
        if not line:
            break
        stripped = line.strip()
        if not stripped:
            continue
        use_headers = False
        if stripped.lower().startswith(b"content-length:"):
            use_headers = True
            length = int(stripped.split(b":", 1)[1].strip())
            while True:
                hdr = in_stream.readline()
                if not hdr or hdr in (b"\r\n", b"\n"):
                    break
            payload = in_stream.read(length)
        else:
            payload = stripped
        req = json.loads(payload.decode("utf-8"))
        resp = _handle_mcp_request(repo_root, req)
        if resp is not None:
            encoded = json.dumps(resp).encode("utf-8")
            if use_headers:
                out_stream.write(f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii") + encoded)
            else:
                out_stream.write(encoded + b"\n")
            out_stream.flush()
    return 0


def build_reproducible_tarball_bytes(
    repo_root: pathlib.Path, prefix: str = "starhub-kit"
) -> tuple[bytes, int]:
    skip_dirs = {".git", "__pycache__", "node_modules", ".next", "dist", "dist-minimal", "dist-ai-sandbox", ".pytest_cache"}
    entries: list[tuple[str, pathlib.Path]] = []
    for root, dirs, files in os.walk(repo_root, followlinks=False):
        dirs[:] = sorted(
            d for d in dirs if d not in skip_dirs and not d.startswith("dist_")
        )
        rp = pathlib.Path(root)
        for name in sorted(files):
            if name.endswith((".pyc", ".pyo")):
                continue
            fp = rp / name
            rel = fp.relative_to(repo_root).as_posix()
            entries.append((rel, fp))
        for dname in list(dirs):
            dp = rp / dname
            if dp.is_symlink():
                rel = dp.relative_to(repo_root).as_posix()
                entries.append((rel, dp))
                dirs.remove(dname)

    entries.sort(key=lambda item: item[0])
    clean_prefix = prefix.strip("/") or "starhub-kit"
    raw_buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw_buf, compresslevel=9, mtime=0) as gz:
        with tarfile.open(mode="w", fileobj=gz, format=tarfile.PAX_FORMAT) as tf:
            for rel, fp in entries:
                arcname = f"{clean_prefix}/{rel}"
                ti = tarfile.TarInfo(name=arcname)
                ti.mtime = 0
                ti.uid = 0
                ti.gid = 0
                ti.uname = ""
                ti.gname = ""
                ti.pax_headers = {}
                if fp.is_symlink():
                    ti.type = tarfile.SYMTYPE
                    ti.linkname = os.readlink(fp)
                    ti.mode = 0o777
                    tf.addfile(ti)
                elif fp.is_file():
                    data = fp.read_bytes()
                    ti.type = tarfile.REGTYPE
                    ti.size = len(data)
                    ti.mode = 0o755 if os.access(fp, os.X_OK) else 0o644
                    tf.addfile(ti, io.BytesIO(data))
    return raw_buf.getvalue(), len(entries)


def cmd_archive(
    repo_root: pathlib.Path,
    output: pathlib.Path | None,
    prefix: str,
    verify: bool,
    verify_file: pathlib.Path | None = None,
) -> int:
    bytes_a, file_count = build_reproducible_tarball_bytes(repo_root, prefix)
    sha_a = hashlib.sha256(bytes_a).hexdigest()

    if verify_file is not None:
        if not verify_file.is_file():
            print(f"[FAIL] [REPRODUCIBLE-BUILD] Archive not found: {verify_file}", file=sys.stderr)
            return 1
        actual_sha = hashlib.sha256(verify_file.read_bytes()).hexdigest()
        if actual_sha != sha_a:
            print(
                f"[FAIL] [REPRODUCIBLE-BUILD] Digest mismatch for {verify_file}: expected {sha_a}, got {actual_sha}",
                file=sys.stderr,
            )
            return 1
        print(
            f"[PASS] [REPRODUCIBLE-BUILD] {verify_file} matches source tree bit-for-bit (sha256={sha_a}, files={file_count})."
        )
        return 0

    if verify:
        bytes_b, _ = build_reproducible_tarball_bytes(repo_root, prefix)
        sha_b = hashlib.sha256(bytes_b).hexdigest()
        if bytes_a != bytes_b or sha_a != sha_b:
            print("[FAIL] [REPRODUCIBLE-BUILD] Non-deterministic archive output detected!", file=sys.stderr)
            return 1

    if output is not None:
        out_path = output.resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(bytes_a)
        print(
            f"[PASS] [REPRODUCIBLE-BUILD] Wrote deterministic archive {out_path} (sha256={sha_a}, files={file_count}, mtime=0, uid/gid=0)."
        )
        return 0

    print(
        f"[PASS] [REPRODUCIBLE-BUILD] Bit-for-bit deterministic archive verified (sha256={sha_a}, files={file_count}, mtime=0, uid/gid=0)."
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="StarHub Declarative Compiler & Open-Source Toolkit CLI"
    )
    parser.add_argument(
        "--repo-root",
        type=pathlib.Path,
        default=DEFAULT_REPO_ROOT,
        help="Repository root directory",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_init = sub.add_parser("init", help="Create STARHUB_GROUND_TRUTH.json from full, minimal, or ai-sandbox template")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing STARHUB_GROUND_TRUTH.json")
    p_init.add_argument("--profile", choices=("full", "minimal", "ai-sandbox"), default="full", help="Topology template tier")

    p_render = sub.add_parser("render", help="Compile firewall/nftables/pf/Tailscale-ACL/Sing-box/Mihomo/Lifeline artifacts")
    p_render.add_argument("--profile", choices=("full", "minimal", "ai-sandbox"), default="full", help="Render full, minimal, or ai-sandbox tier")
    p_render.add_argument(
        "--only",
        choices=("all", "firewall", "mihomo", "ai-sandbox", "lifeline"),
        default="all",
        help="Compile or preview only a specific subsystem module",
    )
    p_render.add_argument(
        "--target",
        choices=("default", "nftables", "macos-pf", "tailscale-acl", "singbox", "all"),
        default="default",
        help="Cross-platform policy backend to emit",
    )
    g_mode = p_render.add_mutually_exclusive_group()
    g_mode.add_argument("--check", action="store_true", help="Verify canonical repo scripts match SSOT with zero drift")
    g_mode.add_argument("--in-place", action="store_true", help="Update canonical scripts under scripts/ in-place")
    g_mode.add_argument("--out-dir", type=pathlib.Path, help="Output directory for rendered bundle")
    g_mode.add_argument("--dry-run", action="store_true", help="Preview rendered rules/scripts to stdout with zero disk writes or root privileges")

    p_audit = sub.add_parser("audit", help="Audit topology for RFC 1918 Wi-Fi collision risks and exposed AI sandbox ports")
    p_audit.add_argument("--profile", choices=("full", "minimal", "ai-sandbox"), default="full", help="Topology tier to audit")

    sub.add_parser("mcp", help="Run zero-dependency Model Context Protocol (MCP) JSON-RPC 2.0 server over stdio")

    p_archive = sub.add_parser("archive", help="Build or verify a bit-for-bit reproducible source tarball")
    p_archive.add_argument("--output", type=pathlib.Path, help="Write deterministic .tar.gz to this path")
    p_archive.add_argument("--prefix", default="starhub-kit", help="Top-level directory prefix inside tarball")
    p_archive.add_argument("--verify", action="store_true", help="Verify bit-for-bit determinism across independent builds")
    p_archive.add_argument("--verify-file", type=pathlib.Path, help="Verify an existing .tar.gz byte-for-byte against the current source tree")

    sub.add_parser("doctor", help="Run StarHub EGM 3.0 zero-drift & zero-PII verification harness")
    sub.add_parser("export-workstation", help="Export [WORKSTATION] ledger entries")

    args, extra_args = parser.parse_known_args()
    repo_root = args.repo_root.resolve()

    if args.subcommand in ("init", "render", "audit", "mcp", "archive", "export-workstation") and extra_args:
        parser.error(f"unrecognized arguments: {' '.join(extra_args)}")

    if args.subcommand == "init":
        return cmd_init(repo_root, args.force, args.profile)
    if args.subcommand == "render":
        return cmd_render(
            repo_root,
            args.check,
            args.in_place,
            args.out_dir,
            args.profile,
            args.only,
            args.dry_run,
            args.target,
        )
    if args.subcommand == "audit":
        return cmd_audit(repo_root, args.profile)
    if args.subcommand == "mcp":
        return serve_mcp_stdio(repo_root, sys.stdin.buffer, sys.stdout.buffer)
    if args.subcommand == "archive":
        return cmd_archive(repo_root, args.output, args.prefix, args.verify, args.verify_file)
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
