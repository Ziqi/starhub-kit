#!/usr/bin/env bash
# ==============================================================================
# StarHub GrokBot Cloud Sandbox Tailscale Bootstrap (B2 Direct Mode)
# Purpose:
#   1. Per-instance state isolation (--statedir=/tmp/tailscale-<instance>) to
#      prevent multi-sandbox NodeKey/HomeDERP split-brain (INC-20261112-001).
#   2. Userspace networking + local SOCKS5/HTTP proxy on 127.0.0.1:1055.
#   3. DERP / WireGuard handshake pre-warm against .13 (100.64.0.13),
#      .22 (100.64.0.22), and Air (100.64.0.100).
# ==============================================================================
set -euo pipefail

RAW_ID="${GROKBOT_INSTANCE_ID:-$(hostname -s 2>/dev/null || true)}"
if [[ -z "${RAW_ID}" || "${RAW_ID}" == "localhost" || "${RAW_ID}" == "box" ]]; then
  RAW_ID="$(cut -c1-8 /proc/sys/kernel/random/boot_id 2>/dev/null || echo "$$")"
fi
SAFE_ID="$(printf '%s' "${RAW_ID}" | tr -cd 'a-zA-Z0-9_-')"

STATE_DIR="/tmp/tailscale-${SAFE_ID}"
SOCK="${STATE_DIR}/tailscaled.sock"
PROXY_ADDR="127.0.0.1:1055"
HOSTNAME_TAG="grokbot-${SAFE_ID}"

mkdir -p "${STATE_DIR}"
chmod 700 "${STATE_DIR}"

if ! tailscale --socket="${SOCK}" status >/dev/null 2>&1; then
  nohup tailscaled \
    --tun=userspace-networking \
    --statedir="${STATE_DIR}" \
    --socket="${SOCK}" \
    --socks5-server="${PROXY_ADDR}" \
    --outbound-http-proxy-listen="${PROXY_ADDR}" \
    >"${STATE_DIR}/tailscaled.log" 2>&1 &
  for _ in $(seq 1 20); do
    [[ -S "${SOCK}" ]] && break
    sleep 0.3
  done
fi

UP_ARGS=(--socket="${SOCK}" up --accept-routes=false --accept-dns=false --hostname="${HOSTNAME_TAG}")
if [[ -n "${TS_AUTHKEY:-}" ]]; then
  UP_ARGS+=(--authkey="${TS_AUTHKEY}")
fi
tailscale "${UP_ARGS[@]}"

# Pre-warm WireGuard / DERP sessions to StarHub B2 endpoints (24/7 online even when Air sleeps)
for peer in 100.64.0.13 100.64.0.22 100.64.0.100; do
  tailscale --socket="${SOCK}" ping -c 1 --timeout=4s "${peer}" >/dev/null 2>&1 || true
done

cat <<EOF
[StarHub B2 Ready]
  Instance   : ${HOSTNAME_TAG}
  Socket     : ${SOCK}
  Proxy      : socks5h://${PROXY_ADDR} (HTTP: http://${PROXY_ADDR})
  Dashboard  : curl --socks5-hostname ${PROXY_ADDR} -fsS http://100.64.0.13:3001/api/health
  Home OS    : curl --socks5-hostname ${PROXY_ADDR} -fsS http://100.64.0.22:8080/api/status
EOF
