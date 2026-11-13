#!/usr/bin/env bash
# StarHub Cam-Gate: Physical gateway-level cloud uplink kill-switch for IoT camera (192.0.2.40)
set -uo pipefail
FLAG=/var/lib/starhub-probe/cam-gate.off
mkdir -p /var/lib/starhub-probe

apply_drop() {
  iptables -t mangle -C FORWARD -s 192.0.2.40 -o Meta -j DROP 2>/dev/null \
    || iptables -t mangle -I FORWARD 1 -s 192.0.2.40 -o Meta -j DROP
}

clear_drop() {
  while iptables -t mangle -D FORWARD -s 192.0.2.40 -o Meta -j DROP 2>/dev/null; do
    :
  done
}

case "${1:-status}" in
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
