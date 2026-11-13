# StarHub Roadmap `v2.0` — Pluggable Dashboard & Home OS Driver Spec

> **Status**: Interface Specification Frozen in `v1.0.0` · Target Implementation: `v2.0`  
> **Related**: [README.md](../README.md) · [AGENTS.md](../AGENTS.md) · [05-智能家居与AI中枢全景.md](./05-智能家居与AI中枢全景.md)

`starhub-kit v1.0` delivers the zero-dependency declarative core (`starhub-ctl.py`), anti-stall gateway/firewall compiler, out-of-band lifelines, and `StarHub EGM 3.0` governance harness. `v2.0` decouples the observability dashboard (`:3001`) and Smart Home hub (`:8080`) from hardcoded vendor logic via two declarative plugin contracts.

---

## 1. Declarative Observability Probe Contract (`:3001` Dashboard `v2.0`)

Instead of hardcoding probe targets in TypeScript/Python handlers, `v2.0` reads a `probes[]` array directly from `STARHUB_GROUND_TRUTH.json`:

```json
{
  "probes": [
    {
      "id": "gw-mihomo-api",
      "name": "Mihomo Gateway",
      "driver": "http_bearer",
      "target": "http://${nodes.gw.lan_ip}:9090/version",
      "secret_env": "MIHOMO_API_SECRET",
      "critical": true,
      "timeout_ms": 2500
    },
    {
      "id": "derp-relay-tcp",
      "name": "Custom DERP Relay",
      "driver": "tcp_connect",
      "target": "${nodes.derp.public_ip}:8443",
      "critical": true,
      "timeout_ms": 3000
    }
  ]
}
```

### Built-in Probe Drivers Planned for `v2.0`
- `tcp_connect`: raw TCP handshake latency & reachability (`ONT`, `DERP`, `SSH`).
- `http_json` / `http_bearer`: REST health endpoints (`Mihomo :9090`, `PVE :8006`, `Home OS :8080`).
- `dns_fakeip`: UDP/TCP `:53` and `:1053` query verifying `198.18.0.0/16` Fake-IP resolution.
- `mihomo_proxy_delay`: queries `/proxies/<name>/delay` for each entry in `egress_vps`.
- `incidents_drawer`: mounts `docs/incidents/*.md` read-only to render `5-Why` postmortems in the web UI.

---

## 2. Pluggable Smart Home Driver Contract (`StarHub Home OS v2.0-spec`)

To let community users mix and match Home Assistant, network speakers, Android TV, microcontroller status displays, or RTSP cameras without editing `server.py`, `StarHub Home OS v2.0-spec` introduces `drivers/<driver_name>.py`:

```python
from typing import Any, Protocol

class HomeDriver(Protocol):
    driver_id: str          # e.g., "android_tv_adb", "airplay_pyatv", "cam_gate_mangle"
    display_name: str       # UI card title (strictly ASCII/CJK text, emoji_count == 0)

    def status(self) -> dict[str, Any]:
        """Return normalized health, power/standby state, and telemetry."""
        ...

    def execute(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Execute a guardrail-checked action (e.g., 'soft_standby', 'tts_speak', 'cloud_off')."""
        ...
```

### Mandatory Safety Invariants Enforced Across All `v2.0` Drivers
1. **Zero-Emoji Production UI (`DIM5-IOT-SSOT`)**: `index.html`, `static/index.html`, `server.py`, and all `drivers/*.py` must maintain `emoji_count == 0` and byte-identical static HTML sync.
2. **Non-Destructive Standby Guardrail**: Android TV / display drivers must implement `soft_standby` via screen-dimming/blackout overlay rather than hardware power-off keycodes (`keycode=power` / Android keycode `223`) that disconnect Wi-Fi.
3. **Gateway-Enforced Privacy**: Camera privacy drivers must toggle `iptables -t mangle` forwarding rules on `gw` (`cam-gate.sh`) rather than trusting closed-source camera firmware "privacy modes".
