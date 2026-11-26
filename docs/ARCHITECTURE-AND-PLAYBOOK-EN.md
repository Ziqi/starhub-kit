# StarHub Kit Architecture & Protocol Playbook (English)

> **Version**: `StarHub Kit v1.3.0` · **Companion Docs**: [README.md](../README.md) · [README.zh-CN.md](../README.zh-CN.md) · [SECURITY.md](../SECURITY.md)

This playbook distills the core protocol engineering, firewall invariants, and progressive deployment tiers behind **StarHub Kit** for international homelab operators, network engineers, and AI infrastructure builders.

---

## 1. Three Progressive Adoption Tiers

You do **not** need a Proxmox cluster, dedicated observability nodes, or three overseas VPS relays to use StarHub Kit. Pick the tier that matches your hardware:

| Tier | Target Setup | Time to Deploy | Entrypoint |
| :--- | :--- | :--- | :--- |
| **Tier 0 · Drop-In Ruleset** | Any existing **OpenWrt / Clash Verge / Mihomo Party / Stash + Tailscale** setup | **30 seconds** (Zero Python) | Copy sections from [`scripts/profiles/standalone-mihomo-tailscale-guardrails.yaml`](../scripts/profiles/standalone-mihomo-tailscale-guardrails.yaml) into your `config.yaml` |
| **Tier 1 · StarHub Lite (`minimal`)** | **1 Gateway** (Linux LXC / Mini-PC) + **1 Controller** (`laptop`) + **1 Egress** (`vps1`) | **3 minutes** | `./bin/starhub render --profile minimal --out-dir ./dist-minimal` (edit [`profiles/topology.minimal.json`](../profiles/topology.minimal.json)) |
| **Tier 2 · Full Reference Blueprint** | Multi-site mesh + isolated compute workstation + cloud AI `B2` sandboxes + IoT kill-switch + 4-way SSH lifelines | **15 minutes** | `./bin/starhub init && ./bin/starhub render --out-dir ./dist` ([`topology.example.json`](../topology.example.json)) |

---

## 2. Protocol Deep Dive #1: Breaking the Tailscale × Fake-IP Loop & DNS Races

Running Tailscale alongside a Fake-IP transparent gateway (`198.18.0.0/16`, `tun: gvisor`) triggers three classic failure modes if left unguarded:

1. **Fake-IP Hijacking of Tailscale Control & DERP Relays**:
   - If `*.tailscale.com`, `*.ts.net`, STUN (`UDP/3478`), or your egress server IP resolves to a `198.18.x.x` Fake-IP or enters the proxy tunnel, WireGuard handshakes recurse into the proxy tunnel itself and collapse.
   - **Fix**: Pin `+.ts.net` to `100.100.100.100#tailscale0` in `nameserver-policy` and place `DST-PORT,3478,DIRECT`, `DOMAIN-SUFFIX,tailscale.com,DIRECT`, `DOMAIN-SUFFIX,ts.net,DIRECT`, `IP-CIDR,100.64.0.0/10,DIRECT,no-resolve`, and egress `/32` exemptions at the very top of `rules:`.
2. **Eliminating Blind `fallback:` DNS Racing & Single-Node DoH/DoT SPOF**:
   - Many community Clash templates configure both domestic and overseas resolvers under `nameserver:` + `fallback:`. Under cross-border jitter, slow responses trigger hundreds of `context canceled` half-open sockets per day and poison domestic CDN GeoIP locality.
   - Pinning overseas DoH/DoT to a single proxy node (e.g., `#EgressPrimary`) creates a hidden single point of failure: if that one node hits its quota or drops offline, *every* overseas DNS query fails even when backup proxies are healthy.
   - **Fix**: Remove `fallback:` completely, enforce `respect-rules: true` with deterministic `nameserver-policy`, and bind `geosite:geolocation-!cn` to a **failover proxy-group** (`https://1.1.1.1/dns-query#AutoSelect`). Both `starhub audit` and `starhub-doctor.py` fail closed if single-node DNS pinning creeps back in.
3. **Zero-Collision `100.x` + `4via6` & TCP MSS Clamping**:
   - Advertising RFC 1918 `/24` LAN routes over Tailscale breaks local Wi-Fi routing whenever a hotel or coffee-shop network uses the same subnet. StarHub uses native `100.64.0.0/10` on containers and Tailscale `4via6` (`fd7a:115c:a1e0::/48`) for non-Tailscale appliances, paired with `iptables -t mangle ... -j TCPMSS --clamp-mss-to-pmtu` and `STARHUB-IPV6-EXIT-GUARD` (`starhub-ts-mss-clamp.sh`) so encapsulated frames never stall on PMTU blackholes or leak native IPv6.

---

## 3. Protocol Deep Dive #2: Surgical `Section 9a` QUIC (`UDP/443`) Governance

Cross-border VLESS/XUDP tunnels frequently experience asymmetric packet loss or middlebox throttling on long-lived `UDP/443` QUIC flows—yet handling `UDP/443` naively creates a painful dilemma:

- **If you allow all `UDP/443` through Fake-IP proxy tunnels**: Apple Media (`tv.apple.com`, `mzstatic.com`) and **mobile Gmail inline images & attachments** (`mail-attachment.googleusercontent.com`, `ci3~6.googleusercontent.com`, `lh3~6.googleusercontent.com`, `robinfrontend-pa.googleapis.com`) stall for 30–50 seconds waiting on dead QUIC streams before timing out.
- **If you globally `REJECT` all `UDP/443`**: YouTube's Cronet engine (`youtube.com`, `googlevideo.com`, `youtubei.googleapis.com`) loses native `HTTP/3` multiplexing and suffers caption/abr stalls on smart TVs.

### The StarHub `Section 9a` Solution & Rule-Ordering Invariant

```mermaid
flowchart TD
    PKT["Outbound UDP/443 Packet"] --> CHK1{"Matches Section 9a<br/>12 Apple or 21 Gmail/Attachment<br/>QUIC Domains?"}
    CHK1 -- "Yes (Evaluated BEFORE broad Google rules)" --> REJ["Immediate ICMP Port Unreachable (REJECT)<br/>Client falls back to TCP/TLS 1.3 in <5 ms"]
    CHK1 -- "No (e.g. googlevideo.com / YouTube)" --> PROXY["Evaluated by Downstream Proxy Rules<br/>Preserves Native HTTP/3 Cronet Multiplexing"]
```

> **Critical Ordering Guardrail**: `AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN,ci3.googleusercontent.com)),REJECT` **must** appear strictly **above** any broad `DOMAIN-SUFFIX,googleapis.com,PROXY`, `DOMAIN-SUFFIX,googleusercontent.com,PROXY`, or `GEOSITE,google,PROXY` rule. In first-match rule engines, placing `Section 9a` below wildcard Google rules shadows the `REJECT` rule and silently re-introduces mobile Gmail attachment stalls. `starhub-doctor.py` enforces both presence (`12/12` Apple + `21/21` Gmail) and zero YouTube Cronet collateral damage on every commit.

---

## 4. Security Deep Dive #3: Cloud AI Sandbox (`B2`) & Workstation Isolation

When granting autonomous AI coding agents or cloud sandboxes access to homelab telemetry, trusting flat VPN peer connectivity is dangerous:

1. **Per-Instance Userspace State Isolation (`scripts/agent-tailscale-bootstrap.sh`)**:
   - Ephemeral cloud sandboxes isolate `--statedir=/tmp/tailscale-<instance_id>` and run `--tun=userspace-networking` exposing a local SOCKS5/HTTP proxy on `127.0.0.1:1055`, preventing `NodeKey` split-brain across concurrent agent workers.
2. **Dual-Stack `STARHUB-BOT-NOSSH` / `NOSSH6` Hard-DROP**:
   - Compiled host firewalls (`starhub-dash-fw.sh`, `starhub-home-fw.sh`) dynamically enumerate `agent_sandbox` Tailscale IPv4/IPv6 peers and permit **only** read/control HTTP APIs (`:3001`/`:8080`) while inserting explicit TCP `:22` `DROP` rules at the top of `INPUT`.
3. **One-Way Controlled Compute Workstations**:
   - High-throughput workstations (`workstation`, `gpu-worker`) are compiled with `ForwardAgent no` and `IdentitiesOnly yes` in `ssh_config.starhub`, preventing compromised compute tasks from hijacking operator SSH agent sockets to pivot back into primary controllers.

---

## 5. Production Gateway Hardening Playbook (5 Field-Proven Fixes)

Beyond the baseline split-DNS and `Section 9a` QUIC rules, five subtle production failure modes recur on multi-client transparent gateways and cross-ISP overlays:

1. **Anti-SPOF Overseas DNS (`#AutoSelect`)**:
   - Never attach an overseas DoH/DoT resolver to a single proxy node (`#EgressPrimary`). Always route `geosite:geolocation-!cn` through a `fallback` proxy-group (`#AutoSelect`) so DNS resolution fails over seamlessly when a single egress VPS goes down or exhausts quota.
2. **Multi-Client Source-IP Physical Isolation (Keeping Domestic Streaming 100% `DIRECT`)**:
   - Heavy 4K streaming devices (`smart_tv` `192.0.2.63/32`), primary developer laptops (`laptop` `192.0.2.31/32`), and mobile Exit-Node traffic should not contend on the same upstream egress IP or burn residential quota.
   - Use semantic IP-suffix / role naming (e.g., `EgressPrimary`, `EgressWorkstation`, high-quota datacenter `EgressBackup`), exempt LAN/private ranges first (`IP-CIDR,192.0.2.0/24,DIRECT,no-resolve`, `GEOIP,private,DIRECT,no-resolve`), then apply `AND,((SRC-IP-CIDR,<client>/32),(NOT,((GEOSITE,cn))),(NOT,((GEOIP,cn,no-resolve)))),<Group>` above broad proxy rules and a matching `SRC-IP-CIDR,<client>/32,<Group>,no-resolve` fallback right above `MATCH,PROXY`. Domestic streaming and local LAN stay 100% `DIRECT` while each client's overseas traffic is isolated cleanly.
3. **Eliminating the 60-Second `unknown` Blind Window After Mihomo Hot-Reload**:
   - Right after `PUT /configs?force=true` hot-reloads `/etc/mihomo/config.yaml`, `fallback` and `url-test` groups start with delay `unknown` until the first periodic health-check tick fires (often 60–120s). During that blind window, the first minute of outbound traffic can still be dispatched to a dead or quota-exhausted first member.
   - **Fix**: Immediately chain a `/group/<Group>/delay` (and/or `/proxies/<Node>/delay`) probe call right after `PUT /configs?force=true` (see [docs/02-日常运维与变更升级.md](./02-日常运维与变更升级.md)) so failover converges within 1–2 seconds of reload.
4. **New Egress Bootstrap Against `gvisor TUN` Self-Hijack, Ubuntu 24.04 SSH Override & Dual-Port Reality (`:8080 + :443`)**:
   - **Pre-SSH Anti-Loop**: When provisioning a new egress VPS from behind a transparent `gvisor TUN` gateway, add `IP-CIDR,<new_vps_ip>/32,DIRECT,no-resolve` to `rules:` and hot-reload *before* initiating SSH bootstrap — otherwise the gateway intercepts your own SSH session into the proxy tunnel or loops during sing-box cutover.
   - **Ubuntu 24.04 Cloud-Image SSH Gotcha**: Many Ubuntu 24.04 cloud images ship `/etc/ssh/sshd_config.d/50-cloud-init.conf` (or vendor drop-ins) containing `PubkeyAuthentication no` or `PasswordAuthentication yes`, which silently overrides `/etc/ssh/sshd_config`. Always verify effective policy with `sshd -T | grep -E 'pubkeyauthentication|permitrootlogin'` before closing your initial root session.
   - **Dual-Port Reality (`:8080 + :443`)**: Some residential dual-ISP lines intermittently throttle or drop `:443` toward specific ASNs. [`templates/singbox-reality-server.json.tmpl`](../templates/singbox-reality-server.json.tmpl) listens simultaneously on `8080` (`vless-reality-8080`) and `443` (`vless-reality-443`) so clients can fail over ports without re-provisioning the server.
5. **Cross-ISP Real-Time Voice Single-Hop Isolation (`VoiceRealtime`)**:
   - Latency-sensitive real-time ASR / voice streams (e.g., `wisprflow.ai`, `deepgram.com`) break audibly when routed through double-hop relays or oscillating `url-test` groups.
   - Keep regular browsing on `url-test` / `AutoSelect`, while binding real-time voice domains to a dedicated single-hop `fallback` group (`VoiceRealtime`) that contains **only** direct single-hop egress nodes (excluding relays).

---

## 6. Continuous Verification Commands

```bash
# 1. Compile minimal single-gateway bundle (Tier 1 StarHub Lite)
./bin/starhub render --profile minimal --out-dir ./dist-minimal

# 2. Verify zero drift across all 8 canonical compiled artifacts
./bin/starhub render --check

# 3. Run 30-check EGM 3.0 static harness + >=80% coverage gate + 2,000-iteration fuzzer
./bin/starhub doctor --local-docs-only
python3 ./tests/test_coverage_gate.py --min-coverage 80
python3 ./tests/fuzz_starhub_ctl.py --iterations 2000
```
