# Contributing to StarHub Kit

Thank you for contributing to **StarHub Kit** (`starhub-kit`), the declarative, zero-drift multi-site mesh, anti-stall gateway, and AI-governed infrastructure toolkit.

## Core Engineering Principles

1. **Zero Third-Party Runtime Dependencies in Core CLI**:
   - `scripts/starhub-ctl.py` and `scripts/starhub-doctor.py` must run on stock **Python 3.9+ standard library** (`json`, `pathlib`, `re`, `subprocess`, `hashlib`, `urllib`) so any fresh Debian/Proxmox LXC or macOS machine can run `./bin/starhub` out of the box.
2. **Single Source of Truth (`STARHUB_GROUND_TRUTH.json`)**:
   - Never hardcode IP addresses, ports, or domain names inside Python or Bash templates. Add fields to `topology.example.json` and compile via `./bin/starhub render --in-place`.
3. **EGM 3.0 Pre-Commit Gate**:
   - Install the tracked Git pre-commit hook before making commits:
     ```bash
     cp scripts/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
     ```
   - Every pull request must pass all three checks with `FAIL=0`:
     ```bash
     ./bin/starhub render --check
     ./bin/starhub render --out-dir ./dist && bash -n ./bin/starhub ./scripts/*.sh ./dist/*.sh
     ./bin/starhub doctor --local-docs-only
     ```
4. **RFC Documentation Addresses Only**:
   - All examples, tests, and documentation in this repository MUST strictly use IETF reserved documentation ranges:
     - IPv4 LAN / WAN: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC 5737)
     - CGNAT / Mesh: `100.64.0.0/10` (RFC 6598)
     - IPv6: `2001:db8::/32` (RFC 3849)
     - MAC addresses: `00:53:00:00:00:00` – `00:53:00:ff:ff:ff` (RFC 7042)
     - Domains: `example.com` / `example.net` / `example.org` (RFC 2606)

## Documentation Whitelist Discipline

To prevent documentation sprawl and AI agent context drift, active Markdown files are strictly locked in `allowed_active_markdown_files` inside [STARHUB_GROUND_TRUTH.json](STARHUB_GROUND_TRUTH.json). When proposing a new architectural manual, discuss consolidating it into the existing 6 Golden Books (`docs/01`–`06`) or [docs/ROADMAP-v2.md](docs/ROADMAP-v2.md) first.
