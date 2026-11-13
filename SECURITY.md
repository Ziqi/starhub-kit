# Security Policy & Zero-PII Architecture

## 1. Zero-Secret & Zero-PII Guarantee

`starhub-kit` enforces strict separation between **engine code** (public) and **live infrastructure secrets/topology** (private):

1. **No Secrets in Git (`DIM4-SECRET-GUARD`)**:
   - `.env` files, SSH private keys (`-----BEGIN ... PRIVATE KEY-----`), VLESS UUIDs, Reality private keys, and Mihomo controller secrets (`secret: ""` only in repo templates) are blocked by both `.gitignore` and `./bin/starhub doctor`.
   - On live hosts, all credential files (`/etc/mihomo/config.yaml`, `/opt/starhub-*/.env`, `/usr/local/starhub/lifeline/id_ed25519`) must be locked to `chmod 0600`.
2. **Mathematical Zero-PII Release Sanitizer (`--verify-public-export`)**:
   - Operators maintaining both a private production repo and a public fork can run:
     ```bash
     python3 scripts/starhub-doctor.py \
       --verify-public-export /path/to/starhub-kit \
       --private-gt /path/to/private/STARHUB_GROUND_TRUTH.json
     ```
   - The sanitizer extracts every real IPv4, Tailscale IPv4/IPv6/`4via6`, hardware MAC, custom domain, and handle from the private SSOT and scans both the public working tree and `git log -p --all` byte-by-byte.

## 2. Cloud AI Agent Sandbox Isolation (`B2` Restricted Guest Mode)

When granting cloud AI agents (such as ephemeral container sandboxes) read/action access to self-hosted dashboards:
- **Never expose `:22` SSH or Docker/Portainer sockets (`:8000/:9000/:9443`) to cloud agent nodes.**
- Always generate dual-stack `iptables` + `ip6tables` chains (`STARHUB-BOT-NOSSH` & `STARHUB-BOT-NOSSH6`) via `./bin/starhub render`, which hard-`DROP` TCP/22 from both static and dynamically discovered sandbox peers while permitting only designated HTTP API ports (`:3001` / `:8080`).
- Isolate each ephemeral sandbox's Tailscale state directory (`--statedir=/tmp/tailscale-<instance-id>`) via [scripts/grokbot-tailscale-bootstrap.sh](scripts/grokbot-tailscale-bootstrap.sh) to prevent multi-container `NodeKey` / `HomeDERP` split-brain.

## 3. Supply-Chain Hardening & OpenSSF Compliance

- **Immutable GitHub Actions (`Pinned-Dependencies`)**: All workflows in `.github/workflows/` (`ci.yml`, `scorecard.yml`, `codeql.yml`) pin actions to full 40-character commit SHAs with least-privilege `permissions` and `persist-credentials: false`, monitored weekly by `.github/dependabot.yml`.
- **Static Analysis & Scorecard**: Every push to `main` runs **CodeQL** (Python SAST), **StarHub EGM 3.0** (`render --check` + 7-dim static harness), and **OpenSSF Scorecard** (`ossf/scorecard-action`).
- **SPDX / REUSE 3.2**: All source scripts carry `# SPDX-License-Identifier: MIT` headers, with repository-wide machine-readable licensing declared in `REUSE.toml` and citation metadata in `CITATION.cff`.
- **Claiming the OpenSSF Best Practices (`Passing`) Badge**: Repository maintainers can log in via GitHub OAuth at `https://www.bestpractices.dev/en/projects/new` for `https://github.com/Ziqi/starhub-kit`—all required criteria (OSI MIT license, English documentation, automated test suite `./bin/starhub doctor`, SAST via CodeQL, vulnerability reporting channel, zero hardcoded credentials) are pre-satisfied out of the box.

## 4. Reporting a Vulnerability

Please do **not** open public GitHub issues for sensitive security vulnerabilities (e.g., firewall bypasses in `STARHUB-*-ACL` or sanitizer evasions). Use GitHub's **Report a vulnerability** (Private Security Advisories) tab on the repository so maintainers can validate and ship a fix prior to disclosure.
