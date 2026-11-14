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
- Isolate each ephemeral sandbox's Tailscale state directory (`--statedir=/tmp/tailscale-<instance-id>`) via [scripts/agent-tailscale-bootstrap.sh](scripts/agent-tailscale-bootstrap.sh) to prevent multi-container `NodeKey` / `HomeDERP` split-brain.

## 3. Supply-Chain Hardening & OpenSSF Compliance

- **Immutable GitHub Actions (`Pinned-Dependencies`)**: All workflows in `.github/workflows/` (`ci.yml`, `scorecard.yml`, `codeql.yml`) pin actions to full 40-character commit SHAs with least-privilege `permissions` and `persist-credentials: false`, monitored weekly with grouped updates by `.github/dependabot.yml`.
- **Static Analysis, Fuzzing & Scorecard**: Every push and pull request runs **CodeQL v4** (Python SAST), **Dual-Mode Fuzzing** (`tests/fuzz_starhub_ctl.py` supporting Google `atheris` + 2,000-iteration security-invariant mutation fuzzing), **StarHub EGM 3.0** (`render --check` + 7-dim static harness), and **OpenSSF Scorecard** (`ossf/scorecard-action`).
- **Signed Releases & SLSA / in-toto Provenance (`Signed-Releases`)**: Official GitHub Releases include deterministic source archives (`starhub-kit-<tag>.tar.gz`), detached Ed25519 signatures (`.sig`), and signed in-toto DSSE provenance attestations (`.intoto.jsonl`). Verify release signatures against the official Ed25519 public key:
  ```pem
  -----BEGIN PUBLIC KEY-----
  MCowBQYDK2VwAyEAxuIA6FCv17guUFZfrXZuTB+erFYRwrm2Lof3/hzm/HM=
  -----END PUBLIC KEY-----
  ```
  ```bash
  openssl pkeyutl -verify -pubin -inkey release_ed25519_pub.pem \
    -rawin -in starhub-kit-v1.3.0.tar.gz -sigfile starhub-kit-v1.3.0.tar.gz.sig
  ```
- **SPDX / REUSE 3.2**: All source scripts carry standard SPDX `MIT` license and copyright headers, with repository-wide machine-readable licensing declared in `REUSE.toml`, license text in `LICENSES/MIT.txt`, and citation metadata in `CITATION.cff`.
- **OpenSSF Best Practices `Silver` Certification (`Project #16658`)**: `starhub-kit` holds an active **OpenSSF Best Practices `Silver`** badge (`tiered_percentage = 200%`: `67/67 Passing` + `55/55 Silver`), publicly verifiable at `https://www.bestpractices.dev/projects/16658` (`https://www.bestpractices.dev/projects/16658.json`).

## 4. Reporting a Vulnerability (SLA & Coordinated Disclosure)

Please do **not** open public GitHub issues for sensitive security vulnerabilities (e.g., firewall bypasses in `STARHUB-*-ACL` or sanitizer evasions). Use GitHub's **Report a vulnerability** (Private Security Advisories: `https://github.com/Ziqi/starhub-kit/security/advisories/new`) so maintainers can validate and ship a fix prior to public disclosure:
- **Initial Acknowledgement SLA**: Within **48 hours**.
- **Triage & Remediation Target**: Within **14 days** for critical/high severity issues (maximum coordinated embargo **90 days**).

## 5. Architecture Threat Model & Security Assurance Case

To satisfy **OpenSSF Best Practices (Silver)** security design review (`security_review`) and assurance case (`assurance_case`) requirements, `starhub-kit` documents explicit trust boundaries and fail-closed controls:

| Trust Boundary / Threat Vector | Attack Scenario | Fail-Closed Engineering Control & Verification |
|---|---|---|
| **TB-1: Cloud AI Sandbox (`B2`) -> Internal Core (`panel` / `home`)** | Compromised or prompt-injected cloud agent attempts lateral movement over Tailscale to `:22` SSH or `:8000/:9000/:9443` Docker/Portainer sockets. | `STARHUB-BOT-NOSSH` & `STARHUB-BOT-NOSSH6` chains are inserted at rule `#1` on TCP `:22` (`DROP`), while `STARHUB-DASH-ACL` / `STARHUB-HOME-ACL` only `RETURN` on HTTP `:3001` / `:8080`. Asserted on 2,000 mutated topologies in `tests/fuzz_starhub_ctl.py`. |
| **TB-2: Dual-Stack Gateway (`gw`) -> Public Internet** | LAN client leaks unproxied IPv6 traffic when `gw` acts as Tailscale Exit Node, or DNS `fallback:` racing leaks split-horizon queries. | `STARHUB-IPV6-EXIT-GUARD` drops non-allowed forward IPv6 egress; `mihomo-config-backup.yaml` disables `fallback:` and enforces `respect-rules: true` + deterministic `nameserver-policy`. Asserted in `DIM6-MIHOMO-GUARD`. |
| **TB-3: Commercial IoT Camera -> Vendor Cloud** | Closed-source camera firmware streams audio/video to external cloud despite app-level "privacy mode". | Kernel-level `cam-gate.sh off` inserts `iptables -t mangle -I FORWARD 1 -s <cam_ip> -o Meta -j DROP` at the gateway while keeping local LAN RTSP reachable. |
| **TB-4: Private Production Repo -> Public Open-Source Kit** | Operator accidentally commits real WAN/LAN/Tailscale IPs, MACs, `.env` secrets, or private keys during public export. | `DIM4-SECRET-GUARD` blocks `.env` and PEM key headers; `--verify-public-export` extracts all sensitive tokens from private SSOT and scans both working tree and `git log -p --all` with zero-tolerance exit code `1`. |
| **TB-5: CI/CD & Release Supply Chain** | Upstream GitHub Action tag hijacking or tampered release archive distribution. | 40-char SHA pinning (`Pinned-Dependencies = 10/10`), zero `contents: write` workflow tokens (`Token-Permissions = 10/10`), GitHub OIDC + Sigstore `SLSA Build Level 3` X.509 attestations (`/attestations`), SPDX-2.3 SBOM, bit-for-bit deterministic tarball builder (`./bin/starhub archive --verify`), and detached Ed25519 `.sig` + `.intoto.jsonl` bundles. |

## 6. OpenSSF OSPS Baseline (Level 3) Alignment & Reproducible Builds

In addition to holding **OpenSSF Best Practices `Silver` (`#16658`)**, `starhub-kit` aligns with the **OpenSSF Open Source Project Security (OSPS) Baseline (Maturity Level 3)** and EU Cyber Resilience Act (CRA) supply-chain readiness controls:

| OSPS Baseline Domain | Maturity Control | Verifiable Evidence in `starhub-kit` |
|---|---|---|
| **Access Control (`OSPS-AC`)** | MFA enforcement, protected `main` branch ruleset, and mandatory code-owner path rules | `.github/CODEOWNERS`, GitHub protected-branch PR CI gates (`egm-verify` + `CodeQL`), zero workflow `contents: write` tokens |
| **Build & Release (`OSPS-BR`)** | SLSA Build Level 3 provenance, cryptographic signing, and **Bit-for-Bit Reproducible Builds** | `.github/workflows/attestation.yml` (`actions/attest-build-provenance`), Ed25519 `.sig` + `.intoto.jsonl`, and `./bin/starhub archive --verify` (`mtime=0`, `uid/gid=0`, lexicographical PAX ordering) |
| **Documentation (`OSPS-DO`)** | Machine-readable Security Insights (`v2.0.0`), user/architecture playbooks, and bilingual security guides | `.github/security-insights.yml`, `docs/ARCHITECTURE-AND-PLAYBOOK-EN.md`, `README.md` / `README.zh-CN.md` |
| **Governance (`OSPS-GV`)** | Explicit maintainer roles, DCO contribution sign-off, and single-maintainer bus-factor continuity plan | `GOVERNANCE.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` |
| **Legal & SBOM (`OSPS-LE`)** | Machine-auditable per-file SPDX licensing (`REUSE 3.2`) and automated release SBOM (`SPDX-2.3`) | `REUSE.toml`, `LICENSES/MIT.txt`, `scripts/generate-sbom.py`, `actions/attest-sbom` |
| **Quality (`OSPS-QA`)** | Automated regression CI, `>=80%` statement coverage gate, and zero third-party runtime dependencies | `.github/workflows/ci.yml`, `tests/test_coverage_gate.py`, `./bin/starhub render --check` |
| **Security Assessment (`OSPS-SA`)** | Continuous SAST, dual-mode coverage/property fuzzing, and documented architecture threat model | `.github/workflows/codeql.yml`, `tests/fuzz_starhub_ctl.py` (Google `atheris` + 2,000-iter invariant fuzzing), Section 5 Threat Model |
| **Vulnerability Management (`OSPS-VM`)** | Private coordinated disclosure channel, explicit acknowledgement/remediation SLAs, and Dependabot monitoring | GitHub Private Security Advisories (Section 4: 48h ack / 14d fix / 90d embargo), `.github/dependabot.yml` |

### Verifying Bit-for-Bit Reproducible Release Archives

Every `starhub-kit-v*.tar.gz` release archive is built via `./bin/starhub archive` with normalized PAX headers (`mtime=0`, `uid=0`, `gid=0`, empty `uname`/`gname`, deterministic POSIX permissions, and `gzip` `mtime=0`). Any third party can check out the release tag on Linux or macOS and verify byte-for-byte reproducibility without root privileges:

```bash
git checkout v1.3.0
./bin/starhub archive --verify-file ./starhub-kit-v1.3.0.tar.gz --prefix starhub-kit-v1.3.0
```
