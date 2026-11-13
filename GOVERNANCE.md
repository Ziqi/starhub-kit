# StarHub Kit Project Governance & Continuity Charter

> **Version**: `v1.0.2` · **License**: [MIT](./LICENSE) · **Related Policies**: [CONTRIBUTING.md](./CONTRIBUTING.md) · [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) · [SECURITY.md](./SECURITY.md)

## 1. Governance Model & Roles

`starhub-kit` follows a transparent, meritocratic **Benevolent Maintainer + Open Contributor** governance model designed for high-assurance infrastructure tooling:

| Role | Responsibilities & Privileges | Current Roster |
|---|---|---|
| **Lead Maintainer** | Architecture stewardship, security advisory triage, Repository Ruleset administration, cryptographic release signing, and roadmap governance (`docs/ROADMAP-v2.md`). | `@Ziqi` (Ziqi Xiao) |
| **Reviewers / Co-Maintainers** | Reviewing pull requests against the Ten Iron Guardrails (`AGENTS.md`), verifying zero-drift compiler parity, and triaging issues. | Nominated from contributors with >=3 accepted high-quality PRs |
| **Contributors** | Submitting pull requests, bug reports, driver specs, documentation improvements, and security disclosures under the MIT License & DCO. | Open to all community members |

## 2. Developer Certificate of Origin (DCO) & Legal Provenance

To satisfy **OpenSSF Best Practices (Silver)** provenance criteria without imposing heavyweight CLA bureaucracy:

1. Every contribution is licensed under the repository's [MIT License](./LICENSE) (SPDX identifier `MIT`).
2. Contributors certify origin under the **Developer Certificate of Origin v1.1 (DCO)** (`https://developercertificate.org/`) by signing off commits (`git commit -s`, adding `Signed-off-by: Name <email>`), confirming they have the legal right to submit the work under the MIT License.
3. Every file in the repository is audited on every commit by `fsfe/reuse-action` (`REUSE 3.2` / `SPDX`).

## 3. Change Control & Quality Gates

No functional change may enter `main` unless all automated gates pass:

1. **Compiler Zero-Drift Gate**: `./bin/starhub render --check` (`0` byte drift vs `STARHUB_GROUND_TRUTH.json`).
2. **80%+ Statement Coverage Gate**: `python3 ./tests/test_coverage_gate.py --min-coverage 80` enforces `>= 80%` executable statement coverage on the core declarative compiler (`scripts/starhub-ctl.py`).
3. **2,000-Iteration Fuzzing & Security Invariant Gate**: `python3 ./tests/fuzz_starhub_ctl.py --iterations 2000` verifies `B2` `:22 DROP`, split-DNS anti-fallback, and Zero-PII scrubbers.
4. **7-Dimension Static EGM 3.0 Gate**: `./bin/starhub doctor --local-docs-only` (`FAIL=0`).
5. **CodeQL SAST & FSFE REUSE Lint**: Zero unresolved static security alerts and 100% SPDX compliance.

## 4. Access Continuity & Succession Plan (`Bus Factor` Resilience)

To guarantee uninterrupted issue management, vulnerability patching, and release capability within **7 days** even if the Lead Maintainer becomes unavailable (satisfying OpenSSF Best Practices Silver `access_continuity`):

1. **Zero Lock-In Open Architecture**: `starhub-kit` is 100% open-source MIT Python 3.9+ standard-library code with zero proprietary SaaS dependencies, zero closed binary blobs, and fully automated GitHub OIDC (`Sigstore` / `SLSA Build Level 3`) build attestations that require no local developer laptop secrets to build or verify.
2. **Emergency Escrow & Succession Protocol**:
   - GitHub Account Recovery codes, two-factor hardware backup keys, and offline Ed25519 release signing key escrow instructions are stored in an encrypted offline family/designated-successor vault with documented 72-hour emergency handover instructions.
   - GitHub's native **Account Successor** setting is designated so repository ownership, issue tracker control, and Ruleset administration can be transferred without repository fork fragmentation.
   - Because all build provenance is also anchored via GitHub OIDC (`actions/attest-build-provenance`) and `REUSE 3.2`, any designated successor or community fork can cut a verified SLSA Level 3 release immediately upon repository transfer.

## 5. Accessibility & Internationalization Standards

- **Bilingual Documentation**: Core onboarding and architecture entrypoints are maintained in both **English** ([README.md](./README.md)) and **Simplified Chinese** ([README.zh-CN.md](./README.zh-CN.md)).
- **CLI Accessibility**: All CLI tools (`./bin/starhub`, `starhub-ctl.py`, `starhub-doctor.py`) use plain UTF-8 structured `[PASS]` / `[FAIL]` / `[SKIP]` prefixes without color-only status encoding, ensuring full compatibility with screen readers, monochrome terminals, and CI log parsers.
